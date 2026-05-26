from tempfile import template
from pyghidra import get_current_interpreter
import toml, os, sys, json, io

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from pymisp import PyMISP, MISPObject, MISPEvent, MISPObjectReference


from ghidra.feature.fid.service import FidService

from java.lang import Long
from java.lang import StringBuffer

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.DecompileOptions as DecompileOptions
import ghidra.program.model.address.Address as Address
import ghidra.program.model.listing.Function as Function
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType

global OBJECT_CREATION_LIMIT
OBJECT_CREATION_LIMIT = 100000

import logging

logger = logging.getLogger(__name__)

# For windows, skip pymisp fileobjects (dependancy on pydeep)
try:
    from pymisp.tools import (
        FileObject,
        ELFObject,
        PEObject,
        MachOObject,
        ELFSectionObject,
        PESectionObject,
        MachOSectionObject,
    )

    HAS_FILE_OBJECTS = True
except ImportError:
    HAS_FILE_OBJECTS = False
    # Optional: Log a warning so you know why it's missing
    logger.warning(
        "Warning: pymisp[fileobjects] not installed. File analysis features will be disabled."
    )


class PyMISPGhidra:

    def __init__(
        self,
        ghidraProgram,
        interpreter,
        monitor,
        config_path="misp/config/config.toml",
        disableUrlWarning=True,
        offline=False,
    ):
        self.monitor = monitor
        self.offline = offline

        # PyMISP parameters
        if disableUrlWarning:
            urllib3.disable_warnings(category=InsecureRequestWarning)

        script_dir = os.path.dirname(os.path.realpath(__file__))

        self.mispGhidraPath = script_dir

        if script_dir not in sys.path:
            sys.path.append(script_dir)

        self.misp_config = None
        self.misp = None

        if not self.offline:
            try:
                config_full_path = os.path.join(os.path.dirname(__file__), config_path)
                config = toml.load(open(config_full_path, encoding="utf-8"))

                self.misp_config = config["misp"]

                self.misp = PyMISP(
                    url=self.misp_config["url"],
                    key=self.misp_config["key"],
                    ssl=self.misp_config["ssl"],
                )
            except Exception as e:
                logger.warning(
                    f"Failed to load MISP configuration or connect to MISP: {e}. Falling back to offline mode."
                )
                self.offline = True

        # Load ghidra-function template with fallback
        template_path = os.path.join(
            self.mispGhidraPath,
            "misp/misp-objects/objects/ghidra-function/definition.json",
        )
        if not os.path.exists(template_path):
            template_path = os.path.join(
                self.mispGhidraPath,
                "misp/object-templates/ghidra-function/definition.json",
            )

        try:
            with open(template_path) as f:
                self.ghidra_function_template = json.load(f)
        except Exception as e:
            logger.error(
                f"Failed to load ghidra-function template from {template_path}: {e}"
            )
            raise e

        # Ghidra parameters

        # Headless API test doesnt require ghidraProgram, just MISP API test.

        if ghidraProgram == None:
            return

        self.ghidraProgram = ghidraProgram
        self.FIDservice = FidService()
        self.interpreter = interpreter
        self.symbol_table = ghidraProgram.getSymbolTable()
        self.listing = ghidraProgram.getListing()

        # Copied from BSIM script DumpBSimDebugSignaturesScript.py
        # Probably a much cleaner way
        # TODO add options and version of the decompiler to the exported object
        self.decompiler = DecompInterface()

        options = DecompileOptions()
        self.decompiler.setOptions(options)
        self.decompiler.toggleSyntaxTree(False)
        self.decompiler.setSignatureSettings(0x4D)

        if not self.decompiler.openProgram(self.ghidraProgram):
            logger.error("Unable to initialize the Decompiler interface!")
            logger.error("%s" % self.decompiler.getLastMessage())
            raise Exception("Decompiler initialization failed")

        sm = ghidraProgram.getSymbolTable()
        self.external_symbols = sm.getExternalSymbols()

        self.language = self.ghidraProgram.getLanguage()

    def get_existing_events(self, ghidraProgram=None) -> dict:

        if self.offline or self.misp is None:
            return []

        if ghidraProgram == None:
            ghidraProgram = self.ghidraProgram

        sha256 = ghidraProgram.getExecutableSHA256()

        events = []

        try:
            search_result = self.misp.search(
                controller="attributes", type_attribute="sha256", value=sha256
            )
            attributes = search_result["Attribute"]
            if len(attributes) < 1:
                raise Exception()

            # Unique events
            events = list(
                {
                    attr["Event"]["uuid"]: attr["Event"]
                    for attr in attributes
                    if "Event" in attr
                }.values()
            )
            for event in events:
                event_id = event["uuid"]

                logger.info(f"found:event:uuid:{event_id}")
                logger.info(self.get_misp_url(event_id))
        except:
            pass

        return events

    def create_empty_event(
        self,
        title="Ghidra Exported Event",
        ghidraProgram=None,
        extends_uuid=None,
        create_file_objects=True,
    ):

        # Right now only support for one program per PyMISPGhidra
        if ghidraProgram == None:
            ghidraProgram = self.ghidraProgram

        # 1. Instantiate an empty event
        event = MISPEvent()

        # 2. Set the properties directly
        event.info = title

        if extends_uuid:
            event.extends_uuid = extends_uuid

        # event.distribution = args.distrib
        # event.threat_level_id = args.threat
        # event.analysis = 0

        if not self.offline and self.misp:
            event = self.misp.add_event(event, pythonify=True)

        if create_file_objects and HAS_FILE_OBJECTS:
            self.create_file_objects(event, ghidraProgram)

        logger.info("Created new event with name " + title)

        logger.info(f"created:event:uuid:{event.uuid}")
        if not self.offline:
            logger.info(self.get_misp_url(event.uuid))
        return event

    def create_file_objects(self, event, ghidraProgram=None):

        # TODO use the BytesIO of the program if the program doesnt exist on disk ?

        path = ghidraProgram.getExecutablePath()
        self.monitor.setMessage(
            "Generating File/PE/ELF/MachO objects and sections objects"
        )
        try:
            file_object = FileObject(path)

            event.add_object(file_object)

            # Check for PE or elf
            exe_format = ghidraProgram.getExecutableFormat()
            if "PE" in exe_format:
                # required text, type, original-filename, internal-filename, entrypoint-address, imphash, impfuzzy
                logger.info("PE file")
                PE_object = PEObject(filepath=path)

                event.add_object(PE_object)

                for s in PE_object.sections:
                    event.add_object(s)

            elif "ELF" in exe_format:
                logger.info("Linux/Unix ELF file.")

                elf_object = ELFObject(filepath=path)

                event.add_object(elf_object)

                for s in elf_object.sections:
                    event.add_object(s)

            elif "Mach-O" in exe_format:
                logger.info("macOS Mach-O file.")

                macho_object = MachOObject(filepath=path)

                event.add_object(macho_object)

                for s in macho_object.sections:
                    event.add_object(s)

            else:
                logger.info(f"Other format detected: {exe_format}")

            if not self.offline and self.misp:
                self.misp.update_event(event)

        except Exception as e:
            logger.error(
                f"Error building ELF/PE/MachO objects, does the file exist on disk ? {e}"
            )

    def get_function_infos(self, func):

        # Initialize all potential conditional values to None
        ext_lib = fh_hex = fx_hex = fn_sig = fn_code = calling_convention = None

        # Basic Info
        entry_point = func.getEntryPoint()

        scope = "internal"

        # Handle External/Thunk logic
        if func.isThunk():
            thunked = func.getThunkedFunction(True)
            if thunked and thunked.getExternalLocation():
                ext_lib = thunked.getExternalLocation().getLibraryName()
                scope = "import"
        elif func.getExternalLocation():
            ext_lib = func.getExternalLocation().getLibraryName()
            scope = "import"

        symbol = self.interpreter.getSymbolAt(entry_point)

        instruction_count = len(
            list(self.ghidraProgram.getListing().getInstructions(func.getBody(), True))
        )

        # FID Hashes
        hash_function = self.FIDservice.hashFunction(func)
        if hash_function:
            fh = hash_function.getFullHash()
            fx = hash_function.getSpecificHash()
            fh_hex = Long.toHexString(fh)
            fx_hex = Long.toHexString(fx)

        # BSIM Vector
        signature = self.decompiler.generateSignatures(func, True, 10, None)
        vector_csv = ",".join(
            [format(f & 0xFFFFFFFF, "08x") for f in signature.features]
        )

        # Decompilation logic
        decomp_results = self.decompiler.decompileFunction(func, 30, self.monitor)
        try:
            decomp_func = decomp_results.getDecompiledFunction()
            fn_sig = decomp_func.getSignature()
            fn_code = decomp_func.getC()
        except:
            logger.info("There was an error in decompilation!")

        calling_convention = (
            str(func.getCallingConventionName())
            if func.getCallingConventionName()
            else None
        )
        lang_id = self.ghidraProgram.getLanguageID().toString()
        comp_id = self.ghidraProgram.getCompilerSpec().getCompilerSpecID().toString()

        return {
            "function-name": func.getName(),
            "entrypoint-address": entry_point.getOffset(),
            "comment": func.getComment(),
            "labels": [s.getName() for s in self.symbol_table.getSymbols(entry_point)],
            "external-library": ext_lib,
            "is-thunk": func.isThunk(),
            "function-scope": scope,
            "decompiler-id": f"{self.decompiler.getMajorVersion()}.{self.decompiler.getMinorVersion()}:{comp_id}",
            "language-id": lang_id,
            "instruction-count": instruction_count,
            "fid-fh-hash": fh_hex,
            "fid-fx-hash": fx_hex,
            "bsim-vector": vector_csv,
            "decompiled-function": fn_code,
            "function-signature": fn_sig,
            "return-type": func.getReturnType().getName(),
            "calling-convention": calling_convention,
        }

    def _create_object_from_function(self, func):

        # 1. Extract data using the first function
        info = self.get_function_infos(func=func)

        # 2. Initialize MISP Object
        ghidra_function = MISPObject(
            name="ghidra-function",
            strict=True,
            misp_objects_template_custom=self.ghidra_function_template,
        )

        # 3. Map values to attributes
        ghidra_function.add_attribute("function-name", value=info["function-name"])
        ghidra_function.add_attribute(
            "entrypoint-address", value=info["entrypoint-address"]
        )

        if info["comment"]:
            ghidra_function.add_note(note=info["comment"])

        for label in info["labels"]:
            ghidra_function.add_attribute("label", value=label)

        if info["external-library"]:
            ghidra_function.add_attribute(
                "external-library", value=info["external-library"]
            )

        if info["is-thunk"]:
            ghidra_function.add_attribute("is-thunk", value=True)

        ghidra_function.add_attribute("function-scope", value=info["function-scope"])
        ghidra_function.add_attribute("decompiler-id", value=info["decompiler-id"])

        ghidra_function.add_attribute("language-id", value=info["language-id"])

        ghidra_function.add_attribute(
            "instruction-count", value=info["instruction-count"]
        )

        if info["fid-fh-hash"]:
            ghidra_function.add_attribute("fid-fh-hash", value=info["fid-fh-hash"])
            ghidra_function.add_attribute("fid-fx-hash", value=info["fid-fx-hash"])

        ghidra_function.add_attribute("bsim-vector", value=info["bsim-vector"])

        if info["decompiled-function"]:
            ghidra_function.add_attribute(
                "decompiled-function", value=info["decompiled-function"]
            )

        if info["function-signature"]:
            ghidra_function.add_attribute(
                "function-signature", value=info["function-signature"]
            )

        if info["calling-convention"]:
            ghidra_function.add_attribute(
                "calling-convention", value=info["calling-convention"]
            )

        ghidra_function.add_attribute("return-type", value=info["return-type"])

        logger.info(
            f"Created MISP object for {info['function-name']} at {hex(info['entrypoint-address'])}"
        )

        return ghidra_function

    def add_object_from_function(self, func, event):

        obj = self._create_object_from_function(func)
        event.add_object(obj)

        if not self.offline and self.misp:
            self.misp.add_object(event, obj)

        logger.info(f"created:ghidra-function:uuid:{obj.uuid}")

    def create_call_tree_relations(
        self, event: MISPEvent, functions_objects_dict=None, limit=OBJECT_CREATION_LIMIT
    ):
        """
        Optimized version: Adds references locally to objects and pushes once.
        """
        self.monitor.setMessage(f"Fetching existing objects")

        if functions_objects_dict is None:

            if self.offline:
                functions_objects_dict = {}
                logger.info("Rebuilding mapping from local event...")
                for obj in event.objects:
                    if obj.name == "ghidra-function":
                        if self.monitor.isCancelled():
                            exit()
                        entry_attr = obj.get_attributes_by_relation(
                            "entrypoint-address"
                        )

                        if entry_attr:
                            addr = self.interpreter.toAddr(int(entry_attr[0].value))
                            ghidra_func = self.interpreter.getFunctionAt(addr)
                            functions_objects_dict[ghidra_func] = obj
            else:
                # If we don't have the dict, we do need to fetch the event to map it
                event = self.misp.get_event(event.uuid, pythonify=True)
                functions_objects_dict = {}
                logger.info("Rebuilding mapping from fetched event...")
                for obj in event.get_objects_by_name("ghidra-function"):

                    if self.monitor.isCancelled():
                        exit()
                    entry_attr = obj.get_attributes_by_relation("entrypoint-address")

                    if entry_attr:
                        addr = self.interpreter.toAddr(int(entry_attr[0].value))
                        ghidra_func = self.interpreter.getFunctionAt(addr)
                        functions_objects_dict[ghidra_func] = obj

        self.monitor.initialize(len(functions_objects_dict), f"Building call tree...")

        logger.info(f"Building call tree for {len(functions_objects_dict)}")
        self.monitor.setProgress(0)

        i = 0
        ref_count = 0
        for func, func_obj in functions_objects_dict.items():

            if i >= limit:
                break

            if self.monitor.isCancelled():
                exit()

            self.monitor.setProgress(i)

            called_funcs = func.getCalledFunctions(self.monitor)
            if not called_funcs:
                i += 1
                continue

            for called_func in called_funcs:
                # Only create a relation if both functions exist in our MISP event
                if called_func in functions_objects_dict:
                    try:
                        target_obj = functions_objects_dict[called_func]

                        # Create the reference locally on the object
                        # PyMISP objects have an 'add_reference' method
                        func_obj.add_reference(
                            referenced_uuid=target_obj.uuid,
                            relationship_type="calls",
                            comment="Function call relation",
                        )
                        ref_count += 1
                    except Exception as e:
                        logger.error(
                            f"Local ref failed: {func.getName()} -> {called_func.getName()}: {e}"
                        )
            i += 1

        # Final Step: Push the updated event structure with all new references
        if ref_count > 0:
            self.monitor.setIndeterminate(True)
            if not self.offline and self.misp:
                self.monitor.setMessage(
                    f"Pushing {ref_count} call-tree relations to MISP..."
                )
                logger.info(f"Pushing {ref_count} call-tree relations to MISP...")
                self.misp.update_event(event)
            else:
                logger.info(f"Prepared {ref_count} call-tree relations offline.")

        return

    def add_object_from_functions(
        self, functions, event, call_tree=True, limit=OBJECT_CREATION_LIMIT
    ):
        functions_objects_dict = {}
        failed_object_creations = []

        count = 0
        fail_count = 0

        if functions is not None:
            self.monitor.setMessage(
                f"Adding ghidra-functions objects to event {event.uuid}"
            )
            self.monitor.initialize(len(functions))
            self.monitor.setProgress(0)
        for func in functions:
            if count >= limit:
                break

            if self.monitor.isCancelled():
                exit()
            if count % 50 == 0:
                logger.info(f"Prepared {count} functions locally...")
                self.monitor.setProgress(count)

            try:
                # Step 1: Create the objects locally
                obj = self._create_object_from_function(func)

                event.add_object(obj)

                functions_objects_dict[func] = obj
                count += 1

            except Exception as e:
                logger.error(f"Failed to prepare object for {func.getName()}: {e}")
                failed_object_creations.append(func.getName())
                fail_count += 1

        self.monitor.setIndeterminate(True)

        # Step 2: Push to MISP
        if not self.offline and self.misp:
            try:
                self.monitor.setMessage(f"Pushing {count} objects to MISP...")
                logger.info(f"Pushing {count} objects to MISP...")
                self.misp.update_event(event)
            except Exception as e:
                logger.error(f"Bulk push failed: {e}")

        # Call Tree Relations
        if call_tree:
            logger.info("Processing call tree relations...")
            self.create_call_tree_relations(
                event, limit=limit, functions_objects_dict=functions_objects_dict
            )
            # Update again after adding relations
            if not self.offline and self.misp:
                self.misp.update_event(event)

        return count, fail_count, failed_object_creations

    def dispose(self):
        logger.info("Disposing of program and decompiler")
        self.decompiler.closeProgram()
        self.decompiler.dispose()

    def get_function_at_address(self, address):

        func = self.ghidraProgram.getFunctionManager().getFunctionAt(address)

        if func is None:
            raise ValueError(f"No function found at address {address}")

        return func

    def get_misp_url(self, uuid):

        if self.offline or self.misp_config is None:
            return f"offline-event:{uuid}"

        return f"{self.misp_config['url']}/events/view/{uuid}"
