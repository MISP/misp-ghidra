from tempfile import template
from pyghidra import get_current_interpreter
import toml, os, sys, json

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from pymisp import PyMISP, MISPObject, MISPEvent, MISPObjectReference
from pymisp.tools import (
    FileObject,
    ELFObject,
    PEObject,
    ELFSectionObject,
    PESectionObject,
)

from ghidra.feature.fid.service import FidService

from java.lang import Long
from java.lang import StringBuffer

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.DecompileOptions as DecompileOptions
import ghidra.program.model.address.Address as Address
import ghidra.program.model.listing.Function as Function
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

global OBJECT_CREATION_LIMIT
OBJECT_CREATION_LIMIT = 100000

import logging

logger = logging.getLogger(__name__)


class PyMISPGhidra:

    def __init__(
        self,
        ghidraProgram,
        interpreter,
        monitor,
        config_path="misp/config/config.toml",
        disableUrlWarning=True,
    ):
        self.monitor = monitor

        # PyMISP parameters
        if disableUrlWarning:
            urllib3.disable_warnings(category=InsecureRequestWarning)

        script_dir = os.path.dirname(os.path.realpath(__file__))

        self.mispGhidraPath = script_dir

        if script_dir not in sys.path:
            sys.path.append(script_dir)

        config_full_path = os.path.join(os.path.dirname(__file__), config_path)
        config = toml.load(open(config_full_path, encoding="utf-8"))

        self.misp_config = config["misp"]

        self.misp = PyMISP(
            url=self.misp_config["url"],
            key=self.misp_config["key"],
            ssl=self.misp_config["ssl"],
        )

        with open(
            self.mispGhidraPath
            + "/misp/object-templates/ghidra-function/definition.json"
        ) as f:
            self.ghidra_function_template = json.load(f)

        # Ghidra parameters

        # Headless API test doesnt require ghidraProgram, just MISP API test.

        if ghidraProgram == None:
            return

        self.ghidraProgram = ghidraProgram
        self.FIDservice = FidService()
        self.interpreter = interpreter

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

        self.language = self.ghidraProgram.getLanguage()

    def get_existing_events(self, ghidraProgram=None) -> dict:
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

                print(f"found:event:uuid:{event_id}")
        except:
            pass

        return events

    def create_empty_event(
        self, title="Ghidra Exported Event", ghidraProgram=None, extends_uuid=None
    ):

        # Right now only support for one program per PyMISPGhidra
        if ghidraProgram == None:
            ghidraProgram = self.ghidraProgram

        if extends_uuid:
            event = MISPEvent(info=title, extends_uuid=extends_uuid)
        else:
            event = MISPEvent(info=title)

        # event.distribution = args.distrib
        # event.threat_level_id = args.threat
        # event.analysis = 0

        event = self.misp.add_event(event, pythonify=True)

        path = ghidraProgram.getExecutablePath()

        file_object = FileObject(path)

        self.misp.add_object(event, file_object)

        # Check for PE or elf
        exe_format = ghidraProgram.getExecutableFormat()
        if "PE" in exe_format:
            # required text, type, original-filename, internal-filename, entrypoint-address, imphash, impfuzzy
            print("PE file")
            PE_object = PEObject(filepath=path)

            self.misp.add_object(event, PE_object)

            for s in PE_object.sections:
                self.misp.add_object(event, s)

        elif "ELF" in exe_format:
            print("Linux/Unix ELF file.")

            elf_object = ELFObject(filepath=path)

            self.misp.add_object(event, elf_object)

            for s in elf_object.sections:
                self.misp.add_object(event, s)

        elif "Mach-O" in exe_format:
            print("macOS Mach-O file.")
        else:
            print(f"Other format detected: {exe_format}")

        logger.info("Created new event with name " + title)

        print(f"created:event:uuid:{event.uuid}", file=sys.stdout)

        return event

    def _create_object_from_function(self, func):

        ghidra_function = MISPObject(
            "ghidra-function",
            strict=True,
            misp_objects_template_custom=self.ghidra_function_template,
        )

        name = func.getName()
        ghidra_function.add_attribute("function-name", name)

        entry_point = func.getEntryPoint()
        ghidra_function.add_attribute("entrypoint-address", entry_point.getOffset())

        logger.info(f"Creating object for function {name} at address {entry_point}")

        if func.isThunk():
            ext_loc = func.getExternalLocation()

            if ext_loc is not None:
                # Get the Library object
                lib = ext_loc.getLibrary()
                ghidra_function.add_attribute(
                    "external-library", Long.toHexString(lib.getName())
                )
            else:
                ghidra_function.add_attribute("external-library", "<EXTERNAL>")

        ghidra_function.add_attribute(
            "decompiler-minor-version", self.decompiler.getMinorVersion()
        )
        ghidra_function.add_attribute(
            "decompiler-major-version", self.decompiler.getMajorVersion()
        )

        instructions_count = func.getBody().getNumAddresses()
        ghidra_function.add_attribute("instruction-count", instructions_count)

        # Function ID
        hashFunction = self.FIDservice.hashFunction(func)

        if hashFunction is None:
            logger.info(f"No hash function {name} at address {entry_point}. ")
            return ghidra_function

        fh_hex = hashFunction.fullHash
        fx_hex = hashFunction.specificHash

        if fh_hex is None:
            fh_hex = hashFunction.getFullHash()
        if fx_hex is None:
            fx_hex = hashFunction.getSpecificHash()

        # BSIM vector

        signature = self.decompiler.generateSignatures(func, True, 10, None)
        vector = signature.features
        # For now this is a comma separated hex string of the vector
        vector_csv = ",".join([format(f & 0xFFFFFFFF, "08x") for f in vector])

        ghidra_function.add_attribute("bsim-vector", vector_csv)

        ghidra_function.add_attribute("fid-fh-hash", Long.toHexString(fh_hex))
        ghidra_function.add_attribute("fid-fx-hash", Long.toHexString(fx_hex))

        return ghidra_function

    def add_object_from_function(self, func, event):

        obj = self._create_object_from_function(func)
        self.misp.add_object(event, obj)
        print(f"created:ghidra-function:uuid:{obj.uuid}", file=sys.stdout)

    def create_call_tree_relations(
        self, event: MISPEvent, functions_objects_dict=None, limit=OBJECT_CREATION_LIMIT
    ):
        """
        Optimized version: Adds references locally to objects and pushes once.
        """
        self.monitor.setMessage(f"Fetching existing objects from MISP")

        if functions_objects_dict is None:
            # If we don't have the dict, we do need to fetch the event to map it
            event = self.misp.get_event(event.uuid, pythonify=True)
            functions_objects_dict = {}
            logger.info("Rebuilding mapping from fetched event...")
            for obj in event.get_objects_by_name("ghidra-function"):
                if self.monitor.isCancelled():
                    exit()
                entry_attr = obj.get_attributes_by_relation("entry-point")
                if entry_attr:
                    addr = self.interpreter.toAddr(entry_attr[0].value)
                    ghidra_func = self.interpreter.getFunctionAt(addr)
                    functions_objects_dict[ghidra_func] = obj

        self.monitor.initialize(
            len(functions_objects_dict), f"Building call tree in MISP..."
        )
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
            self.monitor.setMessage(
                f"Pushing {ref_count} call-tree relations to MISP..."
            )
            logger.info(f"Pushing {ref_count} call-tree relations to MISP...")
            self.misp.update_event(event)

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
                print(f"Prepared {count} functions locally...")
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
            self.misp.update_event(event)

        return count, fail_count, failed_object_creations

    def dispose(self):
        print("Disposing of program and decompiler")
        self.decompiler.closeProgram()
        self.decompiler.dispose()

    def get_function_at_address(self, address):

        func = self.ghidraProgram.getFunctionManager().getFunctionAt(address)

        if func is None:
            raise ValueError(f"No function found at address {address}")

        return func

    # def create_call_tree_relations_legacy(
    #     self, event: MISPEvent, functions_objects_dict=None, limit=OBJECT_CREATION_LIMIT
    # ):
    #     """ "
    #     functions_objects_dict : str function entry-point, MISPObject ghidra-function
    #     """
    #     # Call tree relations

    #     # Reload
    #     event = self.misp.get_event(event.uuid, pythonify=True)

    #     if functions_objects_dict is None:
    #         # Find all objects in the event and create a mapping of function name to object
    #         functions_objects_dict = {}
    #         logger.info(
    #             "Missing functions_objects_dict. Creating mapping of function names to MISP objects..."
    #         )
    #         # Search for "ghidra-function" objects in the event and map them to their corresponding function names
    #         for obj in event.get_objects_by_name("ghidra-function"):

    #             if obj.name == "ghidra-function":
    #                 entry_points = obj.get_attributes_by_relation("entry-point")
    #                 for entry_point_attr in entry_points:
    #                     entry_point = self.interpreter.toAddr(entry_point_attr.value)
    #                     ghidra_function = self.interpreter.getFunctionAt(entry_point)
    #                     functions_objects_dict[ghidra_function] = obj

    #     i = 0
    #     for func in functions_objects_dict.keys():
    #         if i >= limit:
    #             break
    #         if monitor.isCancelled():
    #             break

    #         called_funcs = func.getCalledFunctions(monitor)
    #         if called_funcs is not None:

    #             for called_func in called_funcs:

    #                 if called_func not in functions_objects_dict:
    #                     continue

    #                 try:
    #                     func_obj = functions_objects_dict[func]
    #                     func_call_ref = MISPObjectReference()
    #                     func_call_ref.object_uuid = func_obj.uuid
    #                     func_call_ref.relationship_type = "calls"
    #                     func_call_ref.referenced_uuid = functions_objects_dict[
    #                         called_func
    #                     ].uuid
    #                     func_call_ref.comment = "Function call relation"
    #                     ref_object = self.misp.add_object_reference(
    #                         func_call_ref, pythonify=True
    #                     )

    #                     print(f"created:object-reference:uuid:{ref_object.uuid}")
    #                 except Exception as e:
    #                     logger.error(
    #                         f"Failed to add relation between {func.getName()} and {called_func.getName()}: {e}"
    #                     )
    #                     continue
    #         i += 1


# def add_object_from_functions_legacy(
#         self, functions, event, call_tree=True, limit=OBJECT_CREATION_LIMIT
#     ):

#         functions_objects_dict = {}

#         failed_object_creations = []
#         # Add objects for each function
#         count = 0
#         fail_count = 0
#         i = 0
#         for func in functions:
#             if count >= limit:
#                 break
#             if monitor.isCancelled():
#                 break

#             try:
#                 obj = self._create_object_from_function(func)
#                 result = self.misp.add_object(event, obj)
#                 if result is None:
#                     raise ValueError("Failed to add object to MISP")
#                 print(f"created:ghidra-function:uuid:{obj.uuid}")
#                 functions_objects_dict[func] = obj
#                 count += 1
#             except Exception as e:
#                 logger.error(
#                     f"Failed to create object for function {func.getName()}: {e}"
#                 )
#                 failed_object_creations.append(func.getName())
#                 fail_count += 1
#             finally:
#                 i += 1

#         logger.info(
#             f"Successfully created {count} objects for functions. Failed to create {fail_count} objects. Now processing call tree relations..."
#         )

#         if not call_tree:
#             return count, fail_count, failed_object_creations

#         self.create_call_tree_relations(
#             event, limit=limit, functions_objects_dict=functions_objects_dict
#         )
#         return count, fail_count, failed_object_creations
