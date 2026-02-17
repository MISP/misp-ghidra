from tempfile import template
from pyghidra import get_current_interpreter
import toml, os, sys, json

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from pymisp import PyMISP, MISPObject, MISPEvent, MISPObjectReference
from pymisp.tools import FileObject

from ghidra.feature.fid.service import FidService
from ghidra.util.task import ConsoleTaskMonitor

from java.lang import Long
from java.lang import StringBuffer

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.DecompileOptions as DecompileOptions
import ghidra.program.model.address.Address as Address
import ghidra.program.model.listing.Function as Function

global OBJECT_CREATION_LIMIT
OBJECT_CREATION_LIMIT = 1000

import logging

logger = logging.getLogger(__name__)

monitor = ConsoleTaskMonitor()


class PyMISPGhidra:

    def __init__(
        self,
        ghidraProgram,
        config_path="misp/config/config.toml",
        disableUrlWarning=True,
    ):
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
        self.interpreter = get_current_interpreter()

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
                controller="attributes", type="sha256", value=sha256
            )
            attributes = search_result["Attribute"]
            if len(attributes) < 1:
                raise Exception()

            for attribute in attributes:
                event_id = attribute["Event"]["uuid"]
                print(f"found:event:uuid:{event_id}")

            # This used to be Pretty slow #self.misp.get_event(attribute["Event"]["uuid"], pythonify=True),
            # This uses the dict
            events = [attribute["Event"] for attribute in attributes]

        except:
            pass

        return events

    def create_empty_event(self, title="Ghidra Exported Event", ghidraProgram=None):

        # Right now only support for one program per PyMISPGhidra
        if ghidraProgram == None:
            ghidraProgram = self.ghidraProgram

        event = MISPEvent()

        # event.distribution = args.distrib
        # event.threat_level_id = args.threat
        # event.analysis = 0
        event.info = title

        event = self.misp.add_event(event, pythonify=True)

        path = ghidraProgram.getExecutablePath()

        file_object = FileObject(path)

        self.misp.add_object(event, file_object)

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
        ghidra_function.add_attribute(
            "entry-point", Long.toHexString(entry_point.getOffset())
        )

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
        """ "
        functions_objects_dict : str function entry-point, MISPObject ghidra-function
        """
        # Call tree relations

        # Reload
        event = self.misp.get_event(event.uuid, pythonify=True)

        if functions_objects_dict is None:
            # Find all objects in the event and create a mapping of function name to object
            functions_objects_dict = {}
            logger.info(
                "Missing functions_objects_dict. Creating mapping of function names to MISP objects..."
            )
            # Search for "ghidra-function" objects in the event and map them to their corresponding function names
            for obj in event.get_objects_by_name("ghidra-function"):

                if obj.name == "ghidra-function":
                    entry_points = obj.get_attributes_by_relation("entry-point")
                    for entry_point_attr in entry_points:
                        entry_point = self.interpreter.toAddr(entry_point_attr.value)
                        ghidra_function = self.interpreter.getFunctionAt(entry_point)
                        functions_objects_dict[ghidra_function] = obj

        i = 0
        for func in functions_objects_dict.keys():
            if i >= limit:
                break
            if monitor.isCancelled():
                break

            called_funcs = func.getCalledFunctions(monitor)
            if called_funcs is not None:

                for called_func in called_funcs:

                    if called_func not in functions_objects_dict:
                        continue

                    try:
                        func_obj = functions_objects_dict[func]
                        func_call_ref = MISPObjectReference()
                        func_call_ref.object_uuid = func_obj.uuid
                        func_call_ref.relationship_type = "calls"
                        func_call_ref.referenced_uuid = functions_objects_dict[
                            called_func
                        ].uuid
                        func_call_ref.comment = "Function call relation"
                        ref_object = self.misp.add_object_reference(
                            func_call_ref, pythonify=True
                        )

                        print(f"created:object-reference:uuid:{ref_object.uuid}")
                    except Exception as e:
                        logger.error(
                            f"Failed to add relation between {func.getName()} and {called_func.getName()}: {e}"
                        )
                        continue
            i += 1

    def add_object_from_functions(
        self, functions, event, call_tree=True, limit=OBJECT_CREATION_LIMIT
    ):

        functions_objects_dict = {}

        failed_object_creations = []
        # Add objects for each function
        count = 0
        fail_count = 0
        i = 0
        for func in functions:
            if count >= limit:
                break
            if monitor.isCancelled():
                break

            try:
                obj = self._create_object_from_function(func)
                result = self.misp.add_object(event, obj)
                if result is None:
                    raise ValueError("Failed to add object to MISP")
                print(f"created:ghidra-function:uuid:{obj.uuid}")
                functions_objects_dict[func] = obj
                count += 1
            except Exception as e:
                logger.error(
                    f"Failed to create object for function {func.getName()}: {e}"
                )
                failed_object_creations.append(func.getName())
                fail_count += 1
            finally:
                i += 1

        logger.info(
            f"Successfully created {count} objects for functions. Failed to create {fail_count} objects. Now processing call tree relations..."
        )

        if not call_tree:
            return count, fail_count, failed_object_creations

        self.create_call_tree_relations(
            event, limit=limit, functions_objects_dict=functions_objects_dict
        )
        return count, fail_count, failed_object_creations

    def dispose(self):
        self.decompiler.closeProgram()
        self.decompiler.dispose()

    def get_function_at_address(self, address):

        func = self.ghidraProgram.getFunctionManager().getFunctionAt(address)

        if func is None:
            raise ValueError(f"No function found at address {address}")

        return func
