from tempfile import template
import toml, os, sys, json

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from pymisp import PyMISP, MISPObject, MISPEvent

from ghidra.feature.fid.service import FidService
from ghidra.util.task import ConsoleTaskMonitor

from java.lang import Long
from java.lang import StringBuffer

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.DecompileOptions as DecompileOptions

global OBJECT_CREATION_LIMIT
OBJECT_CREATION_LIMIT = 1000


monitor = ConsoleTaskMonitor()


class PyMISPGhidra:

    def __init__(
        self,
        ghidraProgram,
        config_path="misp/config/config.toml",
        disableUrlWarning=True,
    ):

        # Ghidra parameters
        self.ghidraProgram = ghidraProgram

        self.FIDservice = FidService()

        # Copied from BSIM script DumpBSimDebugSignaturesScript.py
        # Probably a much cleaner way
        self.decompiler = DecompInterface()

        options = DecompileOptions()
        self.decompiler.setOptions(options)
        self.decompiler.toggleSyntaxTree(False)
        self.decompiler.setSignatureSettings(0x4D)
        if not self.decompiler.openProgram(self.ghidraProgram):
            print("Unable to initialize the Decompiler interface!")
            print("%s" % self.decompiler.getLastMessage())
            raise Exception("Decompiler initialization failed")

        self.language = self.ghidraProgram.getLanguage()

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

    def create_empty_event(self, title="Ghidra Exported Event"):

        event = MISPEvent()

        # event.distribution = args.distrib
        # event.threat_level_id = args.threat
        # event.analysis = 0
        event.info = title

        event = self.misp.add_event(event, pythonify=True)

        print("Created new event with name " + title)

        return event

    def _create_object_from_function(self, func):

        with open(
            self.mispGhidraPath
            + "/misp/object-templates/ghidra-function/definition.json"
        ) as f:
            template = json.load(f)

        ghidra_function = MISPObject(
            "ghidra-function", strict=True, misp_objects_template_custom=template
        )

        name = func.getName()
        entry_point = func.getEntryPoint()

        insructions_count = func.getBody().getNumAddresses()

        # Function ID
        hashFunction = self.FIDservice.hashFunction(func)

        if hashFunction == None:
            return None

        fh_hex = hashFunction.fullHash
        fx_hex = hashFunction.specificHash

        if fh_hex is None:
            fh_hex = hashFunction.getFullHash()
        if fx_hex is None:
            fx_hex = hashFunction.getSpecificHash()

        # BSIM
        # sigres = self.decompiler.debugSignatures(func,10,None)
        signature = self.decompiler.generateSignatures(func, True, 10, None)

        vector = signature.features

        # For now this is a comma separated hex string of the vector
        vector_csv = ",".join([format(f & 0xFFFFFFFF, "08x") for f in vector])
        print(vector_csv)
        print(f"Generated BSIM vector for function {func.getName()}")

        ghidra_function.add_attribute("function-name", name)
        ghidra_function.add_attribute(
            "entry-point", Long.toHexString(entry_point.getOffset())
        )
        ghidra_function.add_attribute("instruction-count", insructions_count)
        ghidra_function.add_attribute("bsim-vector", vector_csv)
        ghidra_function.add_attribute("fid-fh-hash", Long.toHexString(fh_hex))
        ghidra_function.add_attribute("fid-fx-hash", Long.toHexString(fx_hex))

        return ghidra_function

    def add_object_from_function(self, func, event):

        obj = self._create_object_from_function(func)
        self.misp.add_object(event, obj)

    def add_object_from_functions(
        self, functions, event, call_tree=True, limit=OBJECT_CREATION_LIMIT
    ):

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

            obj = self._create_object_from_function(func)

            i += 1

            if obj is None:
                print(f"Failed to hash {func.getName()}")
                failed_object_creations.append(func.getName())
                fail_count += 1
                continue

            count += 1

            self.misp.add_object(event, obj)

        if not call_tree:
            return count, fail_count, failed_object_creations

        # Call tree relations
        i = 0
        for func in functions:
            if i >= limit:
                break
            if monitor.isCancelled():
                break

            # TODO objects relations for caller/callee

            i += 1

        return count, fail_count, failed_object_creations

    def dispose(self):
        self.decompiler.closeProgram()
        self.decompiler.dispose()

    def get_function_at_address(self, address):

        func = self.ghidraProgram.getFunctionManager().getFunctionAt(address)

        if func is None:
            raise ValueError(f"No function found at address {address}")

        return func


# LEGACY
# def add_object_to_event(self, event_id, fileobject):

#     try:
#         # Convert your fileobject to a dict compatible with MISP
#         misp_obj_dict = fileobject.to_dict()
#         # Create the object in MISP under the given event
#         self.misp.add_object(event_id, misp_obj_dict)
#         print(f"Added object to event {event_id}")
#     except Exception as e:
#         print(f"Failed to add object to event {event_id}: {e}")
#         raise

# def all_functions_to_MISP_object(self):

#     with open(self.mispGhidraPath+'/misp/object-templates/ghidra-project/definition.json') as f:
#         template = json.load(f)

#     ghidra_project = MISPObject("ghidra-project",strict=True, misp_objects_template_custom=template)

#     for func in self.ghidraProgram.getFunctionManager().getFunctions(True):

#         name = func.getName()
#         ghidra_project.add_attribute("function-name", name)

#     return ghidra_project

# def export_object_in_new_event(self,fileobject):
#     print("Exporting...")
#     event = self.create_empty_event("Ghidra Exported Event")
#     event_uuid = event.uuid
#     self.add_object_to_event(event.id, fileobject)
#     print(f"Successfully uploaded object to new MISP {event_uuid}")

#     return event

# def fid_hash_event(self,event_name="Ghidra Exported FID hashes",limit=999):

#     event = self.create_empty_event( f"Ghidra FID hahes from {self.ghidraProgram.getName()}")

#     with open(self.mispGhidraPath+'/misp/object-templates/ghidra-function/definition.json') as f:
#         template = json.load(f)

#     i = 0
#     for func in self.ghidraProgram.getFunctionManager().getFunctions(True):

#         if i> limit: break

#         if monitor.isCancelled(): break

#         fid_object = MISPObject("ghidra-function",strict=True, misp_objects_template_custom=template)

#         name = func.getName()
#         fid_object.add_attribute("function-name", name)

#         hashFunction = self.FIDservice.hashFunction(func)

#         if hashFunction == None:
#             print(f"Failed to hash {name} ")
#             continue

#         fh_hex = hashFunction.fullHash
#         fx_hex = hashFunction.specificHash


#         fid_object.add_attribute("fid-fh-hash", Long.toHexString(fh_hex))
#         fid_object.add_attribute("fid-fx-hash", Long.toHexString(fx_hex))

#         self.misp.add_object(event,fid_object)

#         i +=1

#     return event
