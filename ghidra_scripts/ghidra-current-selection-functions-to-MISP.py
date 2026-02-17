# Current selection to MISP
# @author Thomas Caillet @rdmmf
# @category MISP.ghidra-function
# @keybinding
# @menupath Tools.MISP.Ghidra Functions.Current selection to MISP
# @toolbar misp.png
# @runtime PyGhidra

import sys, os, importlib

from pymisp import MISPObject

# Add library folder to sys.path
lib_dir = os.path.join(os.path.dirname(__file__), "..")
if lib_dir not in sys.path:
    sys.path.append(lib_dir)

import mispghidra
import mispghidra.PyMISPGhidra
import mispghidra.PyMISPGhidraIOHandler

# This is for updating the library if it has been edited while PyGhidra was running
importlib.reload(mispghidra)
importlib.reload(mispghidra.PyMISPGhidra)
importlib.reload(mispghidra.PyMISPGhidraIOHandler)

from mispghidra.PyMISPGhidra import PyMISPGhidra
from mispghidra.PyMISPGhidraIOHandler import PyMISPGhidraIOHandler

from pyghidra.script import get_current_interpreter
import time, logging

logger = logging.getLogger(__name__)


def main(
    func_addresses=None,
    event_uuid=None,
    all_functions=False,
    call_tree=True,
    new_event=False,
):

    # IO Handler regardless of headless or GUI mode
    interpreter = get_current_interpreter()

    isHeadless = interpreter.getState().getTool() is None

    logger.info(f"Running main {os.path.basename(__file__)} with arguments:")
    logger.info(f"    Function addresses: {func_addresses}")
    logger.info(f"    Event UUID: {event_uuid}")
    logger.info(f"    All functions: {all_functions}")

    if interpreter.currentProgram == None:
        if isHeadless:
            raise Exception("No program selected")
        else:
            selectedProgram = interpreter.askProgram("Select a program")

        interpreter.openProgram(selectedProgram)

    mispGhidra = PyMISPGhidra(interpreter.currentProgram)
    IOHandler = PyMISPGhidraIOHandler(
        mispGhidra,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )

    # Handle input parameters regardless of headless or GUI mode
    if func_addresses == None or func_addresses == []:
        selection = interpreter.currentSelection

        all_functions_addresses = list(
            interpreter.currentProgram.getFunctionManager().getFunctions(
                selection, True
            )
        )
        func_addresses = IOHandler.handle_functions_selections(
            all_functions_addresses, single_function=False
        )

    logger.info(f"Function addresses after handling parameters: {func_addresses}")
    funcs = []

    # Check functions exist and retrieve them, handle exceptions if they don't
    for func_address in func_addresses:
        try:
            func = interpreter.getFunctionContaining(interpreter.toAddr(func_address))
            funcs.append(func)
            if func is None:
                raise ValueError(f"No function found at address {func_address}")
        except Exception as e:
            IOHandler.handle_exception_message(e, "Error retrieving function")

    if event_uuid == None and not new_event:
        # No UUID provided, use sha256 search
        search_events = mispGhidra.get_existing_events()
        event_uuid = IOHandler.handle_events_selection(search_events, ask_new=True)

        # User selected new in the GUI
        if event_uuid == "new":
            new_event = True

    if new_event:
        new_event_name = (
            f"Ghidra Exported Event from {interpreter.currentProgram.getName()}"
        )
        event = mispGhidra.create_empty_event(new_event_name)
    else:
        event_uuid = IOHandler.handle_event_uuid(event_uuid)

        if event_uuid != None:
            try:
                event = mispGhidra.misp.get_event(event_uuid, pythonify=True)
                if event is None:
                    raise ValueError(f"No event found with uuid {event_uuid}")
            except Exception as e:
                IOHandler.handle_exception_message(e, "Error retrieving event")

    mispGhidra.add_object_from_functions(funcs, event=event, call_tree=call_tree)

    IOHandler.handle_message(
        f"Successfully added functions to event {event.info} ({event.uuid}). "
    )


if __name__ == "__main__":
    start = time.time()

    args = getScriptArgs()
    func_addresses = []
    event_uuid = None
    all_functions = False
    log_file = "/tmp/misp-ghidra.log"
    call_tree = True
    new_event = False

    # ['--event-uuid', '550e8400-e29b-41d4-a716-446655440000', '--function-address', '0010e3a0', '--function-address', '0010e3a0', '--verbose']
    for i in range(len(args)):
        if args[i] == "--function-address" and i + 1 < len(args):
            func_addresses.append(args[i + 1])
        elif args[i] == "--event-uuid" and i + 1 < len(args):
            event_uuid = args[i + 1]
        elif args[i] == "--all-functions":
            all_functions = True
        elif args[i] == "--log-file" and i + 1 < len(args):
            log_file = args[i + 1]
        elif args[i] == "--no-call-tree":
            call_tree = False
        elif args[i] == "--new-event":
            new_event = True

    # logging.basicConfig(filename=log_file, level=logging.INFO,stream=sys.stderr)

    main(
        func_addresses=func_addresses,
        event_uuid=event_uuid,
        all_functions=all_functions,
        call_tree=call_tree,
        new_event=new_event,
    )

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
