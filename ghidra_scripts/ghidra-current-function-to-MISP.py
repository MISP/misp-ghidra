# Add a ghidra-function object to a MISP Event (provide uuid)
# @author
# @category MISP.ghidra-function
# @keybinding
# @menupath
# @toolbar
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

import time, logging, argparse

logger = logging.getLogger(__name__)


def main(event_uuid=None, new_event=False, verbose=False):

    # IO Handler regardless of headless or GUI mode
    interpreter = get_current_interpreter()

    isHeadless = interpreter.getState().getTool() is None

    logger.info(f"Running main {os.path.basename(__file__)} with parameters:")
    logger.info(f"    Event UUID: {event_uuid}")
    logger.info(f"    Headless mode: {isHeadless}")

    mispGhidra = PyMISPGhidra(interpreter.currentProgram)
    IOHandler = PyMISPGhidraIOHandler(
        mispGhidra,
        verbose=verbose,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )
    # Find function
    func_address = interpreter.currentAddress.toString()
    try:
        func = interpreter.getFunctionContaining(interpreter.toAddr(func_address))
    except Exception as e:
        IOHandler.handle_exception_message(e, "Error retrieving function")
    if func is None:
        IOHandler.handle_exception_message(
            ValueError(f"No function found at address {func_address}"),
            "Error retrieving function",
        )

    if event_uuid == None and not new_event:
        # No UUID provided, use sha256 search
        search_events = mispGhidra.get_existing_events()

        if search_events == None:
            IOHandler.handle_exception_message(
                "Couldn't find event in MISP with program sha256",
                "Error retrieving event",
            )

        event_uuid = IOHandler.handle_events_selection(search_events,ask_new=True)

        if event_uuid == "new":
            new_event = True

    if new_event:
        new_event_name = f"Ghidra Exported Function {func.getName()} from {interpreter.currentProgram.getName()}"
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

    mispGhidra.add_object_from_function(func, event=event)

    IOHandler.handle_message(
        f"Successfully added function {func.getName()} to event {event.info} ({event.uuid}). "
    )


if __name__ == "__main__":
    start = time.time()

    args = getScriptArgs()
    event_uuid = None
    verbose = False
    new_event = False
    log_file = "/tmp/ghidra-misp.log"

    # ['--event-uuid', '550e8400-e29b-41d4-a716-446655440000', '--function-address', '0010e3a0', '--verbose']
    for i in range(len(args)):
        if args[i] == "--event-uuid" and i + 1 < len(args):
            event_uuid = args[i + 1]
        elif args[i] == "--verbose":
            verbose = True
        elif args[i] == "--log-file" and i + 1 < len(args):
            log_file = args[i + 1]
        elif args[i] == "--new-event":
            new_event = True

    if verbose:
        logger.setLevel(logging.DEBUG)
    # logging.basicConfig(level=logging.INFO,stream=sys.stderr)

    main(
        event_uuid=event_uuid,
        new_event=new_event,
        verbose=verbose,
    )

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
