# Recreate call tree in MISP
# @author Thomas Caillet @rdmmf
# @category MISP.ghidra-function
# @keybinding
# @menupath Tools.MISP.Ghidra Functions.Others.Recreate call tree in MISP
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


def main(event_uuid=None):

    # IO Handler regardless of headless or GUI mode
    interpreter = get_current_interpreter()

    isHeadless = interpreter.getState().getTool() is None

    logger.info(f"Running main {os.path.basename(__file__)} with parameters:")
    logger.info(f"    Event UUID: {event_uuid}")

    # Boilerplate
    if interpreter.currentProgram == None:
        if isHeadless:
            raise Exception("No program selected")
        else:
            selectedProgram = interpreter.askProgram("Select a program")

        interpreter.openProgram(selectedProgram)

    # Boilerplate
    mispGhidra = PyMISPGhidra(interpreter.currentProgram)
    IOHandler = PyMISPGhidraIOHandler(
        mispGhidra,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )

    # Boilerplate UUID search
    if event_uuid == None:
        # No UUID provided, use sha256 search
        search_events = mispGhidra.get_existing_events()

        if search_events == None:
            IOHandler.handle_exception_message(
                "Couldn't find event in MISP with program sha256",
                "Error retrieving event",
            )

        event_uuid = IOHandler.handle_events_selection(search_events, ask_new=False)

    try:
        event = mispGhidra.misp.get_event(event_uuid, pythonify=True)
        if event is None:
            raise ValueError(f"No event found with uuid {event_uuid}")
    except Exception as e:
        IOHandler.handle_exception_message(e, "Error retrieving event")

    mispGhidra.create_call_tree_relations(event=event)

    IOHandler.handle_message(
        f"Successfully created call tree relations for event {event.info} ({event.uuid}). "
    )


if __name__ == "__main__":
    start = time.time()

    args = getScriptArgs()
    event_uuid = None

    log_file = "/tmp/misp-ghidra.log"

    # ['--event-uuid', '550e8400-e29b-41d4-a716-446655440000', '--function-address', '0010e3a0', '--verbose']
    for i in range(len(args)):
        if args[i] == "--event-uuid" and i + 1 < len(args):
            event_uuid = args[i + 1]
        elif args[i] == "--log-file" and i + 1 < len(args):
            log_file = args[i + 1]

    # if not sys.stdin.isatty():

    #     input_data = sys.stdin.read().splitlines()
    #     for line in input_data:

    #         parts = line.split(":")
    #         if parts[0] == "event" and parts[1] == "uuid":
    #             event_uuid = parts[2]

    # for line in sys.stdin:
    #     uuid = line.strip()
    #     if not uuid:
    #         continue

    # logging.basicConfig(filename=log_file, level=logging.INFO,stream=sys.stderr)

    logger.info(f"Running {os.path.basename(__file__)} with arguments:")

    main(event_uuid=event_uuid)

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
