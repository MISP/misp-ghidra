# Main components used by the GUI and Headless scripts
# Rely on the PyMispGhidra and PyMispGhidraIOHandler

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

from ghidra.program.flatapi import FlatProgramAPI

import time, logging

logger = logging.getLogger(__name__)


# This function can be called by headless and GUI scripts
def functions_to_misp(
    state,
    interpreter,
    func_addresses=None,
    event_uuid=None,
    all_functions=False,
    use_current_selection=False,
    call_tree=True,
    new_event=False,
    ignored_functions=[],
    included_functions=["imports","exports","thunks","defined"]
):

    isHeadless = state.getTool() is None
    selectedProgram = state.getCurrentProgram()

    logger.info("=" * 60)
    logger.info(f"STARTING: {os.path.basename(__file__)}")
    logger.info("-" * 60)

    # Existing Debug Info
    logger.info(f"Function addresses: {func_addresses}")
    logger.info(f"Event UUID:        {event_uuid}")
    logger.info(f"All functions:     {all_functions}")

    # Added Missing Debug Info
    logger.info(f"Use Selection:     {use_current_selection}")
    logger.info(f"Include Call Tree: {call_tree}")
    logger.info(f"Create New Event:  {new_event}")

    logger.info("=" * 60)

    mispGhidra = PyMISPGhidra(selectedProgram)
    IOHandler = PyMISPGhidraIOHandler(
        mispGhidra,
        interpreter=interpreter,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )

    # If --all-functions is set, ignore provided function addresses and use all functions in the program
    if all_functions:
        func_addresses = []
        for func in selectedProgram.getFunctionManager().getFunctions(True):
            func_addresses.append(func.getEntryPoint().toString())

    elif use_current_selection:
        if func_addresses == None or func_addresses == []:
            selection = state.getCurrentSelection()

            if selection is None:
                IOHandler.handle_exception_message(ValueError(""), "No selection")

            all_functions_addresses = list(
                selectedProgram.getFunctionManager().getFunctions(selection, True)
            )
            func_addresses = [
                func.getEntryPoint().toString() for func in all_functions_addresses
            ]

    # Handle input parameters regardless of headless or GUI mode
    if func_addresses == None or func_addresses == []:
        all_functions_addresses = list(
            state.getCurrentProgram().getFunctionManager().getFunctions(True)
        )
        func_addresses = IOHandler.handle_functions_selections(
            all_functions_addresses, single_function=False
        )

    logger.info(f"Function addresses after handling parameters: {func_addresses}")
    funcs = []

    # Check functions exist and retrieve them, handle exceptions if they don't
    for func_address in func_addresses:
        

        try:
            func = (
                state.getCurrentProgram()
                .getFunctionManager()
                .getFunctionContaining(interpreter.toAddr(func_address))
            )

            if "thunks" in ignored_functions and func.isThunk():
                continue

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
        new_event_name = f"Ghidra Exported Event from {state.currentProgram.getName()}"
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


def create_call_tree(state, interpreter, event_uuid=None):

    # IO Handler regardless of headless or GUI mode

    isHeadless = interpreter.getState().getTool() is None

    logger.info(f"Running main {os.path.basename(__file__)} with parameters:")
    logger.info(f"    Event UUID: {event_uuid}")

    # Boilerplate
    mispGhidra = PyMISPGhidra(state.getCurrentProgram())
    IOHandler = PyMISPGhidraIOHandler(
        mispGhidra,
        interpreter,
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
