# Main components used by the GUI and Headless scripts
# Rely on the PyMispGhidra and PyMispGhidraIOHandler

import sys, os, importlib, re

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
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from java.util import ArrayList

import time, logging

logger = logging.getLogger(__name__)


# This function can be called by headless and GUI scripts
def functions_to_misp(
    state,
    interpreter,
    monitor,
    func_addresses=None,
    event_uuid=None,
    all_functions=False,
    use_current_selection=False,
    call_tree=True,
    new_event=False,
    ignored_functions=[],
    included_functions=["import", "export", "thunk", "internal"],
    name_include=None,
    name_exclude=None,
    min_blocks=0,
    extend_event=False,
    offline=False,
    out_dir=None,
):

    isHeadless = state.getTool() is None
    selectedProgram = state.getCurrentProgram()

    # Prompt for offline mode if in GUI and not explicitly set
    if not isHeadless and not offline:
        try:
            java_options = ArrayList()
            java_options.add("Export to MISP Server")
            java_options.add("Export locally to JSON file (Offline)")
            choice = interpreter.askChoice(
                "Select Export Destination",
                "Do you want to send data to the configured MISP server, or export it to a local JSON file?",
                java_options,
                java_options.get(0),
            )
            if choice == "Export locally to JSON file (Offline)":
                offline = True
        except Exception:
            pass  # fallback to passed parameter if cancelled or error

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
    logger.info(f"Offline Mode:      {offline}")

    logger.info("=" * 60)

    mispGhidra = PyMISPGhidra(selectedProgram, interpreter, monitor, offline=offline)
    is_offline = mispGhidra.offline  # Check if it fell back to offline

    IOHandler = PyMISPGhidraIOHandler(
        mispghidra=mispGhidra,
        interpreter=interpreter,
        monitor=monitor,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )

    func_addresses = get_function_selection_addresses(
        func_addresses=func_addresses,
        all_functions=all_functions,
        use_current_selection=use_current_selection,
        state=state,
        interpreter=interpreter,
        monitor=monitor,
        IOHandler=IOHandler,
    )
    funcs = filter_functions(
        func_addresses=func_addresses,
        name_include=name_include,
        name_exclude=name_exclude,
        ignored_functions=ignored_functions,
        included_functions=included_functions,
        min_blocks=min_blocks,
        state=state,
        interpreter=interpreter,
        monitor=monitor,
        IOHandler=IOHandler,
    )
    event = get_event_selection(
        event_uuid=event_uuid,
        extend_event=extend_event,
        new_event=new_event,
        state=state,
        interpreter=interpreter,
        monitor=monitor,
        IOHandler=IOHandler,
        mispGhidra=mispGhidra,
        offline=is_offline,
    )

    mispGhidra.add_object_from_functions(funcs, event=event, call_tree=call_tree)

    if is_offline:
        try:
            if out_dir is None:
                if not isHeadless:
                    try:
                        out_dir_file = interpreter.askDirectory(
                            "Select Output Directory for MISP Event JSON", "Select"
                        )
                        if out_dir_file:
                            out_dir = out_dir_file.getAbsolutePath()
                    except Exception:
                        out_dir = "."
                else:
                    out_dir = "."

            if out_dir:
                # Ensure the output directory exists
                if not os.path.exists(out_dir):
                    os.makedirs(out_dir)

                out_file = os.path.join(out_dir, f"misp_event_{event.uuid}.json")
                with open(out_file, "w") as f:
                    f.write(event.to_json())
                IOHandler.handle_message(
                    f"Successfully exported functions offline. Saved to {out_file}"
                )
        except Exception as e:
            IOHandler.handle_exception_message(e, "Error saving offline event to JSON")
    else:
        IOHandler.handle_message(
            f"Successfully added functions to event {event.info} ({event.uuid}). {mispGhidra.get_misp_url(event.uuid)} "
        )


def search_functions_in_misp(
    state,
    interpreter,
    monitor,
    func_addresses=None,
    all_functions=False,
    use_current_selection=False,
    ignored_functions=[],
    included_functions=["import", "export", "thunk", "internal"],
    name_include=None,
    name_exclude=None,
    min_blocks=0,
):

    # TODO This function is experimental, needs to be optimized
    isHeadless = state.getTool() is None
    selectedProgram = state.getCurrentProgram()

    mispGhidra = PyMISPGhidra(selectedProgram, interpreter, monitor)
    IOHandler = PyMISPGhidraIOHandler(
        mispghidra=mispGhidra,
        interpreter=interpreter,
        monitor=monitor,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )

    if mispGhidra.offline:
        IOHandler.handle_message(
            "Search requires a MISP connection. Currently in offline mode."
        )
        return

    func_addresses = get_function_selection_addresses(
        func_addresses=func_addresses,
        all_functions=all_functions,
        use_current_selection=use_current_selection,
        state=state,
        interpreter=interpreter,
        monitor=monitor,
        IOHandler=IOHandler,
    )
    funcs = filter_functions(
        func_addresses=func_addresses,
        name_include=name_include,
        name_exclude=name_exclude,
        ignored_functions=ignored_functions,
        included_functions=included_functions,
        min_blocks=min_blocks,
        state=state,
        interpreter=interpreter,
        monitor=monitor,
        IOHandler=IOHandler,
    )

    monitor.initialize(
        len(funcs), f"Looking for function hashes for {len(funcs)} functions..."
    )

    for i, func in enumerate(funcs):
        if monitor.isCancelled():
            exit()

        monitor.setProgress(i)
        # 1. Extract the info from the current function
        func_infos = mispGhidra.get_function_infos(func=func)

        # 2. Prepare our search criteria
        search_terms = []
        if func_infos.get("fid-fh-hash"):
            search_terms.append(func_infos["fid-fh-hash"])
        if func_infos.get("fid-fx-hash"):
            search_terms.append(func_infos["fid-fx-hash"])
        if func_infos.get("bsim-vector"):
            search_terms.append(func_infos["bsim-vector"])

        # 3. Perform the search in MISP
        for term in search_terms:
            if monitor.isCancelled():
                exit()

            logger.info(f"Searching MISP for attribute: {term}...")

            search_result = mispGhidra.misp.search(
                controller="attributes", value=term, pythonify=True
            )

            if search_result:
                for attribute in search_result:
                    # Logic for what to do when a match is found
                    # (e.g., link the current event to the found event)
                    event_id = attribute.event_id
                    parent_id = attribute.Object["id"]
                    parent_obj = mispGhidra.misp.get_object(parent_id, True)

                    name = parent_obj.get_attributes_by_relation("function-name")
                    logger.info(
                        f"MATCH FOUND: Function {func_infos['function-name']} matches {term} Attribute in Event {event_id} with name {name}"
                    )

                    # Optional: Add a tag or a relationship if you find a match
                    # mispGhidra.add_tag_to_current_event(tag=f"matches-event-{event_id}")
            else:
                logger.info(f"No match found for {term}")


def create_call_tree(state, interpreter, monitor, event_uuid=None):

    # IO Handler regardless of headless or GUI mode
    selectedProgram = state.getCurrentProgram()
    isHeadless = interpreter.getState().getTool() is None

    logger.info(f"Running main {os.path.basename(__file__)} with parameters:")
    logger.info(f"    Event UUID: {event_uuid}")

    # Boilerplate
    mispGhidra = PyMISPGhidra(selectedProgram, interpreter, monitor)
    IOHandler = PyMISPGhidraIOHandler(
        mispghidra=mispGhidra,
        interpreter=interpreter,
        monitor=monitor,
        isHeadless=isHeadless,
        script_name=os.path.basename(__file__),
    )

    if mispGhidra.offline:
        IOHandler.handle_message(
            "Creating call tree relations for an existing event requires a MISP connection. Currently in offline mode."
        )
        return

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


def get_event_selection(
    event_uuid,
    extend_event,
    new_event,
    state,
    interpreter,
    monitor,
    IOHandler,
    mispGhidra,
    offline=False,
):
    if offline:
        new_event = True

    if not extend_event and not new_event and event_uuid == None:

        action_type = IOHandler.handle_new_or_extend_event()

        if action_type == "new event":
            new_event = True
        elif action_type == "extend existing event":
            extend_event = True

    if event_uuid == None and not new_event:
        # No UUID provided, use sha256 search
        search_events = mispGhidra.get_existing_events()
        event_uuid = IOHandler.handle_events_selection(
            search_events, ask_new=True, ask_other=True
        )

        # User selected new in the GUI
        if event_uuid == "new":
            new_event = True

        if event_uuid == "other":
            event_uuid = interpreter.askString(
                "Provide event UUID", "Provide event UUID"
            )
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

        if extend_event:

            new_event_name = (
                f"Extended Ghidra Exported Event from {state.currentProgram.getName()}"
            )
            event = mispGhidra.create_empty_event(
                new_event_name, extends_uuid=event.uuid
            )
    return event


def get_function_selection_addresses(
    func_addresses,
    all_functions,
    use_current_selection,
    state,
    interpreter,
    monitor,
    IOHandler,
):

    selectedProgram = state.getCurrentProgram()

    # If --all-functions is set, ignore provided function addresses and use all functions in the program
    if all_functions:
        func_addresses = []
        monitor.setMessage(f"Fetching all functions addresses from Ghidra")
        for func in selectedProgram.getFunctionManager().getFunctions(True):
            if monitor.isCancelled():
                exit()
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

    return func_addresses


def filter_functions(
    func_addresses,
    name_include,
    name_exclude,
    ignored_functions,
    included_functions,
    min_blocks,
    state,
    interpreter,
    monitor,
    IOHandler,
):

    selectedProgram = state.getCurrentProgram()

    logger.info(f"Function addresses after handling parameters: {func_addresses}")
    funcs = []

    include_re = re.compile(name_include) if name_include else None
    exclude_re = re.compile(name_exclude) if name_exclude else None

    blockModel = BasicBlockModel(selectedProgram)

    # Check functions exist and retrieve them, handle exceptions if they don't
    monitor.setMessage(f"Applying function filters...")

    if "internal" in included_functions:
        logger.warning("Internal identification is not supported for now")

    if "export" in included_functions:
        logger.warning("Export identification is not supported for now")

    if "export" in ignored_functions:
        logger.warning("Export identification is not supported for now")

    if "internal" in ignored_functions:
        logger.warning("Internal identification is not supported for now")

    for func_address in func_addresses:

        if monitor.isCancelled():
            exit()
        try:
            func = (
                state.getCurrentProgram()
                .getFunctionManager()
                .getFunctionContaining(
                    FlatProgramAPI(state.getCurrentProgram()).toAddr(func_address)
                )
            )

            if func is None:
                logger.info(f"No function found at address {func_address}")
                continue

            # IGNORED FUNCTION TYPES
            if "thunk" in ignored_functions and func.isThunk():
                logger.info(f"ignore thunked {name}")
                continue

            if "import" in ignored_functions and func.isExternal():
                logger.info(f"ignore import {name}")
                continue

            # INCLUDED FUNCTION TYPES
            if "thunk" not in included_functions and func.isThunk():
                logger.info(f"not include thunked {name}")
                continue

            if "import" not in included_functions and func.isExternal():
                logger.info(f"not include import {name}")
                continue

            name = func.getName()
            # 1. Exclusion Logic (Skip matches)
            if exclude_re and exclude_re.search(name):
                logger.info(f"exclude regex {name}")
                continue

            # 2. Inclusion Logic (Only keep matches)
            if include_re and not include_re.search(name):
                logger.info(f"not include regex {name}")
                continue

            # Small functions exclusion, based on min blocks
            blocks = blockModel.getCodeBlocksContaining(func.getBody(), None)
            count = 0
            while blocks.hasNext():
                blocks.next()
                count += 1

            if count < min_blocks:

                logger.info(f"Ignored small func {name} {count}")

            funcs.append(func)

        except Exception as e:
            IOHandler.handle_exception_message(e, "Error retrieving function")

    return funcs
