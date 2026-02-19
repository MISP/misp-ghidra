# Manually select functions to MISP
# @author Thomas Caillet @rdmmf
# @category MISP.Headless
# @keybinding
# @menupath
# @runtime PyGhidra

# Headless only

import time, logging, argparse, importlib, os, sys

# Add library folder to sys.path
lib_dir = os.path.join(os.path.dirname(__file__), "..")
if lib_dir not in sys.path:
    sys.path.append(lib_dir)

logger = logging.getLogger(__name__)

import mispghidra.PyMISPGhidraScripts as PyMISPGhidraScripts

importlib.reload(PyMISPGhidraScripts)

from pyghidra import get_current_interpreter

if __name__ == "__main__":

    start = time.time()

    parser = argparse.ArgumentParser(description="Ghidra Script Argument Parser")

    # Args
    parser.add_argument(
        "-a", "--function-address", dest="func_addresses", action="append", default=[]
    )
    parser.add_argument("--event-uuid", type=str, default=None)

    functions_types_choices = ["imports", "exports", "thunks", "defined"]
    parser.add_argument(
        "--ignore",
        dest="ignored_functions",
        action="append",
        default=[],
        choices=functions_types_choices,
    )
    parser.add_argument(
        "--include",
        dest="included_functions",
        action="append",
        default=functions_types_choices,
        choices=functions_types_choices,
    )

    # Flags
    parser.add_argument(
        "--no-call-tree",
        dest="call_tree",
        action="store_false",
        help="Disable call tree",
    )
    parser.add_argument(
        "--all",
        "--all-functions",
        dest="all_functions",
        action="store_true",
        help="Use all functions",
    )
    parser.add_argument(
        "-n",
        "--new-event",
        dest="new_event",
        action="store_true",
        help="Create a new event",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        help="increase output verbosity",
        action="store_true",
    )

    parser.add_argument(
        "--name-include",
        type=str,
        help="Regex pattern: only export functions matching this (e.g., '^LAB_' or 'malware_')",
    )
    parser.add_argument(
        "--name-exclude",
        type=str,
        help="Regex pattern: skip functions matching this (e.g., '^__libc|^_')",
    )

    parser.add_argument(
        "--min-blocks",
        type=int,
        default=0,
        help="Minimum of basic blocks for a function to be included",
    )

    parser.add_argument(
        "--extend-event",
        action="store_true",
        default=False,
        help="Extend the event with --event-uuid",
    )

    # 3. Get Ghidra's arguments and parse them
    # Note: we pass getScriptArgs() specifically so argparse doesn't look at sys.argv
    args_list = getScriptArgs()
    args = parser.parse_args(args_list)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    PyMISPGhidraScripts.functions_to_misp(
        state=state,
        interpreter=get_current_interpreter(),
        monitor=monitor,
        func_addresses=args.func_addresses,
        event_uuid=args.event_uuid,
        all_functions=args.all_functions,
        call_tree=args.call_tree,
        new_event=args.new_event,
        ignored_functions=args.ignored_functions,
        included_functions=args.included_functions,
        name_include=args.name_include,
        name_exclude=args.name_exclude,
        min_blocks=args.min_blocks,
        extend_event=args.extend_event,
    )

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
