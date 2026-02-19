# Recreate call tree in MISP
# @author Thomas Caillet @rdmmf
# @category MISP.ghidra-function
# @keybinding
# @menupath MISP.Call Tree.Recreate call tree in MISP
# @toolbar misp.png
# @runtime PyGhidra

# TODO seperate GUI and Headless

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

    args_list = getScriptArgs()
    parser = argparse.ArgumentParser(description="MISP Ghidra Integration Script")
    parser.add_argument(
        "--event-uuid", type=str, default=None, help="The MISP Event UUID"
    )
    args = parser.parse_args(args_list)

    PyMISPGhidraScripts.create_call_tree(
        state, get_current_interpreter(), monitor, args.event_uuid
    )

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
