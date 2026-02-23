# Search for current functon in MISP
# @author Thomas Caillet @rdmmf
# @category MISP.search
# @keybinding
# @menupath MISP.Fetch from MISP.Fetch MISP comments for all function
# @runtime PyGhidra

import time, logging, argparse, importlib, os, sys

# Add library folder to sys.path
lib_dir = os.path.join(os.path.dirname(__file__), "..")
if lib_dir not in sys.path:
    sys.path.append(lib_dir)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import mispghidra.PyMISPGhidraScripts as PyMISPGhidraScripts

importlib.reload(PyMISPGhidraScripts)

from pyghidra import get_current_interpreter

if __name__ == "__main__":

    start = time.time()

    # Default args
    PyMISPGhidraScripts.search_functions_in_misp(
        all_functions=True,
        ignored_functions=["thunks"],
        state=state,
        interpreter=get_current_interpreter(),
        monitor=monitor,
    )

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
