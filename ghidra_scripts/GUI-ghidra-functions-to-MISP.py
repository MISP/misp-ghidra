# Manually select functions to MISP
# @author Thomas Caillet @rdmmf
# @category MISP.ghidra-function
# @keybinding
# @menupath MISP.Ghidra Functions.Manually select functions to MISP
# @runtime PyGhidra


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

    # Default args
    PyMISPGhidraScripts.functions_to_misp(
        state=state, interpreter=get_current_interpreter()
    )

    end = time.time()
    logger.info(f"Operation took {end - start:.6f} seconds")
