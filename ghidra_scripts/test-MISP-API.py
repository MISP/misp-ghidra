# Test connection to the MISP instance
# @author Thomas Caillet @rdmmf
# @category MISP.ghidra-function
# @keybinding
# @menupath MISP.Test connection to the MISP instance
# @toolbar misp.png
# @runtime PyGhidra

import sys, os, importlib

from pymisp import MISPObject

from javax.swing import JFrame, JTextArea, JScrollPane, JButton, JPanel, JOptionPane
from java.awt import Dimension, BorderLayout
from java.awt.event import ActionListener

# Add library folder to sys.path
lib_dir = os.path.join(os.path.dirname(__file__), "..")
if lib_dir not in sys.path:
    sys.path.append(lib_dir)

import mispghidra
import mispghidra.PyMISPGhidra

# This is for updating the library if it has been edited while PyGhidra was running
importlib.reload(mispghidra)
importlib.reload(mispghidra.PyMISPGhidra)

from mispghidra.PyMISPGhidra import PyMISPGhidra
from mispghidra.PyMISPGhidraIOHandler import PyMISPGhidraIOHandler

import time, datetime, logging

logger = logging.getLogger(__name__)


def add_test_event():
    mispGhidra = PyMISPGhidra(currentProgram)

    event = {
        "info": "Test Event from Python",
        "date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "threat_level_id": 2,  # 1=High, 2=Medium, 3=Low, 4=Undefined
        "analysis": 0,  # 0=Initial, 1=Ongoing, 2=Completed
    }

    mispGhidra.misp.add_event(event)


def get_misp_version():

    mispGhidra = PyMISPGhidra(None)
    version = mispGhidra.misp.version["version"]

    return version


if __name__ == "__main__":

    headless = getState().getTool() is None

    print(f"Running in headless mode: {headless}")

    IOhandler = PyMISPGhidraIOHandler(isHeadless=headless)

    try:
        version = get_misp_version()
        IOhandler.handle_message(f"Succesfully connected to MISP {version}")
    except Exception as e:
        IOhandler.handle_exception_message("Couldn't connect")
