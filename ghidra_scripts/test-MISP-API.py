# Test the connection to the MISP instance configured in /mispghidra/misp/config/config.toml
# @author
# @category MISP.utils
# @keybinding
# @menupath
# @toolbar
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

import time, datetime


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

    mispGhidra = PyMISPGhidra(currentProgram)
    version = mispGhidra.misp.version["version"]

    return version


if __name__ == "__main__":
    headless = getState().getTool() is None
    print(f"Running in headless mode: {headless}")

    try:
        version = get_misp_version()
        popup("Succefully connected to MISP " + version)
    except Exception as e:
        popup("Failed to connect")
        print(e)
