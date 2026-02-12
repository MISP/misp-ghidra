# Add a ghidra-function object to a MISP Event (provide uuid)
# @author
# @category MISP.ghidra-function
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra

import sys, os, importlib

from pymisp import MISPObject

from javax.swing import JFrame, JTextArea, JScrollPane, JButton, JPanel, JOptionPane
from java.awt import Dimension, BorderLayout
from java.awt.event import ActionListener

from ghidra.util.task import ConsoleTaskMonitor

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

import time



def main(func=None, uuid=None):

    # Ask user for event id or uuid
    event_uuid = askString(
        "Enter MISP Event UUID",
        "Enter the UUID of the MISP event to add the function object to (type 0 to create a new event):",
    )

    mispGhidra = PyMISPGhidra(currentProgram)

    # Find function
    if func is None:
        try:
            functions = list(currentProgram.getFunctionManager().getFunctions(True))

            if len(functions) == 0:
                popup("No functions found in program")
                return
        except Exception as e:
            popup(f"Error retrieving functions: {e}")
            return

    # Handle input parameters
    if event_uuid is None or event_uuid == "0":
        new_event_name = f"Ghidra Exported Functions from {currentProgram.getName()}"
        event = mispGhidra.create_empty_event(new_event_name)
    else:
        try:
            event = mispGhidra.misp.get_event(event_uuid, pythonify=True)
            if event is None:
                popup("No event found with uuid " + event_uuid)
                return
        except Exception as e:
            popup(f"Error retrieving event: {e}")
            return

    count, fail_count, failed_object_creations = mispGhidra.add_object_from_functions(
        functions, event=event
    )

    popup(
        f"Successfully added functions {count} to event {event.info} ({event.uuid}). Failed to add {fail_count} functions."
    )


if __name__ == "__main__":

    headless = getState().getTool() is None
    print(f"Running in headless mode: {headless}")

    start = time.time()

    main()

    end = time.time()
    print(f"Operation took {end - start:.6f} seconds")
