# Add a ghidra-function object to a MISP Event (provide uuid)
# @author
# @category MISP.ghidra-function.test
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
import mispghidra.PyMISPGhidraIOHandler

# This is for updating the library if it has been edited while PyGhidra was running
importlib.reload(mispghidra)
importlib.reload(mispghidra.PyMISPGhidra)
importlib.reload(mispghidra.PyMISPGhidraIOHandler)

from mispghidra.PyMISPGhidra import PyMISPGhidra
from mispghidra.PyMISPGhidraIOHandler import PyMISPGhidraIOHandler

from pyghidra.script import get_current_interpreter

import time




def main(func_address=None, event_uuid=None, verbose=False):

    # IO Handler regardless of headless or GUI mode
    interpreter = get_current_interpreter()

    isHeadless = interpreter.getState().getTool() is None

    if verbose:
        print("Parameters:")
        print(f"    Function address: {func_address}")
        print(f"    Event UUID: {event_uuid}")
        print(f"    Headless mode: {isHeadless}")
    
    IOHandler = PyMISPGhidraIOHandler(verbose=verbose, isHeadless=isHeadless)
    mispGhidra = PyMISPGhidra(interpreter.currentProgram)
    
    # Handle input parameters regardless of headless or GUI mode
    func_address = IOHandler.handle_parameter(func_address, "function-address")
    func_address = interpreter.toAddr(func_address)
    
    # Find function
    try:
        func = interpreter.getFunctionAt(func_address)
    except Exception as e:
        IOHandler.handle_exception_message(e, "Error retrieving function")
    if func is None:
        IOHandler.handle_exception_message(ValueError(f"No function found at address {func_address}"), "Error retrieving function")

    event_uuid = IOHandler.handle_parameter(event_uuid, "event-uuid")

    if event_uuid == "new":
        new_event_name = f"Ghidra Exported Function {func.getName()} from {interpreter.currentProgram.getName()}"
        event = mispGhidra.create_empty_event(new_event_name)
    else:
        try:
            event = mispGhidra.misp.get_event(event_uuid, pythonify=True)
            if event is None:
                IOHandler.handle_exception_message(ValueError("No event found with uuid " + event_uuid), "Error retrieving event")
        except Exception as e:
            IOHandler.handle_exception_message(e, "Error retrieving event")

    mispGhidra.add_object_from_function(func, event=event)

    IOHandler.handle_message(
        f"Successfully added function {func.getName()} to event {event.info} ({event.uuid}). "
    )



if __name__ == "__main__":
    start = time.time()

    args = getScriptArgs()
    func_address = None
    event_uuid = None
    verbose = False

    # ['--event-uuid', '550e8400-e29b-41d4-a716-446655440000', '--function-address', '0010e3a0', '--verbose']
    for i in range(len(args)):
        if args[i] == "--function-address" and i + 1 < len(args):
            func_address = args[i + 1]
        elif args[i] == "--event-uuid" and i + 1 < len(args):
            event_uuid = args[i + 1]
        elif args[i] == "--verbose":
            verbose = True


    print(f"Running {os.path.basename(__file__)} with arguments:")    

    main(func_address=func_address, event_uuid=event_uuid, verbose=verbose)

    end = time.time()
    print(f"Operation took {end - start:.6f} seconds")
