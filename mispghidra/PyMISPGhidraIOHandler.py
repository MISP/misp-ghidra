import logging
import os
from pyghidra.script import get_current_interpreter

logger = logging.getLogger(__name__)


class PyMISPGhidraIOHandler:
    """
    Helper class to handle user input and messages in a consistent way across Ghidra scripts, regardless of Headless or GUI mode.
    Only works for scripts
    """

    def __init__(
        self, verbose=False, isHeadless=True, script_name="PyMISPGhidraScript"
    ):

        self.interpreter = get_current_interpreter()
        self.verbose = verbose
        self.isHeadless = isHeadless
        self.script_name = script_name

    def handle_parameter(self, param, param_type):

        # Correct parameter, exit
        if param is not None and param is not []:
            return param

        # Missing parameter
        # In headless mode, log and raise an error
        if self.isHeadless:
            self.handle_exception_message(
                ValueError(f"Missing parameter {param_type}"),
                f"Error handling parameter {param_type}",
            )

        # In GUI, ask user for input
        user_GUI_input_handles = {
            "event-uuid": lambda: self.interpreter.askString(
                "Enter MISP Event UUID",
                "Enter the UUID of the MISP event to add the function object to (type 'new' to create a new event):",
                "new",
            ),
            "function-addresses": lambda: self.interpreter.currentAddress.toString(),
            "function-address": lambda: self.interpreter.askAddress(
                "Enter Function Address",
                "Enter the address of the function to add to MISP (default is current address):",
                self.interpreter.currentAddress.toString(),
            ).toString(),
        }

        if param_type in user_GUI_input_handles:
            try:
                return user_GUI_input_handles[param_type]()
            except Exception as e:
                self.handle_exception_message(
                    e, f"Error handling user input for parameter {param_type}"
                )

        # If param_type is not in user_GUI_input_handles, raise an error
        self.handle_exception_message(
            ValueError(f"Unknown parameter type {param_type}"),
            f"Error handling parameter {param_type}",
        )

    def handle_exception_message(self, e, message):

        self.handle_message(f"{message}: {e}")
        raise ValueError(f"{message}: {e}")

    def handle_message(self, message):

        self.console_log(message)
        if self.isHeadless is False:
            self.interpreter.popup(message)

    def console_log(self, message):

        logger.info(f"[{self.script_name}] {message}")
