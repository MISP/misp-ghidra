import logging
import os
from pyghidra.script import get_current_interpreter

from pymisp import MISPEvent
from java.util import ArrayList
import ghidra.program.model.listing.Function as Function

logger = logging.getLogger(__name__)

GUI_ASK_CHOICE_LIMIT = 100


class PyMISPGhidraIOHandler:
    """
    Helper class to handle user input and messages in a consistent way across Ghidra scripts, regardless of Headless or GUI mode.
    Only works for scripts
    """

    def __init__(
        self,
        mispghidra=None,
        interpreter=None,
        isHeadless=True,
        script_name="PyMISPGhidraScript",
    ):

        self.interpreter = interpreter
        self.isHeadless = isHeadless
        self.script_name = script_name
        self.mispghidra = mispghidra

    def handle_new_or_extend_event(self):
        if self.isHeadless:
            return None

        options = ["new event", "extend existing event", "add to existing event"]

        java_options = ArrayList()
        for opt in options:
            java_options.add(opt)

        choice = self.interpreter.askChoice(
            "Select action",
            "Select an event type to add the ghidra-function objects",
            java_options,
            java_options[0],
        )
        return choice

    def handle_events_selection(
        self, events: dict, ask_new=False, ask_other=False
    ) -> str:

        if self.isHeadless and len(events) == 0:
            raise Exception(
                "No events found for program sha256, please provide one or use --new-event"
            )

        if self.isHeadless and len(events) == 1:
            return events[0]["uuid"]

        if self.isHeadless and len(events) > 0:
            logger.warning("Multiple events found, please choose one among :")
            for event in events:
                logger.warning(f"   uuid : {event['uuid']}, info : {event['info']}")
            raise Exception(
                "Multiple events found for program sha256, please choose one."
            )

        if not self.isHeadless:
            java_options = ArrayList()

            if ask_new:
                java_options.add("new")

            if ask_new:
                java_options.add("other")

            for event in events:

                java_options.add(f"{event['uuid']}:{event['info']}")

            choice = self.interpreter.askChoice(
                "Found multiple events with program sha256, choose one to attach ghidra-functions objects: ",
                "Select UUID",
                java_options,
                java_options.get(0),
            )

            uuid = choice.split(":")[0]
        return uuid

    def handle_functions_selections(
        self, functions: list[Function], single_function=False
    ) -> str:

        if len(functions) == 1:
            return functions[0]

        if self.isHeadless and len(functions) > 0:
            logger.warning("Multiple functions found, please choose one.")
            for item in functions:
                logger.warning(
                    f"   entry : {item.getEntryPoint()} , function-name : {item.getName()}"
                )
            raise Exception("Multiple functions found, please choose one.")

        if not self.isHeadless:

            if len(functions) > GUI_ASK_CHOICE_LIMIT:

                functions = functions[:GUI_ASK_CHOICE_LIMIT]

            java_options = ArrayList()
            for func in functions:
                java_options.add(f"{func.getEntryPoint()}:{func.getName()}")

            if single_function:
                choice = self.interpreter.askChoice(
                    "Please select functions",
                    "Select Function",
                    java_options,
                    java_options.get(0),
                )
                address = choice.split(":")[0]
                return address
            else:
                choices = self.interpreter.askChoices(
                    "Please select functions ", "Select Function", java_options
                )
                addresses = [choice.split(":")[0] for choice in choices]
                return addresses
            # TODO use Ghidra parseChoices function

    def handle_event_uuid(self, uuid) -> str | None:

        if uuid is not None:
            return uuid

        # UUID is None, ask user in GUI
        if not self.isHeadless:
            uuid = self.interpreter.askString(
                "Enter MISP Event UUID",
                "Enter the UUID of the MISP event to add the function object to (type 'new' to create a new event, leave blank to search for event based on program hash):",
                "new",
            )
            if uuid == "":
                uuid = None

        return uuid

    def handle_exception_message(self, e, message):

        self.handle_message(f"{message}: {e}")
        raise ValueError(f"{message}: {e}")

    def handle_message(self, message):

        self.console_log(message)
        if self.isHeadless is False:
            self.interpreter.popup(message)

    def console_log(self, message):

        logger.info(f"[{self.script_name}] {message}")
