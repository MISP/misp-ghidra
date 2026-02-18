ghidra_scripts are entry point from Headless and GUI

They use :

# PyMISPGhidra

[PyMISPGhidra.py](../mispghidra/PyMISPGhidra.py)

The class handling MISP API and Ghidra integration

# PyMISPGhidraIOHandler :

[PyMISPGhidraIOHandler.py](../mispghidra/PyMISPGhidraIOHandler.py)

The class handling missing inputs by user, regardless of headless or GUI mode 

# PyMISPGhidraScripts: 

[PyMISPGhidraScripts.py](../mispghidra/PyMISPGhidraScripts.py)

Multiple functions to be used by ghidra_functions

The actual logic behind the ghidra_scripts