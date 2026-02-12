This is a work in progress. MISP-Ghidra is a python library and scripts to extend Ghidra for exporting and 

# Installation

install requirements with your pyghidra venv
```bash
~/.config/ghidra/ghidra_12.0.2_PUBLIC/venv/bin/pip install -r requirements.txt
```

Add the `ghidra_scripts` directory to the Ghidra Bundle Manager

# Usage

Launch ghidra with PyGhidra `ghidra_12.0.2_PUBLIC/support/pyghidraRun`

# Example usage

For a malware analysis, an event could contain objects : 

	file | file
	file | elf / pe
	file | elf-section / pe-section / pe-optional-header
    malware
	ghidra ghidra-program-metadata
    multiple ghidra-function


