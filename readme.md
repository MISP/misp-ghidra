This is a work in progress. MISP-Ghidra is a python library and scripts to extend Ghidra for exporting and 

# Installation

install requirements with your pyghidra venv
```bash
~/.config/ghidra/ghidra_12.0.2_PUBLIC/venv/bin/pip install -r requirements.txt
```

Add the `ghidra_scripts` directory to the Ghidra Bundle Manager

# GUI Usage

Launch ghidra with PyGhidra `ghidra_12.0.2_PUBLIC/support/pyghidraRun`

# Headless Usage
## Add object to existing event in MISP
```bash
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-function-to-MISP.py \
    --event-uuid ${EVENT_UUID_EXISTING} \
    --function-address ${FUNCTION_ADDRESS} \
    --verbose
```
## Add object to new event in MISP
```bash
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-function-to-MISP.py \
    --event-uuid "new" \
    --function-address ${FUNCTION_ADDRESS} \
    --verbose
```
# Example usage

For a malware analysis, an event could contain objects : 

	file | file
	file | elf / pe
	file | elf-section / pe-section / pe-optional-header
    file | malware
	ghidra | ghidra-program-metadata
    ghidra | ghidra-function


