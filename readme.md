MISP-Ghidra is a python library and scripts to extend Ghidra for exporting ghidra decompilation indicators (functions names, FID hashes, BSIM vectors) to MISP Objects

This is a work in progress.

# Requirements

Ghidra 12.0.2 with PyGhidra and BSIM plugin activated

# Installation

Install requirements with your pyghidra venv
```bash
ghidra_12.0.2_PUBLIC/venv/bin/pip install -r requirements.txt
```

Copy the MISP config.toml template and edit with your own API keys
```bash
cp mispghidra/misp/config/config.template.toml mispghidra/misp/config/config.toml
```

# GUI Usage

Launch ghidra with PyGhidra : `pyghidra -g`

Add the `ghidra_scripts` directory from this git repository to the Ghidra Bundle Manager

The scripts are under the category `MISP`

Run `MISP/Test connection to the MISP instance` to test the connection to the MISP instances API (configured in config.toml)

![GUI scripts](img/GUI-functions.png)

# Headless Usage

Check the [`/test/`](/test/) directory bash scripts for more examples.

## Add a sinle ghidra-function object to existing event in MISP
```bash
pyghidraRun --headless ${PROJECT_PATH} ${PROJECT_NAME} \
    -import ${BINARY_PATH} \
    -postScript ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid ${EVENT_UUID_EXISTING} \
    --function-address ${FUNCTION_ADDRESS}
```
## Add object to new event in MISP
```bash
pyghidra \
pyghidraRun --headless ${PROJECT_PATH} ${PROJECT_NAME} \
    -import ${BINARY_PATH} \
    -postScript ghidra_scripts/ghidra-functions-to-MISP.py \
    --new-event \
    --function-address ${FUNCTION_ADDRESS}
```

## Add all functions to an event
```bash
pyghidraRun --headless ${PROJECT_PATH} ${PROJECT_NAME} \
    -import ${BINARY_PATH} \
    -postScript ghidra_scripts/ghidra-functions-to-MISP.py \
    --new-event \
    --all-functions
```

## Filter on function types and names 

This is still a work in progress.

You can filter on which functions to send based on function types (thunk, defined, external, internal) and function names (regex)

```bash
pyghidraRun --headless ${PROJECT_PATH} ${PROJECT_NAME} \
    -import ${BINARY_PATH} \
    -postScript ghidra_scripts/ghidra-functions-to-MISP.py \
    --new-event \
    --all-functions
    --name-include "entry" \
    --name-exclude "^_|^abort|^plt" \
    --ignore thunks \
    --new-event \
```

# In MISP

misp-ghidra creates by default the objects: 
```
	file   | file
    ghidra | ghidra-function
```

## Correlation graph on FID hashes

Event correlation graph

<img src="img/correlation.png">

## Function call tree graph

Event graph

<img src="img/function_call_graph.png">
