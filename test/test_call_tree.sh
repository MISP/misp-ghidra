#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="/tmp/test-projects23/"
PROJECT_NAME="temp_project2"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="dd0d96a3-09d9-466b-a624-ff1c78d15259"
FUNCTION_ADDRESS="0010e3a0"

# Add multiple functions to new event
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid new \
    --all-functions \
    --no-call-tree \
    1>/tmp/uuids.txt

cat /tmp/uuids.txt | pyghidra -vv \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/create-MISP-call-tree.py \


