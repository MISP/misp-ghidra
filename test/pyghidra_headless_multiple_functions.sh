#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="/tmp/test-projects/"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="b96c200f-a0de-4890-b130-6e7885b206dd"
FUNCTION_ADDRESS="0010e3a0"

echo "[+] Add multiple functions to new event"
pyghidra -v \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid "new" \
    --verbose