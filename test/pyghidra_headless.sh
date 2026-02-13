#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="/tmp/"
PROJECT_NAME="temp_project"
BINARY_PATH="/usr/bin/curl"
EVENT_UUID_EXISTING="b96c200f-a0de-4890-b130-6e7885b206dd"
FUNCTION_ADDRESS="0010e3a0"

# Add object to event
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-function-to-MISP.py \
    --event-uuid ${EVENT_UUID_EXISTING} \
    --function-address ${FUNCTION_ADDRESS} \
    --verbose

# Add object to new event
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-function-to-MISP.py \
    --event-uuid "new" \
    --function-address ${FUNCTION_ADDRESS} \
    --verbose

# Add multiple functions to new event
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid "new" \
    --function-address ${FUNCTION_ADDRESS} \
    --function-address 0010c120 \
    --verbose