#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="/tmp/"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="afc05077-55bd-4300-8a55-c32f77627696"
FUNCTION_ADDRESS="101189"

echo "[+] Adding object to event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-function-to-MISP.py \
    --event-uuid ${EVENT_UUID_EXISTING} \
    --function-address ${FUNCTION_ADDRESS} \
    --verbose

echo "[+] Adding object to new event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-function-to-MISP.py \
    --event-uuid "new" \
    --function-address ${FUNCTION_ADDRESS} \
    --verbose

echo "[+] Adding multiple functions to an existing event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid ${EVENT_UUID_EXISTING} \
    --function-address ${FUNCTION_ADDRESS} \
    --function-address 101100 \
    --verbose

echo "[+] Adding multiple functions to new event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid "new" \
    --function-address ${FUNCTION_ADDRESS} \
    --function-address 101100 \
    --verbose
