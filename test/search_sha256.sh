#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="/tmp/test-projects/" #"$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
FUNCTION_ADDRESS="00105028"

echo "[+] Adding object to new event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --function-address ${FUNCTION_ADDRESS} \
    --new-event

echo "[+] Adding object to exising event, will fail if there are more than one events with file"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --function-address ${FUNCTION_ADDRESS} \

echo "[+] Adding multiple functions object to new event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --function-address ${FUNCTION_ADDRESS} \
    --all-functions \
    --new-event
    
echo "[+] Adding object to exising event, will fail if there are more than one events with file"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --function-address ${FUNCTION_ADDRESS} \