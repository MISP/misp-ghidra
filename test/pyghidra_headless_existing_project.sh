#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="d5ad48bd-b027-4400-a564-dde16d0c883b"
FUNCTION_ADDRESS="101189"

echo "[+] Adding object to event"
pyghidra -v \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid ${EVENT_UUID_EXISTING} \
    --function-address ${FUNCTION_ADDRESS} \

echo "[+] Doing the same without adding the bin path, just opening the project"
pyghidra -v \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --new-event \
    --function-address ${FUNCTION_ADDRESS} \