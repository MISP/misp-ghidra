#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project2"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="dd0d96a3-09d9-466b-a624-ff1c78d15259"
FUNCTION_ADDRESS="0010e3a0"

# Add multiple functions to new event
echo "[+] Creating new event with all functions but no call tree"
NEW_EVENT_UUID=$(pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --new-event \
    --all-functions \
    --no-call-tree \
| grep -Po '(?<=event:uuid:)[a-f0-9-]+')

echo "[+] Now manually building call tree of event ${NEW_EVENT_UUID}"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/create-MISP-call-tree.py \
    --event-uuid ${NEW_EVENT_UUID}