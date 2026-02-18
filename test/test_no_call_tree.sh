#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project2"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="dd0d96a3-09d9-466b-a624-ff1c78d15259"
FUNCTION_ADDRESS="0010e3a0"
SCRIPT_MISP="ghidra_scripts/ghidra-functions-to-MISP.py"
SCRIPT_TREE="ghidra_scripts/create-MISP-call-tree.py"

# Add multiple functions to new event
echo "[+] Creating new event with all functions but no call tree"

# We use -import here. Note: pyghidraRun sends log info to stdout.
# Your python script must print "event:uuid:<uuid>" to stdout for grep to catch it.
NEW_EVENT_UUID=$(pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT_MISP}" \
    --new-event \
    --all-functions \
    --no-call-tree \
| grep -Po '(?<=event:uuid:)[a-f0-9-]+')

echo "Extracted UUID: ${NEW_EVENT_UUID}"

echo "[+] Now manually building call tree of event ${NEW_EVENT_UUID}"

# Use -process "*" because the binary is already imported into the project 
# from the previous step. This saves time on re-importing/re-analyzing.
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -process "*" \
    -noanalysis \
    -postScript "${SCRIPT_TREE}" \
    --event-uuid "${NEW_EVENT_UUID}"

# Cleanup the temp project
rm -rf "${PROJECT_PATH}"