#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project2"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="419739fe-37f8-47fe-96bb-de260996591d"
FUNCTION_ADDRESS="0010e3a0"
SCRIPT_MISP="headless_scripts/ghidra-functions-to-MISP.py"
SCRIPT_TREE="headless_scripts/create-MISP-call-tree.py"

# Add multiple functions to new event
echo "[+] Creating new event with all functions but no call tree"

# We use -import here. Note: pyghidraRun sends log info to stdout.
# Your python script must print "event:uuid:<uuid>" to stdout for grep to catch it.
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT_MISP}" \
    --event-uuid $EVENT_UUID_EXISTING \
    --all-functions \
    --no-call-tree \
    --verbose \


echo "[+] Now manually building call tree of event ${NEW_EVENT_UUID}"

# Use -process "*" because the binary is already imported into the project 
# from the previous step. This saves time on re-importing/re-analyzing.
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -process "*" \
    -noanalysis \
    -postScript "${SCRIPT_TREE}" \
    --event-uuid $EVENT_UUID_EXISTING \
    -v

# Cleanup the temp project
rm -rf "${PROJECT_PATH}"