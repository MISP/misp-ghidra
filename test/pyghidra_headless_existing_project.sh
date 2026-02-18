#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
BINARY_NAME="test_ssl.elf" # The name as it appears inside the Ghidra project
EVENT_UUID_EXISTING="d5ad48bd-b027-4400-a564-dde16d0c883b"
FUNCTION_ADDRESS="101189"
SCRIPT="ghidra_scripts/ghidra-functions-to-MISP.py"

echo "[+] Adding object to event"
# Using -import to bring the file into the temporary project
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT}" \
    --new-event \
    --function-address "${FUNCTION_ADDRESS}"

echo "[+] Doing the same without adding the bin path, just opening the project"
# Using -process "*" to target the binary already imported in the previous step
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -process "*" \
    -noanalysis \
    -postScript "${SCRIPT}" \
    --new-event \
    --function-address "${FUNCTION_ADDRESS}"