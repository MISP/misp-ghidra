#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
FUNCTION_ADDRESS="00105028"
SCRIPT="ghidra_scripts/ghidra-functions-to-MISP.py"

echo "[+] Adding object to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -overwrite \
    -postScript "${SCRIPT}" \
    --function-address "${FUNCTION_ADDRESS}" \
    --new-event

echo "[+] Adding object to existing event (logic handled by script)"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -overwrite \
    -postScript "${SCRIPT}" \
    --function-address "${FUNCTION_ADDRESS}"

echo "[+] Adding multiple functions object to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -overwrite \
    -postScript "${SCRIPT}" \
    --function-address "${FUNCTION_ADDRESS}" \
    --all-functions \
    --new-event
    
echo "[+] Adding object to existing event (logic handled by script)"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -overwrite \
    -postScript "${SCRIPT}" \
    --function-address "${FUNCTION_ADDRESS}"