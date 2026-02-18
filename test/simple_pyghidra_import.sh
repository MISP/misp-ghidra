#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="d5ad48bd-b027-4400-a564-dde16d0c883b"
FUNCTION_ADDRESS="101189"
SCRIPT="ghidra_scripts/ghidra-functions-to-MISP.py"

# Use -import to handle the binary file directly from the filesystem
# -deleteProject is added to clean up the temp project after the run

echo "[+] Adding object to event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT}" \
    --event-uuid "${EVENT_UUID_EXISTING}" \
    --function-address "${FUNCTION_ADDRESS}" \
    -deleteProject

echo "[+] Adding object to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT}" \
    --new-event \
    --function-address "${FUNCTION_ADDRESS}" \
    -deleteProject

echo "[+] Adding multiple functions to an existing event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT}" \
    --event-uuid "${EVENT_UUID_EXISTING}" \
    --function-address "${FUNCTION_ADDRESS}" \
    --function-address "101100" \
    -deleteProject

echo "[+] Adding multiple functions to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT}" \
    --new-event \
    --function-address "${FUNCTION_ADDRESS}" \
    --function-address "101100" \
    -deleteProject

echo "[+] Add all functions to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "${BINARY_PATH}" \
    -postScript "${SCRIPT}" \
    --new-event \
    --all-functions \
    -deleteProject