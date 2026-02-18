#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="d5ad48bd-b027-4400-a564-dde16d0c883b"
FUNCTION_ADDRESS="101189"
SCRIPT="ghidra_scripts/ghidra-functions-to-MISP.py"

echo "[+] Add multiple functions to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "test/bin/test_ssl.elf" \
    -postScript "${SCRIPT}" \
    --new-event \
    --all-functions \
    --ignore thunks \
    -deleteProject

echo "[+] Add multiple functions to new event"
pyghidraRun --headless "${PROJECT_PATH}" "${PROJECT_NAME}" \
    -import "test/bin/test_ssl.elf" \
    -postScript "${SCRIPT}" \
    --new-event \
    --all-functions 