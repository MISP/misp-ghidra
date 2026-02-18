#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project"
BINARY_PATH="test/bin/test_ssl.elf"
EVENT_UUID_EXISTING="d5ad48bd-b027-4400-a564-dde16d0c883b"
FUNCTION_ADDRESS="101189"

echo "Project dir ${PROJECT_PATH}"

echo "[+] Batch import two scripts"
pyghidraRun --headless ${PROJECT_PATH} ${PROJECT_NAME} \
    -import "test/bin/test_ssl2.elf" \
    -import "test/bin/test_ssl.elf" \
    -postScript ghidra_scripts/ghidra-functions-to-MISP.py \
    --all-functions \
    --new-event \
    --verbose \

echo "[+] Do the same thing"
pyghidraRun --headless ${PROJECT_PATH} ${PROJECT_NAME} \
    -process "*" -noanalysis \
    -postScript ghidra_scripts/ghidra-functions-to-MISP.py \
    --all-functions \
    --new-event \
    --verbose \