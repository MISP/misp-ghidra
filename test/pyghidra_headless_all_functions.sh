#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="$(mktemp -d /tmp/ghidra-temp-project.XXXXXXXXX)"
PROJECT_NAME="temp_project" 
#BINARY_PATH="/usr/bin/curl"
BINARY_PATH="test/bin/test_ssl.elf" 

echo "[+] Add multiple functions to new event"
pyghidra -v \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid "new" \
    --all-functions