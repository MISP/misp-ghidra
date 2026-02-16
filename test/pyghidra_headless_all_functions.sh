#!/bin/bash
source setup.sh

# VARIABLES
PROJECT_PATH="/tmp/test-projects/"
PROJECT_NAME="temp_project" 
#BINARY_PATH="/usr/bin/curl"
BINARY_PATH="test/bin/test_ssl.elf" 

echo "[+] Add multiple functions to new event"
pyghidra \
    --project-name ${PROJECT_NAME} \
    --project-path ${PROJECT_PATH} \
    ${BINARY_PATH} \
    ghidra_scripts/ghidra-functions-to-MISP.py \
    --event-uuid "new" \
    --all-functions \
    --verbos