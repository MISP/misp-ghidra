#!/bin/bash
source setup.sh

# Add multiple functions to new event
echo "[+] Testing API"
pyghidra ghidra_scripts/test-MISP-API.py
