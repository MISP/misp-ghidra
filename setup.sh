#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/.env" ]; then
    echo "[+] Loading environment variables from .env"
    
    # Use 'set -a' to automatically export all variables defined in the file
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
else
    echo "[-] WARNING: .env file not found at $SCRIPT_DIR/.env"
    echo "[!] Please copy .env.example to .env and fill in your details."
    exit 1
fi

source ${VENV_PATH}/bin/activate
pip install -r requirements.txt --quiet