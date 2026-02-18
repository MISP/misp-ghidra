# MISP configuration
# @author Thomas Caillet @rdmmf
# @category MISP.ghidra-function
# @keybinding
# @menupath MISP.MISP configuration
# @toolbar conf.png
# @runtime PyGhidra

import os
import platform
import subprocess
import shutil
from pathlib import Path


def setup_and_open_config():
    # 1. Setup paths relative to the script location
    script_dir = Path(__file__).parent.absolute()
    config_file = (script_dir / "../mispghidra/misp/config/config.toml").resolve()
    template_file = (
        script_dir / "../mispghidra/misp/config/config.template.toml"
    ).resolve()

    # 2. Check and Copy logic
    if not config_file.exists():
        if template_file.exists():
            print(f"Config not found. Creating from template: {config_file}")
            shutil.copy(template_file, config_file)
        else:
            print("Error: Neither config nor template found!")
            return

    # 3. Cross-platform open
    try:
        if platform.system() == "Windows":
            os.startfile(config_file)
        elif platform.system() == "Darwin":  # macOS
            subprocess.call(["open", str(config_file)])
        else:  # Linux/Unix
            subprocess.call(["xdg-open", str(config_file)])
    except Exception as e:
        print(f"Failed to open editor: {e}")


# Run the function
setup_and_open_config()
