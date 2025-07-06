import os
import shutil

# Define target folders
structure = {
    "assets": ["nichosec_bg.png", "nichosec_ui.png"],
    "backup": ["nichosec_backup.py"],
    "src": ["main.py", "nichosec.py"],
    "src/ui": ["nichosec_ui.py", "nichosec_ui_merged.py", "nichosec_ui.png"]
}

# Create folders if they don't exist
for folder in structure:
    os.makedirs(folder, exist_ok=True)

# Move files into respective folders
for folder, files in structure.items():
    for file in files:
        if os.path.exists(file):
            shutil.move(file, os.path.join(folder, file))

# Create __init__.py files
open("src/__init__.py", "a").close()
open("src/ui/__init__.py", "a").close()

print("✅ Project structure updated successfully.")
