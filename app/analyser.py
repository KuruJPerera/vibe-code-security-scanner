"""
analyser.py — coordinates all security checks across file types.
Imports from checks/python_checks.py and checks/frontend_checks.py.
"""

import os
from typing import List, Dict

from app.checks.python_checks import analyze_python_file, analyze_requirements_file
from app.checks.frontend_checks import analyze_frontend_file


def analyze_directory(directory: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []

    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            lower_name = filename.lower()

            # skip virtual environments and hidden directories
            if any(part.startswith(".") or part == "__pycache__" or part == ".venv"
                   for part in file_path.split(os.sep)):
                continue

            if lower_name.endswith(".py"):
                findings.extend(analyze_python_file(file_path, directory))
            elif lower_name == "requirements.txt" or lower_name == "setup.py":
                findings.extend(analyze_requirements_file(file_path, directory))
            elif lower_name.endswith((".html", ".js")):
                findings.extend(analyze_frontend_file(file_path, directory))

    return findings


def scan_directory(directory: str) -> List[Dict[str, object]]:
    return analyze_directory(directory)