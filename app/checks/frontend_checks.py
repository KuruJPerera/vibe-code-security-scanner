import os
import re
from typing import List, Dict, Optional


def _make_finding(check_name: str, severity: str, file_path: str, line_number: int, detail: str) -> Dict[str, object]:
    return {
        "check_name": check_name,
        "severity": severity,
        "file_path": file_path,
        "line_number": line_number,
        "detail": detail,
    }


def check_insecure_token_storage(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    pattern = re.compile(
        r"(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['\"][^'\"]*(?:token|session|auth|jwt|key)[^'\"]*['\"]|(?:localStorage|sessionStorage)\s*\.\s*\w+\s*=|(?:localStorage|sessionStorage)\s*\[",
        re.IGNORECASE,
    )
    sensitive_word_pattern = re.compile(r"(token|jwt|auth|session|key)", re.IGNORECASE)

    for match in pattern.finditer(source):
        line_number = source.count("\n", 0, match.start()) + 1
        if sensitive_word_pattern.search(match.group(0)):
            findings.append(
                _make_finding(
                    "Insecure Token Storage",
                    "high",
                    rel_path,
                    line_number,
                    "Sensitive token or session data stored in localStorage or sessionStorage instead of a secure httpOnly cookie",
                )
            )

    return findings


def check_api_key_on_frontend(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    lines = source.splitlines()

    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        if re.search(r"\b(?:apiKey|api_key|token|secret|authToken|clientSecret)\b", line, re.IGNORECASE):
            if re.search(r"['\"][^'\"]{4,}['\"]", line):
                findings.append(
                    _make_finding(
                        "API Key Exposed on Frontend",
                        "high",
                        rel_path,
                        index,
                        "Frontend code contains a hardcoded API key, token, or secret",
                    )
                )
                continue

        if re.search(r"(?:Authorization\s*:\s*['\"]Bearer\s+[^'\"]+|Bearer\s+[A-Za-z0-9._~+/=-]+)", line):
            findings.append(
                _make_finding(
                    "API Key Exposed on Frontend",
                    "high",
                    rel_path,
                    index,
                    "Frontend code contains a hardcoded bearer token or authorization header",
                )
            )
            continue

        if re.search(r"(?:sk-[A-Za-z0-9]{10,}|pk-[A-Za-z0-9]{10,}|AIza[0-9A-Za-z\-_]{10,}|AKIA[0-9A-Z]{10,})", line):
            findings.append(
                _make_finding(
                    "API Key Exposed on Frontend",
                    "high",
                    rel_path,
                    index,
                    "Frontend code contains a hardcoded API key pattern",
                )
            )

    return findings


def analyze_frontend_file(file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    with open(file_path, "r", encoding="utf-8") as handle:
        source = handle.read()
    findings.extend(check_insecure_token_storage(source, file_path, root_dir))
    findings.extend(check_api_key_on_frontend(source, file_path, root_dir))
    return findings