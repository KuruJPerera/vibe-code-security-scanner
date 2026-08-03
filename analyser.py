import ast
import os
import re
import sys
from typing import List, Dict, Optional

SECRET_PATTERN = re.compile(r"(password|api[_-]?key|secret|token)", re.IGNORECASE)
SQL_PATTERN = re.compile(r"\b(select|insert|update|delete|from|where)\b", re.IGNORECASE)
SENSITIVE_NAME_PATTERN = re.compile(r"(password|secret|token|user|db|session|profile|account)", re.IGNORECASE)


def _make_finding(check_name: str, severity: str, file_path: str, line_number: int, detail: str) -> Dict[str, object]:
    return {
        "check_name": check_name,
        "severity": severity,
        "file_path": file_path,
        "line_number": line_number,
        "detail": detail,
    }


def _get_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_route_function(node: ast.FunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Attribute) and func.attr.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                return True
            if isinstance(func, ast.Name) and func.id.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                return True
        elif isinstance(decorator, ast.Attribute):
            if decorator.attr.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                return True
        elif isinstance(decorator, ast.Name):
            if decorator.id.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                return True
    return False


def _has_auth_dependency(node: ast.FunctionDef) -> bool:
    for decorator in node.decorator_list:
        for child in ast.walk(decorator):
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name) and func.id == "Depends":
                    return True
                if isinstance(func, ast.Attribute) and func.attr == "Depends":
                    return True
            if isinstance(child, ast.Name) and child.id == "Depends":
                return True
    return False


def _looks_sensitive_response(value: ast.AST) -> bool:
    if isinstance(value, ast.Dict):
        for key in value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and SECRET_PATTERN.search(key.value):
                return True
        return False

    if isinstance(value, ast.Name):
        return bool(SENSITIVE_NAME_PATTERN.search(value.id))

    if isinstance(value, ast.Attribute):
        return bool(SENSITIVE_NAME_PATTERN.search(value.attr))

    if isinstance(value, ast.Call):
        return bool(SENSITIVE_NAME_PATTERN.search(ast.unparse(value)))

    return False


def check_security_headers(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    response_return_pattern = re.compile(
        r"\breturn\b\s+(?:response|jsonresponse|htmlresponse|plaintextresponse|redirectresponse|streamingresponse|fileresponse|response\(|jsonresponse\(|htmlresponse\(|plaintextresponse\(|redirectresponse\(|streamingresponse\(|fileresponse\()",
        re.IGNORECASE,
    )
    header_pattern = re.compile(
        r"(?:response\.headers\s*\[|headers\s*=\s*\{|headers\s*\[|\b(?:x-content-type-options|x-frame-options|content-security-policy|strict-transport-security)\b)",
        re.IGNORECASE,
    )

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_route_function(node):
            continue

        function_source = ast.get_source_segment(source, node) or ""
        if not function_source:
            continue
        if not response_return_pattern.search(function_source):
            continue
        if header_pattern.search(function_source):
            continue

        findings.append(
            _make_finding(
                "Missing Security Headers",
                "medium",
                rel_path,
                getattr(node, "lineno", 1),
                "Route returns a response without setting common security headers",
            )
        )

    return findings


def check_env_vars_in_source(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    env_var_pattern = re.compile(
        r"(secret|key|password|token|api|auth|credential|database_url)",
        re.IGNORECASE,
    )
    safe_load_pattern = re.compile(r"(os\.getenv|os\.environ|getenv|dotenv|load_dotenv)", re.IGNORECASE)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not node.targets:
            continue

        target_name = None
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id
                break
            if isinstance(target, ast.Attribute):
                target_name = target.attr
                break

        if not target_name:
            continue

        if safe_load_pattern.search(source):
            # Allow obvious env-loading patterns to pass without reporting.
            if isinstance(node.value, ast.Call) and (isinstance(node.value.func, ast.Attribute) and node.value.func.attr in {"getenv", "get"}) or (
                isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id in {"getenv", "get"}
            ):
                continue

        if not env_var_pattern.search(target_name):
            continue

        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            literal = value.value
            if len(literal) > 8 and not literal.startswith("${"):
                findings.append(
                    _make_finding(
                        "Environment Variable in Source",
                        "high",
                        rel_path,
                        getattr(value, "lineno", 1),
                        f"Sensitive value assigned directly to '{target_name}' instead of loading from environment or .env",
                    )
                )
        elif isinstance(value, ast.JoinedStr):
            findings.append(
                _make_finding(
                    "Environment Variable in Source",
                    "high",
                    rel_path,
                    getattr(value, "lineno", 1),
                    f"Sensitive value assigned directly to '{target_name}' instead of loading from environment or .env",
                )
            )

    return findings


def analyze_file(file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    with open(file_path, "r", encoding="utf-8") as handle:
        source = handle.read()

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    findings.extend(check_security_headers(source, file_path, root_dir))
    findings.extend(check_env_vars_in_source(source, file_path, root_dir))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.Assign) else node.value
            if value is None:
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                target_name = None
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        target_name = _get_name(target)
                        if target_name:
                            break
                else:
                    target_name = _get_name(node.target)

                if target_name and (SECRET_PATTERN.search(target_name) or SECRET_PATTERN.search(value.value)):
                    findings.append(
                        _make_finding(
                            "Hardcoded Secret",
                            "high",
                            rel_path,
                            getattr(value, "lineno", 1),
                            f"Potential hardcoded secret assigned to '{target_name}'",
                        )
                    )

        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"execute", "executemany"}:
                if node.args:
                    query_arg = node.args[0]
                    if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
                        if isinstance(query_arg.left, ast.Constant) and isinstance(query_arg.left.value, str) and SQL_PATTERN.search(query_arg.left.value):
                            findings.append(
                                _make_finding(
                                    "SQL Injection Risk",
                                    "high",
                                    rel_path,
                                    getattr(query_arg, "lineno", 1),
                                    "String formatting is used in a SQL query; prefer parameterized queries",
                                )
                            )
                    elif isinstance(query_arg, ast.Call) and isinstance(query_arg.func, ast.Attribute) and query_arg.func.attr == "format":
                        if isinstance(query_arg.func.value, ast.Constant) and isinstance(query_arg.func.value.value, str) and SQL_PATTERN.search(query_arg.func.value.value):
                            findings.append(
                                _make_finding(
                                    "SQL Injection Risk",
                                    "high",
                                    rel_path,
                                    getattr(query_arg, "lineno", 1),
                                    "String formatting is used in a SQL query; prefer parameterized queries",
                                )
                            )

            if isinstance(func, ast.Attribute) and func.attr == "run" and any(
                isinstance(keyword, ast.keyword) and keyword.arg == "debug" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords
            ):
                findings.append(
                    _make_finding(
                        "Debug Mode Enabled",
                        "medium",
                        rel_path,
                        getattr(node, "lineno", 1),
                        "Application debug mode is enabled",
                    )
                )

        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                findings.append(
                    _make_finding(
                        "Debug Mode Enabled",
                        "medium",
                        rel_path,
                        getattr(node, "lineno", 1),
                        "DEBUG flag is set to True",
                    )
                )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_route_function(node) and not _has_auth_dependency(node):
                findings.append(
                    _make_finding(
                        "Missing Authentication",
                        "high",
                        rel_path,
                        getattr(node, "lineno", 1),
                        "FastAPI route function has no authentication dependency",
                    )
                )

            for arg in list(node.args.args) + list(node.args.kwonlyargs):
                if arg.annotation is None and arg.arg not in {"self", "cls"}:
                    findings.append(
                        _make_finding(
                            "Missing Input Validation",
                            "medium",
                            rel_path,
                            getattr(arg, "lineno", node.lineno),
                            f"Parameter '{arg.arg}' has no type hint or validation",
                        )
                    )
                    break

            if _is_route_function(node):
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None and _looks_sensitive_response(child.value):
                        findings.append(
                            _make_finding(
                                "Sensitive Data in Response",
                                "high",
                                rel_path,
                                getattr(child, "lineno", 1),
                                "Route returns a potentially sensitive object or field",
                            )
                        )
                        break

    return findings


def analyze_directory(directory: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".py"):
                file_path = os.path.join(root, filename)
                findings.extend(analyze_file(file_path, directory))
    return findings


def scan_directory(directory: str) -> List[Dict[str, object]]:
    return analyze_directory(directory)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = analyze_directory(target)
    for finding in findings:
        print(finding)
