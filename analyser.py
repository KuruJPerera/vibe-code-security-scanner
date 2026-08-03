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
    for child in ast.walk(node):
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


def check_stack_trace_exposure(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    exception_detail_pattern = re.compile(r"(str\(e\)|repr\(e\)|traceback|exception\(|traceback\.print_exc|traceback\.format_exc)", re.IGNORECASE)
    logging_pattern = re.compile(r"(logging\.(error|exception|critical|warning)|logger\.(error|exception|critical|warning))", re.IGNORECASE)

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        for stmt in node.body:
            if isinstance(stmt, ast.Return):
                if stmt.value is not None and isinstance(stmt.value, ast.Call):
                    if isinstance(stmt.value.func, ast.Name) and stmt.value.func.id in {"str", "repr"}:
                        if stmt.value.args and isinstance(stmt.value.args[0], ast.Name) and stmt.value.args[0].id == "e":
                            findings.append(
                                _make_finding(
                                    "Stack Trace Exposure",
                                    "medium",
                                    rel_path,
                                    getattr(stmt, "lineno", 1),
                                    "Exception handler returns exception details directly to the user",
                                )
                            )
                            break
                if stmt.value is not None and exception_detail_pattern.search(ast.unparse(stmt.value)):
                    findings.append(
                        _make_finding(
                            "Stack Trace Exposure",
                            "medium",
                            rel_path,
                            getattr(stmt, "lineno", 1),
                            "Exception handler returns exception details or tracebacks directly to the user",
                        )
                    )
                    break

            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                if isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "print":
                    if stmt.value.args and exception_detail_pattern.search(ast.unparse(stmt.value.args[0])):
                        findings.append(
                            _make_finding(
                                "Stack Trace Exposure",
                                "medium",
                                rel_path,
                                getattr(stmt, "lineno", 1),
                                "Exception handler prints exception details or stack traces",
                            )
                        )
                        break

            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                if logging_pattern.search(ast.unparse(stmt.value)) and "exc_info=True" in ast.unparse(stmt.value):
                    findings.append(
                        _make_finding(
                            "Stack Trace Exposure",
                            "medium",
                            rel_path,
                            getattr(stmt, "lineno", 1),
                            "Exception handler logs with exc_info=True without sanitisation",
                        )
                    )
                    break

            if isinstance(stmt, ast.Raise):
                if isinstance(stmt.exc, ast.Call) and isinstance(stmt.exc.func, ast.Name) and stmt.exc.func.id == "HTTPException":
                    for kw in stmt.exc.keywords:
                        if kw.arg == "detail" and kw.value is not None:
                            if exception_detail_pattern.search(ast.unparse(kw.value)):
                                findings.append(
                                    _make_finding(
                                        "Stack Trace Exposure",
                                        "medium",
                                        rel_path,
                                        getattr(stmt, "lineno", 1),
                                        "HTTPException detail includes exception details or stack traces",
                                    )
                                )
                                break

    return findings


def check_rate_limiting(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    limiter_decorator_names = {"limit", "ratelimit"}
    limiter_imports = {"slowapi", "flask_limiter", "fastapi_limiter"}
    high_priority_routes = {"login", "register", "password", "reset", "payment", "checkout", "auth"}

    imported_limiter = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in limiter_imports:
                    imported_limiter = True
                    break
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in limiter_imports:
                imported_limiter = True

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_route_function(node):
            continue

        function_name = node.name.lower()
        has_limiter = False

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                func = decorator.func
                if isinstance(func, ast.Attribute) and func.attr.lower() in limiter_decorator_names:
                    has_limiter = True
                    break
                if isinstance(func, ast.Name) and func.id.lower() in limiter_decorator_names:
                    has_limiter = True
                    break
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr.lower() in limiter_decorator_names:
                    has_limiter = True
                    break
            elif isinstance(decorator, ast.Name):
                if decorator.id.lower() in limiter_decorator_names:
                    has_limiter = True
                    break

        if not has_limiter and not imported_limiter:
            severity = "high" if any(term in function_name for term in high_priority_routes) else "medium"
            findings.append(
                _make_finding(
                    "Missing Rate Limiting",
                    severity,
                    rel_path,
                    getattr(node, "lineno", 1),
                    "Route function has no visible rate limiting protection",
                )
            )

    return findings


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
                    "Sensitive token or session data is being stored in localStorage or sessionStorage instead of a secure httpOnly cookie",
                )
            )

    return findings


def check_exposed_admin_endpoints(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    path_markers = ("/admin", "/debug", "/internal", "/dev", "/test", "/console", "/manage", "/superuser", "/root")
    function_markers = ("admin", "debug", "internal", "superuser", "manage", "console")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _has_auth_dependency(node):
            continue

        function_name = node.name.lower()
        if not any(marker in function_name for marker in function_markers):
            continue

        path_value = None
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                    if decorator.args:
                        first_arg = decorator.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            path_value = first_arg.value
                            break
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                    continue
            elif isinstance(decorator, ast.Name):
                if decorator.id.lower() in {"get", "post", "put", "delete", "patch", "route"}:
                    continue

        if path_value is None:
            path_value = ""

        if any(marker in path_value.lower() for marker in path_markers):
            findings.append(
                _make_finding(
                    "Exposed Admin Endpoint",
                    "high",
                    rel_path,
                    getattr(node, "lineno", 1),
                    "Route appears to expose admin or debug functionality without authentication",
                )
            )

    return findings


def check_file_upload_validation(source: str, file_path: str, root_dir: Optional[str] = None) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    rel_path = os.path.relpath(file_path, root_dir or os.getcwd())
    upload_param_names = ("file", "upload", "attachment", "document", "image")
    upload_annotation_names = ("UploadFile", "File")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        has_upload_param = False
        upload_param_name = None
        for arg in list(node.args.args) + list(node.args.kwonlyargs):
            arg_name = arg.arg.lower()
            if any(name in arg_name for name in upload_param_names):
                has_upload_param = True
                upload_param_name = arg_name
                break
            if arg.annotation is not None:
                annotation_text = ast.unparse(arg.annotation)
                if any(name in annotation_text for name in upload_annotation_names):
                    has_upload_param = True
                    upload_param_name = arg_name
                    break

        if not has_upload_param:
            continue

        function_source = ast.get_source_segment(source, node) or ""
        has_extension_check = bool(re.search(r"(?:endswith|split\(|os\.path\.splitext|pathlib\.Path\(|suffix)", function_source, re.IGNORECASE))
        has_content_type_check = bool(re.search(r"content[_-]?type|mime", function_source, re.IGNORECASE))
        has_size_check = bool(re.search(r"size|length|bytes|filesize", function_source, re.IGNORECASE))

        if not has_extension_check and not has_content_type_check and not has_size_check:
            severity = "high"
            detail = "Upload handler accepts files without any visible validation for extension, content type, or size"
        elif has_extension_check + has_content_type_check + has_size_check == 1:
            severity = "medium"
            detail = "Upload handler performs partial validation but is missing one or more controls for extension, content type, or size"
        else:
            continue

        findings.append(
            _make_finding(
                "Missing File Upload Validation",
                severity,
                rel_path,
                getattr(node, "lineno", 1),
                detail,
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
    findings.extend(check_stack_trace_exposure(source, file_path, root_dir))
    findings.extend(check_rate_limiting(source, file_path, root_dir))
    findings.extend(check_exposed_admin_endpoints(source, file_path, root_dir))
    findings.extend(check_file_upload_validation(source, file_path, root_dir))

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
            if filename.endswith((".py", ".html", ".js")):
                file_path = os.path.join(root, filename)
                if filename.endswith(".py"):
                    findings.extend(analyze_file(file_path, directory))
                else:
                    with open(file_path, "r", encoding="utf-8") as handle:
                        source = handle.read()
                    findings.extend(check_insecure_token_storage(source, file_path, directory))
    return findings


def scan_directory(directory: str) -> List[Dict[str, object]]:
    return analyze_directory(directory)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = analyze_directory(target)
    for finding in findings:
        print(finding)
