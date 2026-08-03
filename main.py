import os
import shutil
import subprocess
import tempfile
from typing import List, Dict

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, HTMLResponse
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - fallback for environments without FastAPI installed
    class BaseModel:
        def __init__(self, **data):
            for key, value in data.items():
                setattr(self, key, value)

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    class FileResponse(str):
        pass

    class HTMLResponse(str):
        pass

    class FastAPI:
        def __init__(self, title: str = ""):
            self.title = title
            self.routes = []

        def on_event(self, event_name: str):
            def decorator(func):
                return func
            return decorator

        def get(self, path: str, response_class=None):
            def decorator(func):
                self.routes.append({"path": path, "methods": ["GET"], "func": func})
                return func
            return decorator

        def post(self, path: str, response_class=None):
            def decorator(func):
                self.routes.append({"path": path, "methods": ["POST"], "func": func})
                return func
            return decorator

from analyser import analyze_directory
from database import get_all_scans, get_findings_by_scan, init_db, save_finding, save_scan


app = FastAPI(title="Vibe Code Security Scanner")


class ScanRequest(BaseModel):
    repo_url: str


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/", response_class=HTMLResponse)
def read_dashboard() -> FileResponse:
    dashboard_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    return FileResponse(dashboard_path)


@app.post("/scan")
def scan_repository(payload: ScanRequest) -> Dict[str, object]:
    repo_url = (payload.repo_url or "").strip()
    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required")

    temp_root = tempfile.mkdtemp(prefix="scan_", dir=None)
    repo_dir = os.path.join(temp_root, "repo")

    try:
        clone_result = subprocess.run(
            ["git", "clone", repo_url, repo_dir],
            capture_output=True,
            text=True,
            check=False,
        )
        if clone_result.returncode != 0:
            error_message = clone_result.stderr.strip() or clone_result.stdout.strip() or "Unknown git error"
            raise HTTPException(status_code=400, detail=f"git clone failed: {error_message}")

        findings = analyze_directory(repo_dir)
        total_findings = len(findings)
        scanned_files = sum(
            1
            for root, _, files in os.walk(repo_dir)
            for filename in files
            if filename.endswith(".py")
        )
        vulnerability_rate = round((total_findings / max(1, scanned_files)) * 100, 2) if scanned_files else 0.0

        scan_id = save_scan(repo_url, total_findings, vulnerability_rate)
        for finding in findings:
            save_finding(
                scan_id,
                finding["check_name"],
                finding["severity"],
                finding["file_path"],
                finding["line_number"],
                finding["detail"],
            )

        return {
            "scan_id": scan_id,
            "total_findings": total_findings,
            "vulnerability_rate": vulnerability_rate,
            "findings": findings,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Scan failed: {exc}") from exc
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@app.get("/scans")
def get_scans() -> List[Dict[str, object]]:
    return get_all_scans()


@app.get("/scans/{scan_id}")
def get_scan_findings(scan_id: int) -> List[Dict[str, object]]:
    return get_findings_by_scan(scan_id)
