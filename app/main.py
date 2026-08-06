import os
import shutil
import subprocess
import tempfile
from typing import List, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from groq import Groq
from pydantic import BaseModel

load_dotenv()

from app.analyser import analyze_directory
from app.database import get_all_scans, get_findings_by_scan, init_db, save_finding, save_scan


app = FastAPI(title="Vibe Code Security Scanner")
app.mount("/static", StaticFiles(directory="static"), name="static")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static")


class ScanRequest(BaseModel):
    repo_url: str


class RemediateRequest(BaseModel):
    check_name: str
    severity: str
    file_path: str
    line_number: int
    detail: str


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/", response_class=HTMLResponse)
def landing():
    return FileResponse(os.path.join(STATIC_DIR, "landing.html"))


@app.get("/scanner", response_class=HTMLResponse)
def scanner():
    return FileResponse(os.path.join(STATIC_DIR, "scanner.html"))


@app.get("/results", response_class=HTMLResponse)
def results():
    return FileResponse(os.path.join(STATIC_DIR, "results.html"))


@app.post("/remediate")
def remediate(payload: RemediateRequest) -> Dict[str, str]:
    try:
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=300,
            temperature=0.3,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a security engineer giving remediation advice. "
                        "Follow these rules strictly: Use clear, simple language. "
                        "Be direct and informative. Write short, impactful sentences. "
                        "Use active voice. Focus on practical, actionable fixes. "
                        "Address the developer directly using you and your. "
                        "Keep the total response under 150 words. "
                        "Use plain text only, no markdown, no bullet symbols, no asterisks, no headers. "
                        "Avoid these words: can, may, just, that, very, really, basically, actually, certainly, probably. "
                        "Give only the remediation output with no preamble or disclaimer."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Security finding in {payload.file_path} at line {payload.line_number}. "
                        f"Check: {payload.check_name}. "
                        f"Severity: {payload.severity}. "
                        f"Detail: {payload.detail}. "
                        f"Give a specific fix for this exact issue with a before and after code example."
                    )
                }
            ]
        )
        return {"remediation": response.choices[0].message.content.strip()}
    except Exception as e:
        return {"remediation": f"Unable to generate remediation: {str(e)}"}


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