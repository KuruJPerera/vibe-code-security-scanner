<div align="center">

# Vibe Code Security Scanner

### Automated security analysis for AI-generated codebases. Find the vulnerabilities that vibe coding introduces before they reach production.

<br/>

<a href="https://github.com/KuruJPerera/vibe-code-security-scanner/actions"><img src="https://github.com/KuruJPerera/vibe-code-security-scanner/actions/workflows/security-pipeline.yml/badge.svg" alt="Security Pipeline"></a>
<a href="https://github.com/KuruJPerera/vibe-code-security-scanner"><img src="https://img.shields.io/github/stars/KuruJPerera/vibe-code-security-scanner?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License"></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11-blue?style=flat-square" alt="Python"></a>
<a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square" alt="FastAPI"></a>

</div>

> [!TIP]
> Paste any public GitHub repository URL into the dashboard and get a full security report in seconds — no setup, no configuration, no API keys required.

---

## Overview

AI tools like ChatGPT and Claude can generate a working web app in minutes. The app runs. It looks fine. But it ships with no authentication on API routes, hardcoded API keys, SQL queries built with string formatting, no rate limiting on login endpoints, and tokens stored in localStorage.

These are not code bugs. They are system design failures — the kind that don't show up in a linter or a basic code review. They show up in a breach.

Vibe Code Security Scanner finds them automatically.

**Key Capabilities:**

- **14 security checks** — covering Python, HTML, and JavaScript files
- **AST-based analysis** — parses Python code into a syntax tree for precise, low false-positive detection
- **System design focus** — catches missing authentication, rate limiting, and access control decisions, not just insecure code patterns
- **Web dashboard** — submit any GitHub repo URL and view findings in a severity-ranked table
- **Scan history** — track security improvements across multiple scans of the same repo
- **CI/CD pipeline** — automated security scanning on every push

<div align="center">
  <img src="static/screenshot.png" alt="Vibe Code Security Scanner Dashboard" width="900" style="border-radius: 12px;">
</div>

---

## Use Cases

- **Vibe-coded app auditing** — scan AI-generated codebases before deploying to production
- **Security engineering portfolio** — demonstrate automated security analysis skills
- **Developer security education** — understand what vibe coding leaves behind
- **CI/CD security gate** — integrate into pipelines to block vulnerable code

---

## Quick Start

**Prerequisites:** Python 3.8+, Git

```bash
# Clone the repo
git clone https://github.com/KuruJPerera/vibe-code-security-scanner.git
cd vibe-code-security-scanner

# Install dependencies
pip install -r requirements.txt

# Start the scanner
uvicorn app.main:app --reload
```

Open **http://localhost:8000**, paste a GitHub repo URL, and click **Run Scan**.

> [!NOTE]
> The scanner clones the target repo to a temporary directory, analyses it, then deletes the clone automatically. Nothing is stored except the findings.

---

## What it detects

### Python — Application Security

- **Hardcoded Secrets** — API keys, passwords, tokens assigned as string literals
- **SQL Injection Risk** — queries built with `%` or `.format()` string formatting
- **Missing Authentication** — FastAPI routes with no `Depends()` call
- **Debug Mode Enabled** — `app.run(debug=True)` or `DEBUG = True` in settings
- **Missing Input Validation** — route parameters with no type hints
- **Sensitive Data in Response** — routes returning password, token, or secret fields
- **Stack Trace Exposure** — exception handlers returning `str(e)` or traceback details
- **Environment Variables in Source** — secrets assigned directly instead of loaded from `.env`

### Python — System Design Security

- **Missing Rate Limiting** — routes with no slowapi, flask_limiter, or fastapi_limiter
- **Missing Security Headers** — responses without X-Frame-Options, CSP, HSTS
- **Exposed Admin Endpoints** — `/admin`, `/debug`, `/internal` routes with no auth
- **IDOR Risk** — routes querying by user-controlled ID with no ownership check
- **Missing File Upload Validation** — upload handlers with no extension or content type check
- **Row Level Security Missing** — database queries with no user-based filter
- **Missing HTTPS Enforcement** — no SSL redirect or HTTPS enforcement configured
- **Missing 2FA** — login routes with no OTP, TOTP, or MFA implementation
- **Missing Server Side Validation** — POST/PUT routes accepting data with no validation
- **Outdated Dependencies** — packages pinned below known vulnerable thresholds

### Frontend — HTML and JavaScript

- **API Key Exposed on Frontend** — hardcoded `apiKey`, `sk-`, `AKIA` patterns in client code
- **Insecure Token Storage** — `localStorage.setItem('token', ...)` or `sessionStorage` usage

---

## CI/CD Integration

Add to any GitHub Actions pipeline to scan on every pull request:

```yaml
name: vibe-security-scan
on:
  pull_request:
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run security scan
        run: python -m pytest tests/ -v
```

---

## Project Structure

```
vibe-code-security-scanner/
├── app/
│   ├── main.py                  — FastAPI routes and API
│   ├── database.py              — SQLite scan history
│   ├── analyser.py              — scan coordinator
│   └── checks/
│       ├── python_checks.py     — AST-based Python security checks
│       └── frontend_checks.py   — HTML and JS regex checks
├── static/
│   └── index.html               — web dashboard
├── tests/
│   └── test_analyser.py         — unit tests (6 passing)
└── .github/
    └── workflows/
        └── security-pipeline.yml
```

---

## Built With

- [Python 3.11](https://www.python.org/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [SQLite](https://www.sqlite.org/)
- [ast](https://docs.python.org/3/library/ast.html) — Python abstract syntax tree analysis
- [pytest](https://pytest.org/)

---

## Contributing

Contributions welcome — new security checks, improved detection logic, or additional file type support. Open a [pull request](https://github.com/KuruJPerera/vibe-code-security-scanner/pulls) or [issue](https://github.com/KuruJPerera/vibe-code-security-scanner/issues).

---

## Author

Jude Perera — BSc Computer Science (Information Security), Royal Holloway, University of London (NCSC Academic Centre of Excellence).

[GitHub](https://github.com/KuruJPerera) · [Medium](https://medium.com/@pererajude39) · [LinkedIn](https://linkedin.com/in/Jude-Perera)

---

> [!WARNING]
> Only scan repositories you own or have explicit permission to test. You are responsible for using this tool ethically and legally.
