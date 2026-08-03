import unittest

from analyser import (
    check_api_key_on_frontend,
    check_exposed_admin_endpoints,
    check_file_upload_validation,
    check_https_enforcement,
    check_idor_risk,
    check_insecure_token_storage,
    check_missing_2fa,
    check_outdated_dependencies,
    check_row_level_security,
    check_server_side_validation,
)


class AnalyserTests(unittest.TestCase):
    def test_detects_sensitive_keys_in_local_storage(self):
        source = "localStorage.setItem('authToken', 'abc')"
        findings = check_insecure_token_storage(source, "example.html")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Insecure Token Storage")

    def test_detects_sensitive_keys_in_session_storage(self):
        source = "sessionStorage['jwt'] = 'abc'"
        findings = check_insecure_token_storage(source, "example.html")
        self.assertTrue(findings)

    def test_detects_exposed_admin_endpoint(self):
        source = """
from fastapi import APIRouter

router = APIRouter()

@router.get('/admin/users')
def admin_users():
    return {'ok': True}
"""
        findings = check_exposed_admin_endpoints(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Exposed Admin Endpoint")

    def test_ignores_admin_endpoint_with_auth_dependency(self):
        source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get('/admin/users')
def admin_users(current_user: str = Depends(get_current_user)):
    return {'ok': True}
"""
        findings = check_exposed_admin_endpoints(source, "example.py")
        self.assertEqual(findings, [])

    def test_detects_file_upload_without_validation(self):
        source = """
from fastapi import FastAPI, File, UploadFile

app = FastAPI()

@app.post('/upload')
async def upload(file: UploadFile = File(...)):
    return {'name': file.filename}
"""
        findings = check_file_upload_validation(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Missing File Upload Validation")

    def test_detects_partial_validation(self):
        source = """
from fastapi import FastAPI, File, UploadFile

app = FastAPI()

@app.post('/upload')
async def upload(file: UploadFile = File(...)):
    if file.filename.endswith('.png'):
        return {'ok': True}
"""
        findings = check_file_upload_validation(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_detects_frontend_api_key(self):
        source = """
<script>
const apiKey = 'sk-test-123456';
fetch('/api', { headers: { Authorization: 'Bearer abc123' } });
</script>
"""
        findings = check_api_key_on_frontend(source, "example.js")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "API Key Exposed on Frontend")

    def test_detects_known_vulnerable_dependency_versions(self):
        source = "flask==1.0.2\nrequests==2.27.0\n"
        findings = check_outdated_dependencies(source, "requirements.txt")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Outdated Dependency")
        self.assertEqual(findings[0]["severity"], "high")

    def test_detects_stale_pinned_dependency(self):
        source = "jinja2==2.11.0\n"
        findings = check_outdated_dependencies(source, "requirements.txt")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_detects_idor_risk(self):
        source = """
from fastapi import APIRouter
router = APIRouter()

@router.get('/users/{user_id}')
def get_user(user_id: int):
    return db.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        findings = check_idor_risk(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "IDOR Risk")

    def test_detects_missing_2fa(self):
        source = """
@app.post('/login')
def login(username, password):
    return {'ok': True}
"""
        findings = check_missing_2fa(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Missing 2FA")

    def test_detects_https_enforcement_gap(self):
        source = """
from fastapi import FastAPI
app = FastAPI()

@app.get('/')
def index():
    return {'ok': True}
"""
        findings = check_https_enforcement(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Missing HTTPS Enforcement")

    def test_detects_server_side_validation_gap(self):
        source = """
@app.post('/users')
def create_user(payload: dict):
    return {'ok': True}
"""
        findings = check_server_side_validation(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Missing Server Side Validation")

    def test_detects_row_level_security_gap(self):
        source = """
def get_orders():
    return db.execute('SELECT * FROM orders')
"""
        findings = check_row_level_security(source, "example.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["check_name"], "Row Level Security Missing")


if __name__ == "__main__":
    unittest.main()
