import os
import tempfile
import unittest

from app.checks.frontend_checks import (
    check_api_key_on_frontend,
    check_insecure_token_storage,
)
from app.checks.python_checks import (
    check_debug_mode,
    check_hardcoded_secret,
    check_missing_authentication,
    check_sql_injection,
)


class AnalyserSecurityTests(unittest.TestCase):
    def _write_temp_file(self, content: str, suffix: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False)
        try:
            handle.write(content)
            handle.flush()
            return handle.name
        finally:
            handle.close()

    def _cleanup(self, path: str) -> None:
        if path and os.path.exists(path):
            os.unlink(path)

    def test_hardcoded_secret_is_flagged_as_high(self):
        source = 'PASSWORD = "supersecret123"\n'
        path = self._write_temp_file(source, ".py")
        self.addCleanup(self._cleanup, path)

        findings = check_hardcoded_secret(source, path)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "high")

    def test_sql_injection_is_flagged_as_high(self):
        source = 'cursor.execute("SELECT * FROM users WHERE name = %s" % username)\n'
        path = self._write_temp_file(source, ".py")
        self.addCleanup(self._cleanup, path)

        findings = check_sql_injection(source, path)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "high")

    def test_missing_authentication_is_flagged_as_high(self):
        source = """
from fastapi import APIRouter

router = APIRouter()

@router.get('/secure')
def secure_route():
    return {'ok': True}
"""
        path = self._write_temp_file(source, ".py")
        self.addCleanup(self._cleanup, path)

        findings = check_missing_authentication(source, path)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "high")

    def test_debug_mode_is_flagged_as_medium(self):
        source = 'app.run(debug=True)\n'
        path = self._write_temp_file(source, ".py")
        self.addCleanup(self._cleanup, path)

        findings = check_debug_mode(source, path)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_insecure_token_storage_is_flagged_as_high(self):
        source = "<script>localStorage.setItem('token', value)</script>"
        path = self._write_temp_file(source, ".html")
        self.addCleanup(self._cleanup, path)

        findings = check_insecure_token_storage(source, path)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "high")

    def test_frontend_api_key_is_flagged_as_high(self):
        source = 'const apiKey = "sk-abc123456789";\n'
        path = self._write_temp_file(source, ".js")
        self.addCleanup(self._cleanup, path)

        findings = check_api_key_on_frontend(source, path)

        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
