import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from member_auth import app as service


class AccessFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.docs = root / "docs"
        self.docs.mkdir()
        (self.docs / "index.html").write_text("private app", encoding="utf-8")
        self.db = root / "members.sqlite3"
        self.patches = [
            patch.object(service, "DB_PATH", self.db),
            patch.object(service, "DOCS_DIR", self.docs),
            patch.object(service, "COOKIE_SECURE", False),
            patch.object(service, "send_owner_code"),
        ]
        self.mocks = [item.start() for item in self.patches]
        self.mail = self.mocks[-1]
        self.client = TestClient(service.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def create_member(self):
        result = self.client.post(
            "/api/auth/register",
            json={"email": "member@example.com", "password": "strong-account-password-42"},
        )
        self.assertEqual(result.status_code, 200, result.text)
        code = self.mail.call_args.args[1]
        return code

    def test_app_requires_active_membership_and_code_expires_with_access(self):
        self.assertIn("Member sign in", self.client.get("/app").text)

        code = self.create_member()
        self.assertIn("Owner approval needed", self.client.get("/app").text)
        self.assertTrue(self.client.get("/api/auth/status").json()["authenticated"])
        self.assertFalse(self.client.get("/api/auth/status").json()["active"])

        redeemed = self.client.post("/api/auth/redeem", json={"code": code.replace("-", "")})
        self.assertEqual(redeemed.status_code, 200, redeemed.text)
        self.assertEqual(self.client.get("/app").text, "private app")

        with service.connect() as db:
            db.execute(
                "UPDATE members SET access_expires_at = 1, code_sent_at = 1 WHERE email = ?",
                ("member@example.com",),
            )
        self.assertIn("Member sign in", self.client.get("/app").text)
        status = self.client.get("/api/auth/status").json()
        self.assertTrue(status["authenticated"])
        self.assertFalse(status["active"])

        renewal = self.client.post("/api/auth/request-renewal", json={})
        self.assertEqual(renewal.status_code, 200, renewal.text)
        renewal_code = self.mail.call_args.args[1]
        self.assertNotEqual(code, renewal_code)
        self.assertEqual(self.client.post("/api/auth/redeem", json={"code": renewal_code}).status_code, 200)
        self.assertEqual(self.client.get("/app").text, "private app")

    def test_codes_are_one_time_and_login_password_is_not_access_code(self):
        code = self.create_member()
        self.assertEqual(self.client.post("/api/auth/redeem", json={"code": code}).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/redeem", json={"code": code}).status_code, 400)

        self.client.post("/api/auth/logout", json={})
        login = self.client.post(
            "/api/auth/login",
            json={"email": "member@example.com", "password": "strong-account-password-42"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        self.assertTrue(login.json()["active"])


if __name__ == "__main__":
    unittest.main()