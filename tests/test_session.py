import json
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from scanner.models import ScanResult
from vibescan import cli, inference, session
from vibescan.login import login_app
from model_answers import plan_answer, review_answer


class SessionTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        install = patch("vibescan.session.registration", return_value=("host", "issued"))
        install.start()
        self.addCleanup(install.stop)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        keys = patch.object(session.JWKS, "get_signing_key_from_jwt",
                            return_value=Mock(key=self.key.public_key()))
        keys.start()
        self.addCleanup(keys.stop)

    def identity(self, nonce="nonce", issuer=session.ISSUER, audience="issued"):
        now = int(time.time())
        return jwt.encode({"iss": issuer, "aud": audience, "sub": "subject", "nonce": nonce,
                           "iat": now, "exp": now + 3600}, self.key, algorithm="RS256")

    def test_loopback_exchange_once(self):
        with patch("vibescan.login.registration", return_value=("host", "issued")):
            app = login_app(self.directory, "127.0.0.1:8765", "ticket")
        with TestClient(app, base_url="http://127.0.0.1:8765", follow_redirects=False) as http:
            self.assertEqual(http.get("/auth/login?key=ticket", headers={"host": "outside"}).status_code, 400)
            response = http.get("/auth/login?key=ticket")
            args = parse_qs(urlsplit(response.headers["location"]).query)
            self.assertEqual(args["client_id"], ["issued"])
            callback = {"state": args["state"][0], "code": "sample"}
            self.assertEqual(http.get("/auth/callback", params={**callback, "state": "bad"}).status_code, 400)
            tokens = {"id_token": self.identity(args["nonce"][0]), "access_token": "access",
                      "refresh_token": "refresh", "scope": session.PLAN, "expires_in": 3600}
            with patch.object(session, "token_request", return_value=tokens) as exchange:
                self.assertEqual(http.get("/auth/callback", params=callback).status_code, 200)
                self.assertEqual(http.get("/auth/callback", params=callback).status_code, 400)
                self.assertEqual(exchange.call_count, 1)
                self.assertEqual(exchange.call_args.kwargs["redirect_uri"], args["redirect_uri"][0])
            self.assertEqual(session.access_token(self.directory), "access")

        with patch("vibescan.login.registration", return_value=("host", "issued")):
            app = login_app(self.directory, "127.0.0.1:8765", "ticket", "http://127.0.0.1:9000/")
        with TestClient(app, base_url="http://127.0.0.1:8765", follow_redirects=False) as http:
            args = parse_qs(urlsplit(http.get("/auth/login?key=ticket").headers["location"]).query)
            response = http.get("/auth/callback", params={"state": args["state"][0], "error": "access_denied"})
            self.assertEqual((response.status_code, response.headers["location"]), (303, "http://127.0.0.1:9000/"))

        # Continue from that saved session, using the real Git and Semgrep binaries.
        repo = self.directory / "sample"
        repo.mkdir()
        source = Path(__file__).resolve().parents[1] / "vulnapp"
        for name in ("app.py", "static_cases.py"):
            shutil.copyfile(source / name, repo / name)
        for args in (["init", "-q"], ["add", "."], ["-c", "user.name=Test", "-c",
                     "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "sample"]):
            subprocess.run(["git", "-C", str(repo), *args], check=True)

        def provider(method, path, token, **kwargs):
            self.assertEqual(token, "access")
            result = Mock()
            result.__enter__ = Mock(return_value=result)
            result.__exit__ = Mock(return_value=None)
            if path == "/models":
                result.json.return_value = {"models": [{"slug": "test-model", "visibility": "list"}]}
                return result
            payload = kwargs["json"]
            self.assertEqual((method, path), ("POST", "/responses"))
            self.assertFalse(payload["store"])
            self.assertTrue(payload["stream"])
            self.assertNotIn("we_meet_fixture_token", json.dumps(payload["input"]))
            self.assertEqual(len(payload["input"]), 1)
            self.assertEqual(payload["input"][0]["role"], "user")
            data = json.loads(payload["input"][0]["content"])
            if isinstance(data, dict):
                answer = plan_answer(data)
            else:
                answer = review_answer(data)
                for item, review in zip(data, answer["reviews"]):
                    if "Markup(title)" in (item["snippet"] or {}).get("code", ""):
                        review["replacement"] = "def render_note(title):\n    from markupsafe import escape\n    return escape(title)\n"
            result.iter_lines.return_value = [
                b"data: " + json.dumps({"type": "response.output_text.delta",
                                        "delta": json.dumps(answer)}).encode(),
                b'data: {"type":"response.completed"}',
            ]
            return result

        with patch.object(inference, "request", side_effect=provider) as remote:
            folder, note, issue = cli.scan(repo, self.directory / "reports", self.directory)
        self.assertIsNone(issue)
        self.assertEqual(remote.call_count, 3)
        result = ScanResult.from_json((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertIn(f"{len(result.findings)}/{len(result.findings)}", note)
        self.assertEqual(result.profile.framework, "Flask")
        self.assertTrue({'CWE-798', 'CWE-89', 'CWE-79', 'CWE-614'} <= {f.cwe for f in result.findings})
        markup = next(f for f in result.findings if f.cwe == "CWE-79")
        self.assertIn("문법 확인", markup.fix_note)
        self.assertIn("+    return escape(title)", markup.fix_diff)
        self.assertEqual(len(result.coverage), 10)
        self.assertEqual(result.report_md, (folder / "report.md").read_text(encoding="utf-8"))

    def test_status_reports_each_login_state_without_network(self):
        def saved(record):
            with session.transaction(self.directory) as db:
                session.save(db, "issued", record)
            return session.status(self.directory)["state"]

        with patch.object(session, "token_request") as remote:
            self.assertEqual(session.status(self.directory)["state"], "login")
            self.assertEqual(saved({"sub": "s", "scope": ""}), "plan")
            ready = {"sub": "s", "scope": session.PLAN, "access_token": "a", "expires_at": time.time() - 10}
            self.assertEqual(saved(ready | {"refresh_token": "r"}), "ready")
            self.assertEqual(saved(ready), "login")
            saved(ready | {"refresh_token": "r"})
            session.logout(self.directory)
            self.assertEqual(session.status(self.directory)["state"], "login")
            remote.assert_not_called()
        with patch("vibescan.session.registration", side_effect=session.SessionError("register first", "register")):
            self.assertEqual(session.status(self.directory)["state"], "register")

    def test_identity_rejections(self):
        for token in (self.identity("other"), self.identity(issuer="bad"), self.identity(audience="bad")):
            with self.assertRaises((session.SessionError, jwt.InvalidTokenError)):
                session.checked_identity(token, "issued", "nonce")

    def test_rotation_and_revoked_grant(self):
        data = {"sub": "subject", "scope": session.PLAN, "access_token": "old",
                "refresh_token": "one", "id_token": None, "expires_at": 0}
        with session.transaction(self.directory) as db:
            session.save(db, "issued", data)
        with patch.object(session, "token_request", return_value={
                "access_token": "next", "refresh_token": "two", "expires_in": 3600}) as refresh:
            self.assertEqual(session.access_token(self.directory), "next")
            self.assertEqual(session.access_token(self.directory), "next")
            self.assertEqual(refresh.call_count, 1)

        with session.transaction(self.directory) as db:
            data = session.read_record(db, "issued")
            self.assertEqual(data["refresh_token"], "two")
            data["expires_at"] = 0
            session.save(db, "issued", data)
        with patch.object(session, "token_request", side_effect=session.InvalidGrant("revoked")) as refresh:
            for _ in range(2):
                with self.assertRaises(session.SessionError):
                    session.access_token(self.directory)
            self.assertEqual(refresh.call_count, 1)

    def test_refresh_identity_failure_keeps_static_scan_available(self):
        record = {"sub": "subject", "scope": session.PLAN, "access_token": "old",
                  "refresh_token": "refresh", "id_token": None, "expires_at": 0}
        with session.transaction(self.directory) as db:
            session.save(db, "issued", record)
        repo = self.directory / "repo"
        repo.mkdir()

        def snapshot(repo, destination, *, folder_source=None):
            self.assertIsNone(folder_source)
            (destination / "app.py").write_text('API_TOKEN = "fixture-secret-Mn4Bv7Cx2Z"\n')
            return "test-commit", "main", ["app.py"]

        for invalid in (self.identity(issuer="wrong"), "malformed-token"):
            with self.subTest(token=invalid[:12]), patch.object(session, "token_request", return_value={
                    "id_token": invalid, "access_token": "rejected", "expires_in": 3600}), \
                 patch.object(cli, "snapshot", side_effect=snapshot), \
                 patch("scanner.static.semgrep", return_value=[]), \
                 patch.object(inference, "request") as remote:
                folder, note, issue = cli.scan(repo, self.directory / "out", self.directory)
                remote.assert_not_called()
                self.assertEqual(issue, "login")
                self.assertIn("계정 검증에 실패", note)
                result = ScanResult.from_json((folder / "scan_result.json").read_text(encoding="utf-8"))
                self.assertEqual(len(result.findings), 1)
                with session.transaction(self.directory) as db:
                    self.assertEqual(session.read_record(db, "issued"), record)
