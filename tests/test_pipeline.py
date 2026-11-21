import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scanner.history import list_scans
from scanner.ingest import snapshot
from scanner.models import ScanResult
from vibescan import cli, inference
from model_answers import plan_answer, review_answer


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "sample"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "app.py").write_text('API_TOKEN = "private-value-Pq8Rs2Tu6V"\n')
        (self.repo / ".env.local").write_text("SENSITIVE")
        (self.repo / ".gitignore").write_text("exclude.py\n")
        (self.repo / "exclude.py").write_text("SENSITIVE")
        (self.repo / "binary.py").write_bytes(b"a\0b")
        (self.repo / ".vibescanignore").write_text("ignore.py\n.env.local\n")
        (self.repo / "ignore.py").write_text("SENSITIVE")
        (self.repo / "nested").mkdir()
        (self.repo / "nested" / "hide.py").write_text("SENSITIVE")
        (self.repo / "nested" / ".gitignore").write_text("!hide.py")
        with (self.repo / ".gitignore").open("a") as ignored:
            ignored.write("nested/\n")
        self.git("add", "-f", ".")
        oid = subprocess.check_output(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                                      input=b"app.py").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", f"120000,{oid},link.py")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "sample")
        (self.repo / "app.py").write_text("dirty = True")
        (self.repo / "untracked.py").write_text("untracked = True")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args])

    def test_snapshot_reads_committed_sources(self):
        dest = self.base / "snapshot"
        dest.mkdir()
        commit, _, files = snapshot(self.repo, dest)
        self.assertEqual(commit, self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(files, ["app.py"])
        self.assertIn("API_TOKEN", (dest / "app.py").read_text())

    def test_authenticated_pipeline_and_quota_fallback(self):
        out, state = self.base / "out", self.base / "state"
        plan = plan_answer()
        plan["checks"].reverse()
        review = review_answer([{"id": "F-001", "severity": "High"}])
        # This fixture contains only a literal credential, so there are no surface points.
        for response in ([plan, review], [inference.SessionError("사용량 한도", "limit")]):
            with patch("scanner.static.semgrep", return_value=[]), \
                 patch.object(cli, "access_token", return_value="private-test-token"), \
                 patch.object(inference, "model_for", return_value="model"), \
                 patch.object(inference, "ask", side_effect=response) as ask:
                folder, note, issue = cli.scan(self.repo, out, state)
            self.assertEqual(issue, None if len(response) == 2 else "limit")
            result = ScanResult.from_json((folder / "scan_result.json").read_text(encoding="utf-8"))
            self.assertEqual(len(result.findings), 1)
            self.assertNotIn("private-value", str(ask.call_args_list))
            self.assertNotIn("private-value", result.to_json())
            self.assertEqual(result.report_md, (folder / "report.md").read_text(encoding="utf-8"))
            if len(response) == 2:
                self.assertEqual([c["id"] for c in result.coverage], [c["id"] for c in plan["checks"]])
                self.assertIn("1/1", note)
            else:
                self.assertIn("사용량", note)
        self.assertEqual(len(list_scans(state / "scan-history.sqlite3", str(self.repo))), 2)

    def test_unreadable_or_excluded_source_keeps_previous_finding(self):
        out, state = self.base / "out", self.base / "state"
        with patch("scanner.static.semgrep", return_value=[]):
            cli.scan(self.repo, out, state, offline=True)
            for payload in (b"\xff", b"x" * (1024 * 1024 + 1), b"ignored"):
                with self.subTest(size=len(payload)):
                    (self.repo / "app.py").write_bytes(payload)
                    if payload == b"ignored":
                        (self.repo / ".vibescanignore").write_text("app.py\nignore.py\n.env.local\n")
                    self.git("add", "-u")
                    self.git("-c", "user.name=T", "-c", "user.email=t@e.invalid", "-c",
                             "commit.gpgsign=false", "commit", "-qm", "partial")
                    folder, _, _ = cli.scan(self.repo, out, state, offline=True)
                    result = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
                    self.assertIn("app.py", result["partial_files"])
                    self.assertEqual(result["delta"]["fixed"], 0)
                    row = next(r for r in result["coverage"] if r["code"] == "VS-01")
                    self.assertEqual(row["findings"], [result["findings"][0]["id"]])

    def test_comparison_follows_branch_and_commit_ancestry(self):
        out, state = self.base / "out", self.base / "state"
        def scan():
            folder, _, _ = cli.scan(self.repo, out, state, offline=True)
            return json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))

        first_branch = self.git("branch", "--show-current").decode().strip()
        with patch("scanner.static.semgrep", return_value=[]):
            self.git("switch", "-qc", "feature")
            first = scan()
            self.git("switch", "-q", first_branch)
            self.assertIsNone(scan()["baseline_commit"])
            self.git("switch", "-q", "feature")
            self.assertEqual(scan()["baseline_commit"], first["commit"])
            self.git("restore", "--", "app.py")
            self.git("switch", "--orphan", "replacement")
            (self.repo / "app.py").write_text("print(1)")
            self.git("add", "app.py")
            self.git("-c", "user.name=T", "-c", "user.email=t@example.invalid",
                     "-c", "commit.gpgsign=false", "commit", "-qm", "unrelated history")
            self.git("branch", "-M", "feature")
            rewritten = scan()
            self.assertIsNone(rewritten["baseline_commit"])
            self.assertEqual(rewritten["delta"]["fixed"], 0)

    def test_stream_requires_completion(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        delta = b'data: {"type":"response.output_text.delta","delta":"{}"}'
        with patch.object(inference, "request", return_value=response) as send:
            response.iter_lines.return_value = [delta]
            with self.assertRaises(inference.SessionError):
                inference.ask("t", "m", "instructions", {})
            response.iter_lines.return_value = [delta, b'data: {"type":"response.completed"}']
            self.assertEqual(inference.ask("t", "m", "instructions", {}), {})
            self.assertFalse(send.call_args.kwargs["json"]["store"])
            self.assertTrue(send.call_args.kwargs["json"]["stream"])
            self.assertEqual(send.call_args.kwargs["json"]["input"],
                             [{"role": "user", "content": "{}"}])

    def test_requests_that_disable_model_use(self):
        for status in (401, 403, 429):
            response = Mock(status_code=status)
            with self.subTest(status=status), patch("requests.request", return_value=response) as call:
                with self.assertRaises(inference.SessionError):
                    inference.request("GET", "/models", "private-test-token")
                self.assertEqual(call.call_count, 1)
                response.close.assert_called_once()

    def test_bad_request_identifies_the_failed_stage(self):
        for path, stage in (("/models", "모델 목록 조회"), ("/responses", "모델 응답 생성")):
            response = Mock(status_code=400)
            with self.subTest(path=path), patch("requests.request", return_value=response):
                with self.assertRaisesRegex(inference.SessionError, stage + " 실패 · HTTP 400"):
                    inference.request("POST", path, "private-test-token")
                response.close.assert_called_once()

    def test_scan_failure_leaves_no_success_artifacts(self):
        with patch("scanner.static.semgrep", side_effect=RuntimeError("analysis failed")):
            with self.assertRaises(RuntimeError):
                cli.scan(self.repo, self.base / "out", self.base / "state", offline=True)
        self.assertFalse((self.base / "out").exists())
        self.assertFalse((self.base / "state/scan-history.sqlite3").exists())

    def test_dismissal_updates_risk_report_and_saved_history(self):
        reply = review_answer([{"id": "F-001", "severity": "High"}])
        reply["reviews"][0].update(decision="dismiss", severity="Info", reason="테스트 전용 고정 표본으로 확인")
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", side_effect=[plan_answer(), reply]):
            folder, _, _ = cli.scan(self.repo, self.base / "out", self.base / "state")
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["risk_score"], 0)
        self.assertEqual(data["summary"]["High"], 0)
        self.assertEqual(data["dismissed_count"], 1)
        self.assertIn("오탐 후보", data["report_md"])
        self.assertIn("테스트 전용", data["findings"][0]["triage_reason"])
        self.assertEqual(list_scans(self.base / "state/scan-history.sqlite3", str(self.repo))[0]["risk_score"], 0)

    def test_quota_stops_remaining_batches_and_preserves_all_findings(self):
        from dataclasses import replace
        from scanner.models import Finding, Location, Severity, Confidence
        base = Finding("F-001", "비밀값", "CWE-798", "A07", Severity.HIGH, Confidence.POTENTIAL,
                       Location("app.py", 1), "[가림]", ["static:secret"], "영향", "수정", "diff")
        findings = [replace(base, id=f"F-{i:03}") for i in range(1, 33)]
        first = review_answer([{"id": f.id, "severity": "High"} for f in findings[:5]])
        with patch.object(cli, "inspect", return_value=findings), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", side_effect=[plan_answer(), first, inference.SessionError("사용량 한도", "limit")]) as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertEqual(ask.call_count, 3)
        self.assertEqual(issue, "limit")
        self.assertIn("5/32", note)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 32)
        self.assertEqual(sum(bool(f["triage_reason"]) for f in data["findings"]), 5)

    def test_no_findings_skips_triage_and_unsupported_rules_are_explicit(self):
        self.git("rm", "-rf", ".")
        (self.repo / "untracked.py").unlink()
        (self.repo / "main.js").write_text("const value = 1;")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c",
                 "commit.gpgsign=false", "commit", "-qm", "JS only")
        with patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", return_value=plan_answer()) as ask:
            folder, _, _ = cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertEqual(ask.call_count, 1)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["findings"], [])
        self.assertEqual({c["id"] for c in data["coverage"] if c["execution"] == "completed"}, {"VS-01"})
        self.assertEqual(next(c for c in data['coverage'] if c['code']=='VS-04')['status'], '해당 없음(추정)')

    def test_invalid_plan_still_runs_local_checks_and_review(self):
        reply = review_answer([{"id": "F-001", "severity": "High"}])
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", side_effect=[{"checks": []}, reply]):
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertIn("고정 점검 계획", note)
        self.assertEqual(issue, "error")
        self.assertIn("1/1", note)
        self.assertEqual(len(json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))["coverage"]), 10)

    def test_background_review_sends_only_new_high_findings_and_reports_progress(self):
        out, state = self.base / "out", self.base / "state"
        with patch("scanner.static.semgrep", return_value=[]):
            cli.scan(self.repo, out, state, offline=True)
            (self.repo / "app.py").write_text('API_TOKEN = "private-value-Pq8Rs2Tu6V"\nSECOND_KEY = "private-value-Xq7Lm2Pz9Wr4"\n')
            self.git("add", "app.py")
            self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                     "commit", "-qm", "second secret")
            steps = []
            with patch.object(cli, "access_token", return_value="t"), \
                    patch.object(inference, "model_for", return_value="m"), \
                    patch.object(cli.analysis, "plan") as plan, \
                    patch.object(cli.analysis, "review", side_effect=lambda ctx, batch, *a: len(batch)) as review:
                folder, note, _ = cli.scan(self.repo, out, state, new_high_only=True,
                                           progress=lambda stage, text: steps.append((stage, text)))
        plan.assert_not_called()  # background scans spare the quota: no planning call
        sent = [f for call in review.call_args_list for f in call.args[1]]
        self.assertTrue(sent)
        self.assertTrue(all(f.change == "new" and f.severity in ("Critical", "High") for f in sent))
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(sent), sum(f["change"] == "new" for f in data["findings"]))
        self.assertIn("새 High 이상만", note)
        self.assertEqual(sorted({stage for stage, _ in steps}), [0, 1, 2, 3, 4])
        self.assertEqual([stage for stage, _ in steps], sorted(stage for stage, _ in steps))
        self.assertNotIn("private-value", json.dumps(steps, ensure_ascii=False))

    def test_paths_differing_only_in_case_do_not_fail_the_scan(self):
        repo = self.base / "case"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        blob = subprocess.check_output(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                                       input=b'API_TOKEN = "private-value-Pq8Rs2Tu6V"\n').decode().strip()
        for name in ("Config.py", "config.py"):  # made on Linux; one file on Windows and macOS
            subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"100644,{blob},{name}"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "case"], check=True)
        with patch("scanner.static.semgrep", return_value=[]):
            folder, _, _ = cli.scan(repo, self.base / "out", self.base / "state", offline=True)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        scanned = {f["location"]["file"] for f in data["findings"]}
        # Every path is either scanned or reported as not checked, never silently dropped.
        self.assertEqual(scanned | set(data["partial_files"]), {"Config.py", "config.py"})
