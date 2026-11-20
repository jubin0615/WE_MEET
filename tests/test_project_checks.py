import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scanner.detectors import dependencies, project, routes, secrets
from scanner.ingest import Files, materialize
from scanner.models import ScanResult
from scanner.normalize import normalize
from vibescan.cli import scan


class ProjectChecks(unittest.TestCase):
    def test_package_identity_release_bounds_and_unresolved_pins(self):
        hits, count, partial = dependencies.detect("requirements.txt", "Flask==0.12\nflask>=0.12\n")
        self.assertIn("CVE-2018-1000656", hits[0].evidence)
        self.assertEqual((count, partial), (1, True))
        hits, _, _ = dependencies.detect("requirements.txt", "flask==0.12.3")
        self.assertNotIn("CVE-2018-1000656", str(hits))
        packages = {"node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/minimist": {"version": "0.0.8"},
                    "node_modules/a/node_modules/lodash": {"version": "4.17.21"}}
        hits, count, partial = dependencies.detect("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages}))
        self.assertEqual((count, partial), (3, False))
        rows = [row for h in hits for row in h.evidence.splitlines()]
        self.assertIn("CVE-2021-23337", next(row for row in rows if "lodash 4.17.20 " in row))
        self.assertNotIn("CVE-2021-23337", str([row for row in rows if "lodash 4.17.21 " in row]))
        self.assertEqual(len(normalize(hits)), len(hits))
        self.assertTrue(dependencies.detect("package-lock.json", "{")[2])
        self.assertEqual(dependencies.detect("package.json", '{"dependencies":{"x":"^1.2.3"}}')[1:], (0, True))

    def test_later_migrations_and_conditional_rules(self):
        prefix = "supabase/migrations/"
        files = {prefix + "01.sql": "CREATE TABLE public.notes(id int);\nCREATE TABLE public.todos(id int);",
                 prefix + "02.sql": "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
                    "-- ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n"
                    "CREATE POLICY open_notes ON public.notes FOR SELECT USING (true);",
                 "firestore.rules": "service cloud.firestore {\n// allow write: if true;\n"
                     "allow read: if request.auth != null;\nallow write: if true;\n}",
                 "database.rules.json": '{"rules":{"users":{".read":true,".write":"auth != null"}}}'}
        hits, _, partial = project.detect(files, [], [])
        self.assertFalse(partial)
        self.assertEqual([(h.file, h.line) for h in hits if h.rule_id == "vs-supabase-rls"], [(prefix + "01.sql", 2)])
        self.assertEqual([h.line for h in hits if h.rule_id == "vs-rls-policy-true"], [3])
        self.assertEqual(sorted(h.line for h in hits if h.rule_id == "vs-firebase-public"), [1, 4])
        files[prefix+"03.sql"] = "DROP TABLE public.todos;"
        self.assertFalse(any(h.rule_id == "vs-supabase-rls" for h in project.detect(files, [], [])[0]))
        for update in ("DROP POLICY open_notes ON public.notes;",
                       "ALTER POLICY open_notes ON public.notes USING (auth.uid() = owner_id);"):
            files[prefix+"04.sql"] = update
            self.assertFalse(any(h.rule_id == "vs-rls-policy-true" for h in project.detect(files, [], [])[0]))

    def test_guard_correlates_method_path_and_server_middleware(self):
        client = "if (!session) return;\nconst data = await fetch('/api/profile');"
        server = "app.get('/api/profile', handler);"
        def hits(js, api):
            return project.detect({"frontend/panel.js": js}, routes.detect("api.js", api)[1], [])[0]
        hit, = hits(client, server)
        self.assertEqual((hit.file, hit.trace[0]["file"]), ("api.js", "frontend/panel.js"))
        self.assertFalse(hits(client, server.replace("handler", "requireAuth, handler")))
        self.assertFalse(hits(client, server.replace(".get", ".post")))
        self.assertFalse(hits(client.replace("/api/profile", "/other"), server))
        self.assertFalse(hits("// if (!session) return;\nfetch('/api/profile')", server))

    def test_public_prefixes_and_redaction(self):
        name = "frontend/panel.ts"
        text = "import.meta.env.VITE_STRIPE_SECRET_KEY;\nprocess.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;"
        hits, _, _ = project.detect({name: text}, [], [{"path": ".env", "keys": ["VITE_DATABASE_URL"]}])
        self.assertEqual([(h.file, h.line) for h in hits], [(name, 1), (".env", 1)])
        value = "opaque.fixture.value"
        hidden = set()
        hits = secrets.detect(name, 'const stripeSecretKey = "' + value + '"', hidden)
        self.assertTrue(any(h.rule_id == "vs-client-server-key" for h in hits))
        self.assertIn(value, hidden)
        self.assertFalse(any(h.fix for h in hits))
        self.assertIn(value, secrets.hidden_values(f'const stripeSecretKey = `{value}`', name))
        self.assertIn(value, secrets.hidden_values("VITE_DATABASE_URL=" + value + " # example", ".env.sample"))

    def test_capture_retains_only_header_facts(self):
        with tempfile.TemporaryDirectory() as temp:
            root, files = Path(temp), Files()
            name = "production.headers.http"
            response = b"HTTP/2 200\r\nContent-Type: text/html\r\nSet-Cookie: session=private\r\n"
            materialize(root, Path(name), response, files)
            content = (root / name).read_text()
            self.assertNotIn("private", content)
            hits, _, _ = project.detect({name: content}, [], [])
            self.assertIn("Content-Security-Policy", hits[0].evidence)
            materialize(root, Path("safe.headers.http"), response + b"Content-Security-Policy: default-src 'self'\r\n"
                        b"X-Content-Type-Options: nosniff\r\n", files)
            self.assertFalse(project.detect({name: (root/"safe.headers.http").read_text()}, [], [])[0])
            materialize(root, Path("invalid.headers.http"), b"HTTP/1.1 200 OK\n\n<body>private", files)
            self.assertEqual(files.skipped, ["invalid.headers.http"])

    def test_full_scan_and_retest_through_cli_pipeline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            def git(*args):
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@example.invalid",
                                "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)
            git("init", "-q")
            files = {"requirements.txt": "flask==0.12\n", "frontend/app.tsx":
                     "if (!user) return;\nfetch('/api/me');\nconst key = import.meta.env.VITE_STRIPE_SECRET_KEY;",
                     "api.js": "app.get('/api/me', handler);\napp.post('/refunds', refund);",
                     "supabase/migrations/01.sql": "alter table public.notes disable row level security;",
                     "nginx.conf": "server { autoindex on; }", "Widget.vue": "<p v-text='value'></p>"}
            for name, content in files.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            git("add", ".")
            git("commit", "-qm", "before")
            def result():
                directory, _, _ = scan(repo, root/"out", root/"state", offline=True)
                raw = (directory/"scan_result.json").read_text(encoding="utf-8")
                data = ScanResult.from_json(raw)
                self.assertEqual(data.report_md, (directory/"report.md").read_text(encoding="utf-8"))
                return data
            before = result()
            self.assertEqual(len(before.source_checks), 7)
            self.assertIn("POST /refunds", before.report_md)
            self.assertIn("frontend/app.tsx:1", before.report_md)
            self.assertTrue({"vs-client-only-auth", "vs-client-server-key", "vs-nginx-autoindex", "vs-supabase-rls",
                             "vs-dependency-advisory"} <= {f.rule_id for f in before.findings})
            (repo/"requirements.txt").write_text("flask>=3\n")
            (repo/"api.js").write_text("app.get('/api/me', requireAuth, handler);")
            git("add", ".")
            git("commit", "-qm", "after")
            after = result()
            self.assertEqual(next(f.change for f in after.findings if f.rule_id == "vs-client-only-auth"), "fixed")
            self.assertEqual(next(f.change for f in after.findings if f.rule_id == "vs-dependency-advisory"), "existing")
