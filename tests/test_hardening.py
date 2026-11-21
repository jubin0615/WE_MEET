import json
import sqlite3
import subprocess
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scanner.context import Context, sanitize
from scanner.detectors import config, routes, secrets
from scanner.detectors.semgrep import Matches, convert, semgrep
from scanner.history import SCHEMA, save_scan
from scanner.ingest import snapshot
from scanner.coverage import compute
from scanner.models import Confidence, ScanResult, Status
from scanner.normalize import RawHit, code_identity, normalize
from scanner.static import inspect
from vibescan.cli import scan


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(TemporaryDirectory())
        self.root = Path(self.temp)

    def test_identity_line_shift_comments_and_distinct_literals(self):
        first = 'def query():\n    db.execute("SELECT a")\n'
        moved = '\n# unrelated\ndef query():\n    db.execute( "SELECT a" ) # comment\n'
        a = code_identity(first, 2, True)
        self.assertEqual(a, code_identity(moved, 4, True))
        self.assertNotEqual(a, code_identity(first.replace('SELECT a', 'SELECT b'), 2, True))
        self.assertNotEqual(a, code_identity(first.replace('query', 'other'), 2, True))
        hit = RawHit('semgrep', 'test-rule', 'app.py', 2, 'CWE-89', 'VS-05', 'SQL', 'bind', identity=a)
        duplicate = replace(hit, detector='config', confidence=Confidence.LIKELY)
        merged = normalize([hit, duplicate])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].how_found), 2)
        self.assertEqual(merged[0].confidence, Confidence.LIKELY)
        self.assertEqual(merged[0].fingerprint, normalize([replace(hit, line=40)])[0].fingerprint)

    def test_new_metadata_rule_needs_no_code_mapping(self):
        match = {'path': 'app.py', 'start': {'line': 1}, 'check_id': 'new-independent-rule',
                 'extra': {'metadata': {'cwe': 'CWE-999',
                           'vibescan': {'category': 'VS-05', 'title_ko': 'New rule', 'remediation_ko': 'Fix',
                                        'severity': 'High', 'confidence': 'Potential'}}}}
        hit = convert(match, {'app.py'})
        self.assertEqual(normalize([hit])[0].cwe, 'CWE-999')
        with self.assertRaises(ValueError):
            convert({**match, 'path': '../private.py'}, {'app.py'})
        match['extra']['metadata']['vibescan']['confidence'] = 'Confirmed'
        with self.assertRaises(ValueError):
            convert(match, {'app.py'})

    def test_semgrep_partial_source_but_fatal_rule_errors(self):
        data = {'results': [], 'paths': {'scanned': []}, 'errors': [{'type': ['PartialParsing', []], 'path': 'broken.js'}]}
        with patch('scanner.detectors.semgrep.subprocess.run', return_value=Mock(returncode=0, stdout=json.dumps(data))):
            self.assertEqual(semgrep(self.root).partial_files, ['broken.js'])
        for error in ({'type': 'InvalidRuleSchema'}, {'type': 'Timeout', 'path': None}):
            data['errors'] = [error]
            with patch('scanner.detectors.semgrep.subprocess.run', return_value=Mock(returncode=2, stdout=json.dumps(data))):
                with self.assertRaises(RuntimeError):
                    semgrep(self.root)

    def test_real_broken_source_retains_other_file_findings(self):
        (self.root / 'broken.js').write_text('const = ; eval(req.query.q);\n', encoding='utf-8')
        (self.root / 'good.py').write_text('API_TOKEN="private-regression-K9j8H7g6F5"\n', encoding='utf-8')
        found = inspect(self.root, ['broken.js', 'good.py'])
        self.assertIn('broken.js', found.partial_files)
        self.assertTrue(any(f.location.file == 'good.py' for f in found))
        self.assertNotIn('private-regression-K9j8H7g6F5', repr(found))

    def test_typescript_rules_and_template_scope(self):
        (self.root / 'api.ts').write_text('const q: string = req.query.q;\ndb.query(`SELECT * FROM notes WHERE id=${q}`);\n', encoding='utf-8')
        (self.root / 'docs.txt').write_text('{{ value | safe }}', encoding='utf-8')
        found = inspect(self.root, ['api.ts', 'docs.txt'])
        self.assertTrue(any(f.location.file == 'api.ts' and f.cwe == 'CWE-89' for f in found))
        self.assertFalse(any(f.location.file == 'docs.txt' for f in found))

    def test_secret_recognition_redaction_and_placeholders(self):
        values = ['AKIAABCDEFGHIJKLMNOP', 'AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ012345678',
                  'postgresql://user:private-password@localhost/db', 'xoxb-' + '0123456789'*3,
                  'sk-ant-' + 'A'*25, '-----BEGIN PRIVATE KEY-----',
                  'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.synthetic_signature']
        source = '\n'.join(f'x{i} = {value!r}' for i, value in enumerate(values))
        self.assertEqual(len(secrets.detect('source.py', source)), len(values))
        clean, hidden = sanitize(source)
        for value in values:
            self.assertNotIn(value, clean)
            self.assertIn(value, hidden)
        self.assertEqual(secrets.detect('a.py', 'API_KEY="your-api-key"'), [])
        weak = secrets.detect('a.py', 'SECRET_KEY="dev"')
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0].category, 'VS-06')
        self.assertTrue(any(h.severity == 'Critical' for h in secrets.detect('a.js', source)))
        (self.root / 'a.js').write_text('const key = "AKIAABCDEFGHIJKLMNOP";', encoding='utf-8')
        (self.root / 'b.py').write_text('value = "AKIAABCDEFGHIJKLMNOP"', encoding='utf-8')
        context = Context(self.root, ['a.js', 'b.py'])
        self.assertNotIn('AKIAABCDEFGHIJKLMNOP', context.sources['b.py'])
        self.assertNotIn('AKIAABCDEFGHIJKLMNOP', context.clean('echo AKIAABCDEFGHIJKLMNOP'))

    def test_committed_sensitive_file_never_materialized_or_sent(self):
        repo = self.root / 'repo'; repo.mkdir()
        (repo / '.env').write_text('OPENAI_KEY=private-never-export-credential\n')
        (repo / '.gitignore').write_text('.env\n')
        for args in (['init', '-q'], ['add', '-f', '.'], ['-c', 'user.name=Test', '-c',
                     'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
        dest = self.root / 'snapshot'; dest.mkdir()
        _, _, files = snapshot(repo, dest)
        self.assertEqual(list(dest.iterdir()), [])
        self.assertEqual(files.sensitive_files, [{'path': '.env', 'kind': 'dotenv', 'keys': ['OPENAI_KEY']}])
        with patch('vibescan.cli.access_token') as token:
            folder, _, _ = scan(repo, self.root / 'out', self.root / 'state', offline=True)
        token.assert_not_called()
        raw = (folder / 'scan_result.json').read_text(encoding='utf-8')
        self.assertNotIn('private-never-export', raw)
        result = ScanResult.from_json(raw)
        self.assertEqual(result.findings[0].category, 'VS-01')
        self.assertEqual(result.findings[0].owasp, 'A01:2025')
        self.assertEqual(len(result.coverage), 10)
        self.assertEqual(len(result.owasp_coverage), 10)
        self.assertIn('OWASP Top 10:2025 분류 기준 점검 범위', result.report_md)
        self.assertIn('VS-01 · CWE-540 · A01:2025', result.report_md)
        for hidden in ('엔드포인트 지도', '설정 요약'):
            self.assertNotIn(hidden, result.report_md)
        legacy = json.loads(raw)
        legacy['kisa_checklist'] = []
        legacy.pop('owasp_coverage')
        legacy['findings'][0].update(kisa=['CI-05'], kisa_reason='old')
        legacy['findings'][0].pop('category')
        restored = ScanResult.from_json(json.dumps(legacy))
        self.assertNotIn('kisa', restored.to_json())
        from scanner.history import compare
        recovered, fixed = compare([], restored, 'next', ['.env'])
        self.assertEqual((recovered[0].category, recovered[0].owasp, fixed), ('VS-01', 'A01:2025', []))
        database = self.root / 'state/scan-history.sqlite3'
        self.assertNotIn(b'private-never-export', database.read_bytes())
        # Existing DB schema migrates without dropping historical scans or finding rows.
        old = self.root / 'old.db'
        with closing(sqlite3.connect(old)) as db:
            db.executescript(SCHEMA)
            db.execute("ALTER TABLE findings ADD COLUMN kisa TEXT")
            db.execute("INSERT INTO findings (scan_id,finding_id,severity,confidence,status,cwe,kisa) "
                       "VALUES ('older','F-001','High','Likely','open','CWE-540','[]')")
            db.commit()
        save_scan(old, result)
        with closing(sqlite3.connect(old)) as db:
            row = db.execute('SELECT fingerprint, rule_id, kisa, category, owasp FROM findings WHERE scan_id=?', (result.scan_id,)).fetchone()
            self.assertEqual(db.execute("SELECT count(*) FROM findings WHERE scan_id='older'").fetchone()[0], 1)
        self.assertEqual(row[0], result.findings[0].fingerprint)
        self.assertEqual(row[2:], ('[]', 'VS-01', 'A01:2025'))

    def test_routes_and_config_are_candidates_not_confirmed(self):
        content = '''from fastapi import APIRouter, Depends
router = APIRouter(prefix="/api")
@router.get("/admin/users")
def users():
    return []
@router.get("/admin/safe")
def safe(user=Depends(get_current_user)):
    return []
'''
        hits, rows = routes.detect('routes.py', content)
        self.assertEqual(len(hits), 2)
        self.assertEqual(rows[0]['path'], '/api/admin/users')
        self.assertEqual(hits[0].confidence, Confidence.POTENTIAL)
        js = '''// app.get('/admin/fake', (req,res) => {});
app.get('/admin/users', authMiddleware, (req,res) => { res.json([]); });
app.get('/orders/:id', (req,res) => { res.json(db.findById(req.params.id)); });'''
        hits, rows = routes.detect('api.ts', js)
        self.assertEqual(len(rows), 2)
        self.assertEqual([h.cwe for h in hits], ['CWE-862', 'CWE-639'])
        hits, _ = config.detect('app.py', 'app.run(debug=False)\nresponse.set_cookie("x", v, **cookie_options)')
        self.assertEqual(hits, [])

    def test_indirect_route_signals_do_not_clear_candidates(self):
        code = '''@app.before_request
def log_request():
    print("request")
@app.get("/admin/authenticate")
def admin():
    return []
@app.get("/users/<user_id>")
def detail(user_id):
    return db.query(user_id)
'''
        hits, _ = routes.detect('app.py', code)
        self.assertEqual({h.cwe for h in hits}, {'CWE-639', 'CWE-862'})
        js = """app.get('/admin/a', handler);
app.get('/admin/b', requireAdmin, handler);"""
        hits, rows = routes.detect('app.js', js)
        self.assertEqual(len(rows), 2)
        self.assertEqual([h.line for h in hits], [1])

    def test_admin_dependency_and_registration_order(self):
        code = '''@admin_required
@app.get("/admin/outer")
def outer(): pass
@app.get("/admin/inner")
@admin_required
def inner(): pass
@router.get("/admin/dependency", dependencies=[Depends(require_admin)])
def dependency(): pass
@router.get("/admin/identity")
def identity(user=Depends(get_current_user)): pass
'''
        hits, rows = routes.detect('app.py', code)
        self.assertEqual([h.line for h in hits], [3, 10])
        self.assertEqual([r['admin_guard'] for r in rows], [False, True, True, False])

    def test_silent_engine_skip_and_open_candidate_preserve_partial_coverage(self):
        for name in ('checked.py', 'skipped.py', 'Skipped.java', 'notes.txt'):
            (self.root / name).write_text('pass')
        with patch('scanner.static.semgrep', return_value=Matches([], scanned_files=['checked.py'])):
            found = inspect(self.root, ['checked.py', 'skipped.py', 'Skipped.java', 'notes.txt'])
        self.assertEqual(found.partial_files, ['Skipped.java', 'skipped.py'])
        finding = normalize([RawHit('semgrep','sql','checked.py',1,'CWE-89','VS-05','SQL','fix')])[0]
        rows, _ = compute([finding], {'python': 2}, found.partial_files)
        sql = next(row for row in rows if row['code'] == 'VS-05')
        self.assertEqual(sql['status'], '취약 후보')
        self.assertEqual(sql['execution'], 'partial')

    def test_owner_reference_must_constrain_the_returned_query(self):
        code = '''@app.get("/items/<id>")
def item(id):
    log(owner_id=current_user.id)
    return db.query(id)
@app.get("/notes/<id>")
def note(id):
    return db.query(id).filter(Note.owner_id == current_user.id).first()
'''
        hits, _ = routes.detect('app.py', code)
        self.assertEqual([(h.line, h.cwe) for h in hits], [(2, 'CWE-639')])
        js = """app.get('/items/:id', (req,res) => { log({ownerId:req.user.id}); res.json(db.findById(req.params.id)); });
app.get('/notes/:id', (req,res) => res.json(db.findUnique({where:{id:req.params.id, ownerId:req.user.id}})));"""
        hits, _ = routes.detect('app.js', js)
        self.assertEqual([(h.line, h.cwe) for h in hits], [(1, 'CWE-639')])

    def test_dynamic_cookie_policy_and_similar_names(self):
        code = '''BACKUP_SESSION_COOKIE_SECURE = False
response.set_cookie("session", value, secure=True, httponly=True, samesite=policy)
app.config["SESSION_COOKIE_SECURE"] = False
response.set_cookie("session", value, secure=False, **policy)
CORS(app, resources=policy)
CORS(app, **policy)
app.config["DEBUG"] = True
'''
        hits, _ = config.detect('app.py', code)
        self.assertCountEqual([h.line for h in hits], [3, 4, 7])

    def test_checklist_never_claims_unsupported_or_dismissed_safe(self):
        rows, web = compute([], {'java': 2}, [])
        self.assertEqual(len(rows), 10)
        self.assertEqual(next(r for r in rows if r['code'] == 'VS-05')['status'], '부분 점검')
        self.assertEqual(next(r for r in web if r['code'] == 'A09:2025')['status'], '수동 확인 필요')
        finding = normalize([RawHit('secrets','key','a.py',1,'CWE-798','VS-01','key','rotate')])[0]
        finding.status = Status.DISMISSED
        self.assertEqual(next(r for r in compute([finding], {'python': 1}, [])[0] if r['code']=='VS-01')['findings'], [])

    def test_identifier_slugs_and_sample_files_do_not_inflate_secret_findings(self):
        found = lambda name, text: [(h.line, h.severity.value) for h in secrets.detect(name, text)]
        # Seen in a real PHP/JSON site: identifiers named "key" are not credentials.
        self.assertEqual(found("data/content.json", '{"key": "family-lounge-guide", "feature_key": "esg-strategy-2026"}'), [])
        self.assertEqual(found("app.py", 'FEATURE_KEY = "news-publication-01"\n'), [])
        # A slug still counts when the line names a real credential.
        self.assertEqual(found("app.py", 'admin_password = "admin-pass-1234"\n'), [(1, "High")])
        # Throwaway test values stay visible as Info; a vendor-format key is a leak even in tests.
        self.assertEqual(found("tests/login_test.py", 'PASSWORD = "LabDemo1234!"\n'), [(1, "Info")])
        self.assertEqual(found("tests/login_test.py", 'STRIPE = "sk_live_' + "a1B2c3D4e5F6g7H8" + '"\n'), [(1, "High")])
        self.assertEqual(found("tests/login_test.py", 'API_KEY = "sk_live_' + "a1B2c3D4e5F6g7H8" + '"\n'), [(1, "High")])

    def test_unsupported_main_language_is_reported_as_incomplete(self):
        repo = self.root / 'php-site'
        repo.mkdir()
        for i in range(3):
            (repo / f'page{i}.php').write_text('<?php echo $_GET["q"]; ?>\n')
        (repo / 'tool.py').write_text('print(1)\n')
        subprocess.run(['git', '-C', str(repo), 'init', '-q'], check=True)
        subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=T', '-c', 'user.email=t@e.invalid', '-c',
                        'commit.gpgsign=false', 'commit', '-qm', 'php'], check=True)
        with patch('scanner.static.semgrep', return_value=[]):
            folder, note, _ = scan(repo, self.root / 'out', self.root / 'state', offline=True)
        self.assertIn('주 언어(PHP)', note)
        result = ScanResult.from_json((folder / 'scan_result.json').read_text(encoding='utf-8'))
        self.assertIn('PHP 3개', result.profile.limitations[0])
        self.assertIn('결과가 불완전', result.report_md)
