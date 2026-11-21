"""커밋별 스캔과 발견 메타데이터를 로컬 SQLite 파일에 보관한다."""

import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import timezone
from pathlib import Path

from .models import Change, ScanResult
from .owasp import classify


# Frozen rule IDs for carrying findings from reports written before VS classification.
LEGACY_CATEGORIES = {rule: code for code, rules in {
    'VS-01': ('literal-token', 'vs-client-server-key', 'vs-secret-file',),
    'VS-02': ('vs-client-only-auth', 'vs-java-admin-policy', 'vs-js-jwt', 'vs-py-jwt', 'vs-route-admin',
              'vs-route-idor',),
    'VS-03': ('vs-firebase-public', 'vs-rls-policy-true', 'vs-supabase-rls',),
    'VS-04': ('vs-dependency-advisory',),
    'VS-05': ('concatenated-select', 'unescaped-markup', 'vs-go-request-html', 'vs-java-sql',
              'vs-java-sql-flow', 'vs-js-code', 'vs-js-path', 'vs-js-react-html', 'vs-js-sql',
              'vs-js-xss', 'vs-php-request-html', 'vs-py-code', 'vs-py-path', 'vs-py-sql',
              'vs-py-ssrf', 'vs-py-upload', 'vs-py-xss', 'vs-py-yaml', 'vs-ruby-request-html',
              'vs-template-raw',),
    'VS-06': ('vs-config-cookie-flags', 'vs-config-cors', 'vs-config-debug', 'vs-js-cookie', 'vs-js-cors',
              'vs-js-error', 'vs-nginx-autoindex', 'vs-nginx-hsts-zero', 'vs-response-headers',
              'weak-signing-key',),
    'VS-07': ('vs-js-payment-amount',),
}.items() for rule in rules}


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY NOT NULL,
    repo_name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    branch TEXT,
    commit_sha TEXT,
    baseline_commit TEXT,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('full', 'diff')),
    scan_trigger TEXT NOT NULL CHECK (scan_trigger IN ('manual', 'git-hook', 'watcher')),
    scanned_at TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    new_count INTEGER NOT NULL,
    fixed_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_repo_time ON scans(repo_path, scanned_at DESC);
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    change TEXT CHECK (change IN ('new', 'existing', 'fixed')),
    introduced_in TEXT,
    cwe TEXT NOT NULL,
    file TEXT,
    line INTEGER,
    PRIMARY KEY (scan_id, finding_id)
);
"""


def save_scan(database: Path, result: ScanResult) -> None:
    data = result.to_dict()
    repo = data["repo"]
    with closing(sqlite3.connect(database)) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(SCHEMA)
        with db:
            # Serialize column discovery with migration if two scans finish together.
            db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in db.execute("PRAGMA table_info(findings)")}
            for column in ("fingerprint", "rule_id", "kisa", "category", "owasp"):
                if column not in columns:
                    db.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")
            db.execute("""
                INSERT INTO scans (scan_id, repo_name, repo_path, branch, commit_sha,
                    baseline_commit, scan_type, scan_trigger, scanned_at, risk_score,
                    new_count, fixed_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (result.scan_id, repo["name"], repo["path"], repo["branch"], result.commit,
                  result.baseline_commit, result.scan_type, result.trigger,
                  result.scanned_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
                  result.risk_score, data["delta"]["new"], data["delta"]["fixed"]))
            db.executemany("""
                INSERT INTO findings (scan_id, finding_id, severity, confidence, status,
                    change, introduced_in, cwe, file, line, fingerprint, rule_id, kisa, category, owasp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ((result.scan_id, f.id, f.severity, f.confidence, f.status,
                   f.change, f.introduced_in, f.cwe, f.location.file, f.location.line,
                   f.fingerprint, f.rule_id, "[]", f.category, f.owasp)
                  for f in result.findings))


def list_scans(database: Path, repo_path: str) -> list[dict]:
    with closing(sqlite3.connect(database)) as db:
        db.executescript(SCHEMA)
        db.row_factory = sqlite3.Row
        rows = db.execute("""
            SELECT * FROM scans WHERE repo_path IN (?, ?)
            ORDER BY scanned_at DESC, scan_id DESC
        """, (repo_path, str(Path(repo_path).expanduser().resolve())))
        return [dict(row) for row in rows]


def evidence_files(finding):
    yield finding.location.file
    for step in finding.trace:
        if isinstance(step, dict):
            yield step.get('file')


def compare(findings, previous, commit, partial_files=(), credential_files=()):
    """Mark findings new/existing against the previous scan; return its vanished findings as fixed.

    Returns None when the previous scan predates fingerprints and cannot be matched.
    """
    before = {}
    for f in previous.findings:
        if f.change == Change.FIXED:
            continue
        if not f.fingerprint:
            return None
        before.setdefault(f.fingerprint, []).append(f)
    for f in findings:
        group = before.get(f.fingerprint)
        if group:
            old = group.pop()
            f.change, f.introduced_in = Change.EXISTING, old.introduced_in
        else:
            f.change, f.introduced_in = Change.NEW, commit
    kept, gone = [], []
    partial = set(partial_files)
    for group in before.values():
        for f in group:
            unresolved = not partial.isdisjoint(evidence_files(f))
            if f.rule_id in ('literal-token', 'weak-signing-key') and f.location.file in credential_files:
                # Other detectors can be partial even though this credential rule fully rescanned the file.
                unresolved = False
            # Old reports can contain excerpts written before the current redaction rules.
            historical = replace(f, change=Change.EXISTING if unresolved else Change.FIXED,
                                 evidence='[이전 검사 위치 · 현재 커밋 근거 코드 없음]', fix_diff='',
                                 fix_note='현재 커밋에서 재검증한 수정 예시 없음')
            if not historical.category and historical.rule_id in LEGACY_CATEGORIES:
                historical.category = LEGACY_CATEGORIES[historical.rule_id]
                historical.owasp = classify(historical.cwe) or ""
            (kept if unresolved else gone).append(historical)
    return kept, gone
