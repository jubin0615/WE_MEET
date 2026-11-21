"""Run bundled rules; source parse failures must not discard healthy files."""

import json
import os
import shutil
import subprocess
import sysconfig
from pathlib import Path

from ..models import Confidence, Severity
from ..normalize import RawHit


class Matches(list):
    def __init__(self, matches, partial_files=(), scanned_files=()):
        super().__init__(matches)
        self.partial_files = sorted(set(partial_files))
        self.scanned_files = set(scanned_files)


def semgrep(directory):
    binary = shutil.which("semgrep", path=sysconfig.get_path("scripts")) or shutil.which("semgrep")
    if not binary:
        raise RuntimeError("Semgrep을 찾을 수 없습니다. 설치 환경을 확인하세요.")
    rules = Path(__file__).resolve().parents[2] / "rules" / "vibescan"
    if not rules.is_dir():
        rules = Path(sysconfig.get_path("data")) / "share/vibescan/rules"
    command = [binary, "scan", "--metrics=off", "--disable-version-check", "--no-git-ignore",
               "--no-rewrite-rule-ids", "--optimizations", "none", "--config", str(rules), "--json", "--timeout", "10",
               "--max-target-bytes", "1048576", "."]
    run = subprocess.run(command, cwd=directory, capture_output=True, timeout=180,
                         env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    try:
        data = json.loads(run.stdout)
    except (ValueError, UnicodeError):
        raise RuntimeError("Semgrep 결과를 읽지 못했습니다.") from None
    partial = []
    for error in data.get("errors", []):
        kind = error.get("type")
        if isinstance(kind, list):
            kind = kind[0] if kind else None
        path = error.get("path") or next((s.get("file") for s in error.get("spans", []) if s.get("file")), None)
        if kind not in {"PartialParsing", "Syntax error", "Lexical error", "Timeout", "ParseError"} or not path:
            raise RuntimeError("Semgrep 규칙 또는 실행 오류입니다.")
        partial.append(Path(path).as_posix().removeprefix("./"))
    for skipped in data.get("paths", {}).get("skipped", []):
        if skipped.get("reason") in {"analysis_failed", "exceeded_size_limit"}:
            partial.append(Path(skipped["path"]).as_posix())
    if data.get("skipped_rules") or run.returncode not in (0, 3) or run.returncode and not partial:
        raise RuntimeError(f"Semgrep 실행 실패 (종료 코드 {run.returncode}).")
    scanned = data.get('paths', {}).get('scanned')
    if not isinstance(scanned, list) or not all(isinstance(name, str) for name in scanned):
        raise RuntimeError("Semgrep 검사 파일 목록을 확인할 수 없습니다.")
    return Matches(data["results"], partial, (Path(name).as_posix() for name in scanned))


def convert(hit, allowed):
    name = Path(hit["path"]).as_posix().removeprefix("./")
    line = hit["start"]["line"]
    if name not in allowed or not isinstance(line, int) or line < 1:
        raise ValueError("Semgrep 결과가 검사 범위 밖입니다.")
    meta = hit["extra"]["metadata"]
    detail = meta["vibescan"]
    confidence = Confidence(detail["confidence"])
    if confidence == Confidence.CONFIRMED:
        raise ValueError("정적 규칙은 악용을 확정할 수 없습니다.")
    return RawHit("semgrep", hit["check_id"], name, line, meta["cwe"], detail["category"],
                  detail["title_ko"], detail["remediation_ko"], Severity(detail["severity"]),
                  confidence, owasp_ai=detail.get("owasp_ai", []), fix=detail.get("fix_example", ""),
                  **({"impact": detail["impact_ko"]} if detail.get("impact_ko") else {}))
