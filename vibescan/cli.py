"""VibeScan manual full-scan and local-login entry points."""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

from scanner.history import compare, evidence_files, list_scans, save_scan
from scanner.context import Context
from scanner.ingest import git, snapshot, languages
from scanner.kisa import checklist, legacy_coverage
from scanner.models import Change, ScanResult, Severity, Status, Target, Trigger
from scanner.static import inspect, profile
from . import analysis, inference
from .register import data_dir
from .session import SessionError, access_token

MANUAL = ["인증·인가 정책 확인", "응답 헤더·쿠키 확인"]


def render(result):
    fixed = [f for f in result.findings if f.change == Change.FIXED]
    opened = [f for f in result.findings if f.status == Status.OPEN and f.change != Change.FIXED]
    dismissed = [f for f in result.findings if f.status == Status.DISMISSED and f.change != Change.FIXED]
    rows = [f"# 보안 진단 보고서 — {result.app_name}", "",
            f"- 커밋: `{result.commit}`", f"- 진단 일시: {result.scanned_at.isoformat()}",
            f"- 위험 점수: {result.risk_score}/100 · 검토 대상 {len(opened)}건 · 오탐 후보 {len(dismissed)}건",
            "- 진단 범위: 수집한 소스의 정적 패턴 및 시크릿 검사",
            f"- 앱 프로파일: {result.profile.framework or '프레임워크 미확인'} · "
            f"라우트 데코레이터 {result.profile.routes}개 · {result.profile.auth or '인증 방식 미확인'}",
            f"- 모델 분석: {result.analysis_note}",
            f"- 직전 스캔 대비: 새로 생김 {sum(f.change == Change.NEW for f in result.findings)}건 · 해결 {len(fixed)}건 "
            f"(기준 커밋 `{result.baseline_commit}`)" if result.baseline_commit else "- 직전 스캔 대비: 비교할 이전 결과 없음", "",
            "## 정찰 결과", result.profile.analysis_ko or "로컬 구조 분석만 수행했습니다."]
    rows.extend(f"- {p['file']}:{p['line']} · {p['kind']}: {p['note']}" for p in result.profile.surfaces)
    rows.extend("- " + s for s in result.profile.limitations)
    rows.extend(["", "## 점검 계획과 범위"])
    for check in result.coverage:
        mode = {"completed": "정적 검사 완료", "unsupported": "지원 Python 소스 없음 · 미검사",
                "manual": "수동 확인 필요 · 미검사", "partial": "부분 점검 · 수동 확인 포함"}[check["execution"]]
        rows.append(f"- {check['name']} [{mode}]: {check['reason']}")
    for check in result.source_checks:
        mode = "부분 점검" if check["execution"] == "partial" else "수동 확인"
        rows.append(f"- {check['name']} [{mode}] · {check['reason']}")
    rows.extend(["", "## 발견 및 수정 방법"])
    for f in sorted(opened, key=lambda item: list(Severity).index(item.severity)):
        rows.extend(["", f"### {f.id} · {f.severity} · {f.title}", "",
                     f"- 위치: `{f.location.file}:{f.location.line}`",
                     f"- 탐지 방식: {', '.join(f.how_found)}",
                     f"- 분류: {f.cwe} · {f.owasp} · {f.confidence}",
                     f"- 판정 근거: {f.triage_reason or '로컬 규칙 탐지 · 모델 검토 없음'}",
                     f"- 최초 규칙 심각도: {f.original_severity or f.severity}",
                     f"- 영향: {f.impact_ko}", f"- 수정 방법: {f.remediation_ko}",
                     "", "근거 코드:", "", "```", f.evidence, "```"])
        if f.fix_diff:
            rows.extend(["", f.fix_note, "", "```diff", f.fix_diff, "```"])
        if f.rule_id == 'vs-java-sql-flow' and f.trace:
            rows.append("호출 경로: " + " → ".join(f"{p['file']}:{p['line']} ({p['method']})" for p in f.trace))
        if f.rule_id == 'vs-java-admin-policy' and f.trace:
            rows.append(f"필터 체인 설정: {f.trace[0]['file']}:{f.trace[0]['line']}")
        if f.rule_id == 'vs-client-only-auth':
            rows.extend(f"- 화면 호출 근거 · {p['file']}:{p['line']}" for p in f.trace)
    if not opened:
        rows.append("적용한 규칙에서 발견된 항목이 없습니다.")
        if dismissed:
            rows[-1] = "모델이 모든 발견을 오탐 후보로 분류했습니다. 아래 근거를 직접 확인하세요."
    if dismissed:
        rows.extend(["", "## 오탐 후보 — 원래 발견을 보존하며 개발자 확인 필요"])
        for f in dismissed:
            rows.extend([f"- {f.id} · {f.title} · {f.location.file}:{f.location.line}",
                         f"  최초 심각도: {f.original_severity} · 근거: {f.triage_reason}"])
    if fixed:
        rows.extend(["", "## 직전 스캔 이후 해결됨"])
        rows.extend(f"- {f.title} · {f.location.file}:{f.location.line}" for f in fixed)
    java_routes = [r for r in result.routes if 'policy_source' in r]
    if java_routes:
        rows.extend(["", "## Spring MVC 경로별 정적 인가 단서"])
        rows.extend(f"- {r['method']} `{r['path']}` · {r['auth_guard']} · {r['file']}:{r['line']}" for r in java_routes)
    rows.extend(["", "## 추가 확인", *["- " + s for s in MANUAL],
                 "- 외부 입력 도달 여부와 제시한 수정 예시는 실제 호출 문맥에서 검토하세요."])
    rows.extend(["", "## 점검 한계", *['- ' + x for x in result.profile.limitations],
                 '- 부분 실패 파일: ' + (', '.join(result.partial_files) or '없음'),
                 '- 규칙팩: ' + result.engine.get('rulepack', '미기록'),
                 '- 점수: 열린 발견의 Critical 40 / High 20 / Medium 10 / Low 3 합계, 최대 100 (기존 방식).'])
    return "\n".join(rows) + "\n"


def baseline(database, repo, output, branch, commit):
    """Use the latest available scan on this branch that HEAD actually descends from."""
    if not database.is_file():
        return None
    for row in list_scans(database, str(repo)):
        if row["branch"] != branch or not row["commit_sha"]:
            continue
        try:
            if row["commit_sha"] != commit:
                git(repo, "merge-base", "--is-ancestor", row["commit_sha"], commit)
            result = ScanResult.from_json((output / row["scan_id"] / "scan_result.json").read_text(encoding="utf-8"))
            if result.branch == branch and result.commit == row["commit_sha"]:
                return result
        except (OSError, ValueError, KeyError, TypeError):
            continue  # moved or damaged result: fall back to an older one, its commit is recorded as the baseline
    return None


class ScanInputError(ValueError):
    """A scan the user can fix; its message is safe to show in the dashboard."""


LIMITED = {"php": "PHP", "rb": "Ruby", "go": "Go", "kt": "Kotlin", "vue": "Vue"}
STAGES = ["코드 수집", "정찰", "점검 계획", "정적 검사", "검토·보고서"]


def scan(repo, output, directory, offline=False, trigger=Trigger.MANUAL, progress=lambda stage, text: None,
         new_high_only=False, folder_source=None):
    """progress(stage, text) reports STAGES[stage] and one log line; text never carries source code.

    new_high_only (background scans with consent): skip the model plan and send only findings that are
    new since the previous scan and High or above, to spare the user's ChatGPT quota.
    """
    repo = repo.expanduser().resolve()
    output = output.expanduser().resolve()
    if output.is_relative_to(repo) or directory.resolve().is_relative_to(repo):
        raise ScanInputError("결과와 이력은 검사 대상 저장소 밖에 저장해야 합니다.")
    scan_id = uuid.uuid4().hex
    coverage = analysis.default_coverage()
    note = "로컬 규칙으로 작성"
    issue = None  # first model problem, so the dashboard can point to its fix
    active = None
    progress(0, "검사할 파일을 임시 폴더에 수집하는 중")
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp)
        commit, branch, files = snapshot(repo, source, folder_source=folder_source)
        progress(0, f"파일 {len(files)}개 수집 · 커밋 {commit[:12]}")
        previous = baseline(directory / "scan-history.sqlite3", repo, output, branch, commit)
        exclusions = getattr(files, 'excluded', set())
        excluded_previous = {name for f in previous.findings if f.change != Change.FIXED
                             for name in evidence_files(f) if name and
                             any(p.as_posix() in exclusions for p in (Path(name), *Path(name).parents))} if previous else set()
        if not (files or getattr(files, 'sensitive_files', []) or getattr(files, 'skipped', []) or excluded_previous):
            raise ScanInputError("제외 규칙 적용 후 검사 가능한 텍스트 파일이 없습니다.")
        app = profile(source, files)
        progress(1, f"정찰 완료 · {app.framework or '프레임워크 미확인'} · 라우트 {app.routes}개")
        context = Context(source, files)
        app.limitations = ["언어별로 지원하는 정적 규칙을 적용합니다. 실행 중 동작은 수동 확인 대상입니다."]
        counts = languages(files)
        if counts.get("java"):
            app.limitations.append("Java는 JDBC SQL 호출 경로와 Spring MVC 관리자 경로의 명시적 인가 정책을 점검합니다. 동적 호출·복잡한 조건·운영 권한은 수동 확인 대상입니다.")
        others = {LIMITED[k]: n for k, n in counts.items() if k in LIMITED}
        mostly_unsupported = sum(others.values()) > sum(counts.get(k, 0) for k in ("python", "javascript", "typescript", "java"))
        if others:
            names = ", ".join(f"{label} {n}개" for label, n in others.items())
            app.limitations.insert(0, f"제한된 규칙을 적용한 파일({names}). PHP·Ruby·Go·Vue는 일부 HTML 출력 처리, Kotlin은 인증정보만 점검합니다.")
        progress(2, "기본 점검 계획 사용" if offline or new_high_only else "ChatGPT에 점검 계획 요청 중")
        if not offline:
            try:
                token = access_token(directory)
                model = inference.model_for(token)
                active = token, model
                if not new_high_only:
                    coverage = analysis.plan(context, app, *active)
                    note = "코드 문맥 기반 정찰·점검 계획 적용"
            except SessionError as exc:
                active = None
                note, issue = f"로컬 규칙으로 작성 · {exc}", exc.kind
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, requests.RequestException):
                note, issue = "모델 정찰·계획 확인 실패 · 고정 점검 계획 적용", "error"
            progress(2, note)
        progress(3, "정적 규칙·시크릿·설정 검사 중")
        findings = inspect(source, files)
        if any('policy_source' in route for route in getattr(findings, 'routes', [])):
            app.framework = ', '.join(filter(None, [app.framework, 'Spring MVC']))
        progress(3, f"발견 후보 {len(findings)}건")
        findings.sort(key=lambda f: (list(Severity).index(f.severity), f.confidence != "Likely", f.id))
        partial = sorted(set(getattr(findings, 'partial_files', [])) | excluded_previous)
        # Compare before the model review, so a background scan can send only what this commit introduced.
        progress(4, "직전 스캔과 비교하는 중")
        matched = compare(findings, previous, commit, partial, getattr(findings, 'credential_files', ())) if previous else None
        kept, gone = matched or ([], [])
        targets = [f for f in findings if not new_high_only or
                   (f.change == Change.NEW and f.severity in (Severity.CRITICAL, Severity.HIGH))]
        if active and targets:
            count = 0
            reviewable = [f for f in targets if f.location.file in context.sources]
            for start in range(0, min(len(reviewable), 30), 5):
                progress(4, f"ChatGPT 검토 중 {start}/{min(len(reviewable), 30)}건")
                try:
                    count += analysis.review(context, reviewable[start:start + 5], *active)
                except SessionError as exc:
                    note += f" · 남은 검토는 로컬 수정안 사용 ({exc})"
                    issue = exc.kind
                    break
                except (ValueError, KeyError, TypeError, requests.RequestException):
                    note += " · 모델 검토 확인 실패 · 남은 항목은 로컬 수정안 사용"
                    issue = "error"
                    break
            note += f" · 한국어 상세 검토 {count}/{len(targets)}건" + (" (새 High 이상만)" if new_high_only else "")
            if len(reviewable) < len(targets):
                note += " · 모델용 소스 문맥이 없는 항목은 로컬 판정 유지"
            if len(reviewable) > 30:
                note += " · 모델 검토 상한 30건, 나머지는 로컬 규칙 결과"
        elif active:
            note += " · 새로 생긴 High 이상 발견이 없어 ChatGPT 검토 생략" if new_high_only else ""

    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10,
               Severity.LOW: 3, Severity.INFO: 0}
    if mostly_unsupported:
        note += f" · 주 언어({', '.join(others)})는 규칙 범위가 제한되어 결과가 불완전합니다"
    progress(4, "보고서 저장 중")
    current = list(findings) + kept
    for number, f in enumerate(kept + gone, len(findings) + 1):
        f.id = f"F-{number:03}"
    kisa_rows = checklist(findings, languages(files), partial, carried=kept)
    coverage = legacy_coverage(coverage, kisa_rows)
    app.routes = len(getattr(findings, 'routes', [])) or app.routes
    result = ScanResult(scan_id, repo.name, datetime.now(timezone.utc), Target(str(repo)),
                        min(100, sum(weights[f.severity] for f in current if f.status == Status.OPEN)), app, current + gone, "",
                        branch=branch, commit=commit, baseline_commit=previous.commit if matched else None, trigger=trigger,
                        checklist=[c['name'] for c in coverage],
                        analysis_note=note, coverage=coverage,
                        engine={'version': '0.2.0', 'rulepack': 'vibescan-2026.11.5', 'semgrep': '1.185.0'},
                        languages=languages(files), partial_files=partial,
                        sensitive_files=getattr(files, 'sensitive_files', []), routes=getattr(findings, 'routes', []),
                        config_summary=getattr(findings, 'config_summary', []), kisa_checklist=kisa_rows,
                        source_checks=getattr(findings, 'source_checks', []))
    result.report_md = render(result)
    output.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    final = output / scan_id
    with tempfile.TemporaryDirectory(dir=output) as staging:
        ready = Path(staging) / "result"
        ready.mkdir()
        (ready / "scan_result.json").write_text(result.to_json(), encoding="utf-8")
        (ready / "report.md").write_text(result.report_md, encoding="utf-8")
        os.rename(ready, final)
    try:
        save_scan(directory / "scan-history.sqlite3", result)
    except Exception:
        shutil.rmtree(final)
        raise
    return final, note, issue


def main():
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            if not stream.isatty() and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="vibescan")
    commands = parser.add_subparsers(dest="command")
    dashboard = commands.add_parser("dashboard", help="저장된 진단 결과를 로컬 대시보드에서 확인")
    dashboard.add_argument("--results", type=Path, help="scan --output으로 지정한 결과 상위 폴더")
    commands.add_parser("login", help="ChatGPT 로컬 로그인")
    run = commands.add_parser("scan", help="로컬 Git 저장소 전체 검사")
    run.add_argument("repo", type=Path)
    run.add_argument("--offline", action="store_true", help="로컬 규칙만 사용")
    run.add_argument("--output", type=Path, help="실행별 결과 폴더의 상위 경로")
    hook = commands.add_parser("hook-trigger", help="git post-commit hook이 호출하는 백그라운드 검사")
    hook.add_argument("commit")
    args = parser.parse_args()
    try:
        directory = data_dir()
        if args.command in (None, "dashboard"):
            from .dashboard import serve
            serve(getattr(args, "results", None) or directory / "scans")
        elif args.command == "hook-trigger":
            from .hook import trigger
            trigger(Path.cwd(), args.commit, directory)
        elif args.command == "login":
            from .login import login
            print(login(directory))
        else:
            folder, note, _ = scan(args.repo, args.output or directory / "scans", directory, args.offline)
            print(f"{folder}\n{note}")
    except (ValueError, RuntimeError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"VibeScan: {exc}\n")
