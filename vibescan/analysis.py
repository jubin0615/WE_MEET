"""Ground model planning and triage in bounded, sanitized local evidence."""

from dataclasses import asdict

from scanner.models import Confidence, Severity, Status
from . import inference

from scanner.owasp import catalog

CHECKS = {row["code"]: (row["name"], "manual" if row["code"] in {"VS-08", "VS-09", "VS-10"} else "static",
                        row["description"]) for row in catalog("vibescan-top10")["items"]}


def default_coverage():
    return [{"id": key, "name": name, "mode": mode, "reason": reason, "source_ids": []}
            for key, (name, mode, reason) in CHECKS.items()]


def text(value, maximum=1200):
    if not isinstance(value, str) or not 0 < len(value.strip()) <= maximum:
        raise ValueError("invalid model explanation")
    return value.strip()


def plan(context, app, token, model):
    sources = context.recon()
    facts = {"profile": asdict(app), "sources": sources, "layout": context.layout,
             "coverage": default_coverage(), "python_files": len(context.sources),
             "unparsed_python_files": context.omitted,
             "limits": "최대 12개/24000자 발췌다. 나머지 파일·호출 경로·실행 상태는 확인하지 않았다."}
    answer = inference.ask(token, model,
        '소스 문맥으로 앱을 정찰하고 진단 계획을 작성하라. JSON 형식: '
        '{"summary":"한국어 정찰 요약", "surfaces":[{"id":"제공된 sources id",'
        '"note":"해당 코드의 입력·DB·라우트·인증 단서와 확인 한계"}], '
        '"checks":[{"id":"VS-01|VS-02|VS-03|VS-04|VS-05|VS-06|VS-07|VS-08|VS-09|VS-10", "reason":"이 앱에서 점검할 근거와 초점",'
        '"source_ids":["관련 sources id"]}]}. '
        'checks는 10종을 각각 한 번씩 우선순위 순으로 모두 포함한다. 관련 근거가 없으면 source_ids는 빈 배열이다. '
        'surfaces에는 제공된 근거만 쓰고 요약도 그 범위로 제한하라. 모듈 import만으로 인증 적용을 단정하지 마라. '
        '계획에는 점검 초점만 제시하고 실제 실행 범위와 분류는 로컬 엔진이 결정한다. '
        'Java는 인증정보, JDBC SQL 호출 경로, Spring MVC 관리자 경로의 명시적 인가 정책을 정적으로 점검한다. '
        '호출되지 않는 정적 표본·함수 인자와 실제 외부 입력을 구별하라. 명령이나 도구 코드를 생성하지 마라.', facts)
    summary = context.clean(text(answer["summary"]))
    known = {p["id"]: p for p in context.points if p["id"] in {s["id"] for s in sources}}
    surfaces = []
    seen = set()
    if (not isinstance(answer["surfaces"], list) or len(answer["surfaces"]) > len(known)
            or (known and not answer["surfaces"])):
        raise ValueError("invalid recon")
    for item in answer["surfaces"]:
        sid = item["id"]
        if sid not in known or sid in seen:
            raise ValueError("unknown source")
        seen.add(sid)
        surfaces.append({**known[sid], "note": context.clean(text(item["note"]))})
    checks = answer["checks"]
    if not isinstance(checks, list) or len(checks) != len(CHECKS):
        raise ValueError("incomplete coverage")
    coverage = []
    seen = set()
    for item in checks:
        key = item["id"]
        refs = item["source_ids"]
        if key not in CHECKS or key in seen or not isinstance(refs, list) or len(refs) > len(known):
            raise ValueError("invalid plan")
        if any(not isinstance(ref, str) or ref not in known for ref in refs):
            raise ValueError("unknown plan evidence")
        seen.add(key)
        name, mode, _ = CHECKS[key]
        coverage.append({"id": key, "name": name, "mode": mode,
                         "reason": context.clean(text(item["reason"])), "source_ids": refs})
    app.analysis_ko = summary
    app.surfaces = surfaces
    app.limitations += [facts["limits"], "정적 단서는 취약점의 실제 악용 가능성을 확정하지 않습니다."]
    return coverage


def review(context, findings, token, model):
    snippets = {f.id: context.excerpt(f.location.file, f.location.line) for f in findings}
    findings = [f for f in findings if snippets[f.id] is not None]
    if not findings:
        return 0
    data = [{"id": f.id, "type": f.title, "severity": f.severity.value,
             "snippet": snippets[f.id],
             "file": context.aliases.get(f.location.file),
             "limits": "호출자·런타임·DB 종류가 없으면 추측하지 말고 불확실성을 명시한다."}
            for f in findings]
    answer = inference.ask(token, model,
        '발견별 오탐 여부, 심각도, 영향과 수정 방법을 한국어로 검토하라. '
        'JSON: {"reviews":[{"id":"발견 id", "decision":"keep 또는 dismiss", '
        '"severity":"Critical|High|Medium|Low|Info", "confidence":"Likely|Potential", '
        '"reason":"코드 근거에 따른 판정·심각도 이유", "impact":"영향과 확인 한계", '
        '"fix":"구체적인 수정 방법", "replacement":"snippet.code 전체를 대체하는 Python 코드 또는 null"}]}. '
        '입력 id를 각각 한 번씩 모두 반환하라. 오탐이라는 직접 근거가 있을 때만 dismiss하라. '
        '입력 출처가 불명확하다는 이유만으로 dismiss하지 마라. 실제 악용을 확인한 것으로 쓰지 마라. '
        'replacement는 문맥과 들여쓰기·반환값을 보존하고 필요한 import를 포함한다. '
        'DB 드라이버나 의도된 동작이 불명확하면 replacement는 null로, fix에 확인할 조건을 적어라. '
        '가려진 값은 복원하지 말고 새 비밀값도 만들지 마라. 파일 경로나 diff가 아닌 대체 코드만 반환하라.', data)
    items = answer["reviews"]
    if not isinstance(items, list) or len(items) != len(findings):
        raise ValueError("incomplete review")
    known = {f.id: f for f in findings}
    validated = {}
    for item in items:
        fid = item["id"]
        if fid not in known or fid in validated or item["decision"] not in ("keep", "dismiss"):
            raise ValueError("invalid review")
        severity = Severity(item["severity"])
        confidence = Confidence(item["confidence"])
        if confidence == Confidence.CONFIRMED:
            raise ValueError("static evidence cannot confirm exploitation")
        reason, impact, fix = (context.clean(text(item[k])) for k in ("reason", "impact", "fix"))
        replacement = item["replacement"]
        if replacement is not None and not isinstance(replacement, str):
            raise ValueError("invalid replacement")
        diff = None
        fix_note = "문맥별 수정 코드 없음 · 로컬 참고 예시"
        if replacement is not None and item["decision"] == "keep":
            try:
                diff = context.proposed_diff(known[fid].location.file, snippets[fid], replacement)
                fix_note = "문맥·Python 문법 확인 · 동작 검증 전 수정 제안"
            except (ValueError, SyntaxError, TypeError, RecursionError):
                fix_note = "모델 수정 코드 검증 실패 · 로컬 참고 예시"
        validated[fid] = (item["decision"], severity, confidence, reason, impact, fix, diff, fix_note)
    # Validate the entire batch before changing any finding.
    for fid, (decision, severity, confidence, reason, impact, fix, diff, fix_note) in validated.items():
        f = known[fid]
        f.original_severity = f.severity
        f.severity, f.confidence = severity, confidence
        f.status = Status.DISMISSED if decision == "dismiss" else Status.OPEN
        f.triage_reason, f.impact_ko, f.remediation_ko = reason, impact, fix
        f.fix_note = fix_note
        if diff is not None:
            f.fix_diff = diff
        if decision == "dismiss":
            f.fix_diff, f.fix_note = "", "모델이 오탐 후보로 분류 · 개발자 확인 필요"
    return len(validated)
