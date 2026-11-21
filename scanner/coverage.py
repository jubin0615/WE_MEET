"""Coverage describes the inputs and rules actually available to this scan."""
from .models import Change, Status
from .owasp import catalog


STATES = {
    "completed": "검사함 · 미발견", "partial": "부분 점검", "skipped": "건너뜀",
    "not_applicable": "해당 없음(추정)", "manual": "수동 확인 필요",
}
SCRIPT = {"python", "javascript", "typescript"}
LIMITED = {"java", "kt", "php", "rb", "go", "vue", "svelte", "astro"}
SAST_INPUTS = SCRIPT | (LIMITED - {"kt"}) | {"html", "jinja", "j2"}


def compute(findings, languages, partial_files, carried=(), plan=()):
    vs = catalog("vibescan-top10")["items"]
    web = catalog("owasp-top10-2025")["items"]
    inputs = {row["id"]: row for row in getattr(findings, "source_checks", ())}
    applied = {key for key, row in inputs.items() if row["execution"] == "partial"}
    partial = bool(partial_files)
    langs = set(languages)
    full_sast = bool(langs & SCRIPT) and not (langs & LIMITED or partial)
    candidates = [f for f in (*findings, *carried) if f.status == Status.OPEN and f.change != Change.FIXED]
    states = {}

    def mark(code, execution, reason):
        states[code] = execution, reason

    mark("VS-01", "partial" if partial or not (langs or getattr(findings, "committed_sensitive", False)) else "completed",
         "수집한 소스의 리터럴·공개 키 이름과 커밋된 민감 파일 메타데이터를 점검합니다.")
    mark("VS-02", "partial" if partial or langs & (SCRIPT | {"java"}) else "skipped", "지원 라우트의 가드·소유자 조건과 JWT 사용을 점검합니다. 상위 권한 정책은 수동 확인합니다.")
    for code, key, hint in [("VS-03", "baas", "BaaS 정책 파일·SDK"),
                            ("VS-04", "dependencies", "지원하는 패키지 매니페스트")]:
        if key in applied:
            mark(code, "partial", inputs[key]["reason"])
        elif partial:
            mark(code, "partial", f"미해석 파일에서 {hint} 사용 여부를 확인할 수 없습니다.")
        elif key in getattr(findings, "inventory_hints", ()):
            mark(code, "skipped", f"{hint} 단서가 있지만 탐지기에 필요한 입력 형식이 없습니다.")
        else:
            mark(code, "not_applicable", f"수집 범위에서 {hint} 단서를 찾지 못했습니다.")
    mark("VS-05", "completed" if full_sast and not langs & {"javascript", "typescript"} else "partial",
         "지원하는 SQL·HTML·코드 실행·경로·역직렬화 패턴을 점검합니다. SSRF와 업로드 검사는 Python에 한정됩니다.")
    if not (partial or langs & SAST_INPUTS):
        mark("VS-05", "skipped", "주입 규칙을 적용할 수 있는 소스가 없습니다.")
    mark("VS-06", "partial", "소스·설정에 명시된 값과 저장된 응답만 점검합니다. 운영 설정은 수동 확인합니다.")
    mark("VS-07", "partial" if "business" in applied else "skipped",
         "JS/TS 결제 호출의 요청 금액 사용만 점검합니다." if "business" in applied else "지원하는 결제 호출 검사 입력이 없습니다.")
    for code in ("VS-08", "VS-09", "VS-10"):
        mark(code, "skipped", "전용 탐지기를 아직 구현하지 않았습니다.")
    # These inputs are narrower than the full inventory of related VS categories.
    has_scripts = bool(langs & SCRIPT)
    has_js = bool(langs & {"javascript", "typescript"})
    web_inputs = {
        "A01:2025": has_scripts or "java" in langs or bool(applied & {"baas", "server"}) or
                    getattr(findings, "committed_sensitive", False),
        "A02:2025": has_scripts,
        "A04:2025": bool(langs) or "server" in applied,
        "A06:2025": "python" in langs or bool(applied & {"server", "client-keys", "business"}),
        "A07:2025": bool(langs),
        "A08:2025": "python" in langs,
        "A10:2025": has_js,
    }
    for item in web:
        code = item["code"]
        if code == "A09:2025":
            mark(code, "manual", "운영 로그 수집과 경보 전달 여부를 확인하세요.")
        elif code == "A03:2025":
            states[code] = states["VS-04"]
        elif code == "A05:2025":
            execution = "completed" if full_sast else states["VS-05"][0]
            mark(code, execution, "지원 언어의 주입 규칙 범위만 점검합니다.")
        elif not web_inputs[code] and not partial:
            mark(code, "skipped", "수집한 파일에는 이 분류의 자동 규칙에 필요한 입력이 없습니다.")
        else:
            mark(code, "partial", "관련 VS 규칙이 다루는 정적 단서에 한정됩니다.")

    def row(item, field):
        code = item["code"]
        execution, reason = states[code]
        matches = [f.id for f in candidates if getattr(f, field) == code]
        if partial and execution == "partial":
            reason += f" 이번 스캔의 부분 실패·미해석 파일 {len(partial_files)}개."
        if any(f.id in matches for f in carried):
            reason += " 이번 스캔에서 재확인하지 못한 이전 발견을 포함합니다."
        return dict(id=code, code=code, name=item.get("name_ko", item["name"]), execution=execution,
                    status="취약 후보" if matches else STATES[execution], reason=reason, findings=matches)

    by_code = {item["code"]: item for item in vs}
    vs_rows = []
    for check in plan or [{"id": item["code"]} for item in vs]:
        item = by_code[check["id"]]
        record = row(item, "category")
        if "source_ids" in check:
            record.update(mode=check["mode"], source_ids=check["source_ids"], plan_reason=check["reason"])
        vs_rows.append(record)
    web_rows = [dict(row(item, "owasp"), static_reach=item["static_reach"], url=item["url"],
                     related_vs=[v["code"] for v in vs if item["code"] in v["owasp"]]) for item in web]
    return vs_rows, web_rows
