"""Project settings and guarded browser calls with source locations."""

import json
import re
from bisect import bisect_left
from collections import defaultdict
from pathlib import PurePosixPath

from ..models import Severity
from ..normalize import RawHit
from . import routes, secrets
from .dependencies import supported as dependency_manifest


def blank(match):
    return re.sub(r"[^\n]", " ", match[0])


SQL_TEXT = re.compile(r"--[^\n]*|/\*[\s\S]*?\*/|'(?:''|[^'])*'|(\$(?:\w+)?\$)[\s\S]*?\1")
IDENT = r'(?:"[\w]+"|[a-z_][\w$]*)'
TABLE = rf'(?:(?:public|"public")\s*\.\s*)?{IDENT}'
RLS = re.compile(rf'^\s*(?:create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<create>{TABLE})\s*\('
    rf'|alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?P<alter>{TABLE})\s+'
    rf'(?P<action>enable|disable)\s+row\s+level\s+security\b'
    rf'|drop\s+table\s+(?:if\s+exists\s+)?(?P<drop>{TABLE})(?=\s|$))', re.I)
POLICY = re.compile(rf'^\s*(create|alter|drop)\s+policy\s+(?:if\s+exists\s+)?({IDENT})'
                    rf'\s+on\s+({TABLE})(?=\s|$)', re.I)
CONDITION = re.compile(r'\b(using|with\s+check)\s*\(\s*(true\s*\))?', re.I)
FIREBASE = re.compile(r'\ballow\s+(?:read|write|get|list|create|update|delete)'
    r'(?:\s*,\s*(?:read|write|get|list|create|update|delete))*\s*:\s*if\s+true\s*;')
NGINX = re.compile(r'''(?:^|(?<=[;{}]))\s*(?P<setting>autoindex\s+on\s*(?=;)|add_header\s+Strict-Transport-Security\s+["']?max-age=0(?:["']|\s|;))''', re.I)
CLIENT_GUARD = re.compile(r'\bif\s*\(\s*(?:!\s*(?:user|session|isAuthenticated|currentUser)\s*\)\s*'
    r'(?:\{\s*return(?:\s+null)?\s*;?\s*\}|return(?:\s+null)?\s*;)|'
    r'(?:user|session|isAuthenticated|currentUser)\s*\)\s*\{)\s*(?:return\s+|(?:const|let)\s+\w+\s*=\s*)?(?:await\s+)?fetch\s*\(')
FETCH_PATH = re.compile(r'''\s*(["'])(/[\w./-]*)\1\s*(?:\)|,\s*\{\s*method\s*:\s*["'](GET|POST|PUT|PATCH|DELETE)["']\s*[,}])''', re.I)
PUBLIC_REF = re.compile(r'(?:import\.meta\.env|process\.env)\.(' + secrets.PUBLIC_SERVER_VAR.pattern + r')')
SCRIPT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
BUSINESS = re.compile(r'/(?:checkout|payments?|refunds?|orders?|coupons?|credits?|transfers?)(?:/|$)', re.I)


def policy_sql(name):
    return bool(re.search(r'(?:^|/)supabase/(?:migrations/[^/]+\.sql|schema\.sql)$', name, re.I))


def firebase_rules(name):
    return name.endswith((".rules", ".rules.json"))


def nginx_config(name):
    path = PurePosixPath(name.lower())
    return path.name == "nginx.conf" or path.suffix == ".conf" and "nginx" in path.parts


def identifier(text):
    text = text.rsplit(".", 1)[-1].strip()
    return text.strip('"') if text.startswith('"') else text.lower()


def detect(contents, route_rows, sensitive_files):
    hits, settings, tables, policies, partial = [], [], {}, {}, []
    by_endpoint = defaultdict(list)
    for route in route_rows:
        by_endpoint[(route["method"], route["path"])].append(route)

    def add(rule, file, line, cwe, codes, title, advice, identity, **kwargs):
        hits.append(RawHit("project", rule, file, line, cwe, codes, title, advice,
                           Severity.MEDIUM, identity=identity, **kwargs))

    for name, source in sorted(contents.items()):
        if policy_sql(name):
            root = re.split(r'(?:^|/)supabase/', name, flags=re.I)[0]
            # A schema dump and a migration stream are independent views.
            stream = (root, PurePosixPath(name).name.lower() == "schema.sql" and "/migrations/" not in name.lower())
            sql = SQL_TEXT.sub(blank, source)
            newlines = [m.start() for m in re.finditer("\n", sql)]
            for statement in re.finditer(r"[^;]+", sql):
                text = statement[0]
                line = bisect_left(newlines, statement.start() + len(text) - len(text.lstrip())) + 1
                change = RLS.match(text)
                if change:
                    ident = next(change[k] for k in ("create", "alter", "drop") if change[k])
                    table = identifier(ident)
                    key = (*stream, table)
                    if change["drop"]:
                        tables.pop(key, None)
                        policies.pop(key, None)
                    elif (change["action"] or "").lower() == "enable":
                        tables[key] = None
                    elif change["create"]:
                        tables.setdefault(key, (name, line, table, False))
                    else:
                        tables[key] = (name, line, table, True)
                policy = POLICY.match(text)
                if policy:
                    action, label, target = policy.groups()
                    policy_name = identifier(label)
                    table_policies = policies.setdefault((*stream, identifier(target)), {})
                    if action.lower() == "drop":
                        table_policies.pop(policy_name, None)
                    else:
                        state = table_policies.setdefault(policy_name, {})
                        for clause in CONDITION.finditer(text, policy.end()):
                            key = clause[1].lower().split()[0]
                            if clause[2]:
                                state[key] = (name, line)
                            else:
                                state.pop(key, None)
        elif name.endswith(".rules.json"):
            try:
                root = json.loads(source)["rules"]
                if not isinstance(root, dict):
                    raise ValueError("invalid rules")
                pending = [("", root)]
                while pending:
                    path, node = pending.pop()
                    for key, value in node.items():
                        if key in {".read", ".write"} and (value is True or value == "true"):
                            add("vs-firebase-public", name, 1, "CWE-862", ["V-04"],
                                "인증 조건 없이 허용하는 Realtime Database 규칙",
                                "해당 경로와 하위 경로에 적용되는 읽기·쓰기 권한을 확인하세요.", f"{path}/{key}",
                                evidence=f"rules{path}/{key} = true · 파일 단위 근거")
                        elif isinstance(value, dict):
                            pending.append((f"{path}/{key}", value))
            except (ValueError, KeyError, TypeError, RecursionError):
                partial.append(name)
        elif firebase_rules(name):
            code = routes.JS_TOKENS.sub(blank, source)
            if re.search(r'\bservice\s+(?:cloud\.firestore|firebase\.storage)\b', code):
                for match in FIREBASE.finditer(code):
                    add("vs-firebase-public", name, code.count("\n", 0, match.start()) + 1, "CWE-862", ["V-04"],
                        "인증 조건 없이 허용하는 Firebase 규칙", "해당 경로가 공개 대상인지 확인하고 필요한 사용자·소유자 조건을 적용하세요.", match[0])
        elif name.lower().endswith(".headers.http"):
            facts = set(source.splitlines())
            missing = []
            if "html" in facts and "csp" not in facts:
                missing.append("Content-Security-Policy")
            if "nosniff" not in facts:
                missing.append("X-Content-Type-Options: nosniff")
            if missing:
                add("vs-response-headers", name, 1, "CWE-693", [], "저장한 응답의 보안 헤더 확인 필요",
                    "해당 응답 형식에 필요한 헤더를 설정하고 새 응답을 저장해 다시 확인하세요.", "response-headers",
                    evidence="2xx 응답에서 확인되지 않은 보호 설정 · " + ", ".join(missing))
                hits[-1].severity = Severity.LOW
        elif nginx_config(name):
            code = re.sub(r"#[^\n]*", "", source)
            for match in NGINX.finditer(code):
                line = code.count("\n", 0, match.start("setting")) + 1
                listing = match["setting"].lower().startswith("autoindex")
                rule = "vs-nginx-autoindex" if listing else "vs-nginx-hsts-zero"
                add(rule, name, line, "CWE-548" if listing else "CWE-319", ["CI-03" if listing else "CI-17"],
                    "Nginx 디렉터리 목록 표시" if listing else "Nginx HSTS 만료 시간 0",
                    "적용되는 server/location과 배포 응답을 확인하고 서비스에 필요한 보호 설정을 적용하세요.", match["setting"])
                settings.append(dict(file=name, line=line, setting=rule, value="배포 적용 확인 필요"))
        if not name.endswith(SCRIPT):
            continue
        code = routes.JS_TOKENS.sub(blank, source)
        for ref in PUBLIC_REF.finditer(code):
            add("vs-client-server-key", name, code.count("\n", 0, ref.start()) + 1, "CWE-522", ["CI-05"],
                "공개 환경변수에서 서버 전용 자격증명 참조", secrets.CLIENT_REMEDIATION, ref[1])
        if not (secrets.client_module(name, source) or name.endswith((".jsx", ".tsx")) or
                re.search(r'\b(?:document|window)\.', code)):
            continue
        for guard in CLIENT_GUARD.finditer(code):
            call = FETCH_PATH.match(source, guard.end())
            if not call:
                continue
            method, path = (call[3] or "GET").upper(), call[2]
            rows = by_endpoint[(method, path)]
            if len(rows) != 1 or rows[0]["auth_guard"]:
                continue
            route = rows[0]
            add("vs-client-only-auth", route["file"], route["line"], "CWE-306", ["CI-10"],
                "화면에서 인증을 확인한 API의 서버 가드 미확인", "서버 핸들러와 상위 미들웨어에서 세션·권한 검사를 확인하세요.",
                f"{method} {path}", trace=[dict(file=name, line=code.count("\n", 0, guard.start()) + 1, method="화면 인증 후 API 호출")])

    for (_, _, table), table_policies in policies.items():
        for policy_name, state in table_policies.items():
            for name, line in sorted(set(state.values())):
                add("vs-rls-policy-true", name, line, "CWE-862", ["V-04"], "항상 참인 RLS 정책 조건",
                    "정책의 대상 역할과 명령, 공개 의도를 확인하고 행 소유자 조건을 검토하세요.", f"{table}/{policy_name}")
    for name, line, table, disabled in filter(None, tables.values()):
        add("vs-supabase-rls", name, line, "CWE-862", ["V-04"],
            f"{table} 테이블 RLS " + ("명시적 비활성화" if disabled else "활성화 구문 미확인"),
            "배포 대상 스키마의 RLS 상태와 API 역할의 테이블 권한을 확인하세요.", table)
    for entry in sensitive_files:
        for key in entry.get("keys", []):
            if secrets.PUBLIC_SERVER_VAR.fullmatch(key):
                add("vs-client-server-key", entry["path"], 1, "CWE-522", ["CI-05"],
                    "공개 환경변수에 서버 전용 키 이름 선언", secrets.CLIENT_REMEDIATION, key,
                    evidence=f"{key} · 파일 단위 키 이름만 수집")
    return hits, settings, partial


def coverage(files, partial, routes_found, manifests, pins, snapshot_date):
    rows = []
    names = set(files) | set(partial)

    def record(key, title, targets, reason):
        skipped = len(set(targets).intersection(partial))
        if not targets:
            reason = "지원하는 입력 조합 미확인. " + reason
        rows.append(dict(id=key, name=title, execution="partial" if targets else "manual",
                         reason=reason + (f" · 부분 실패/미해석 파일 {skipped}개" if skipped else "")))

    record("dependencies", "의존성 보안 공지", [n for n in names if dependency_manifest(n)],
           f"GHSA {snapshot_date} 스냅샷 · 매니페스트 {manifests}개, 파일별 고정 버전 {pins}건 대조. 범위 선언과 다른 생태계는 미확인.")
    policies = [n for n in names if policy_sql(n) or firebase_rules(n)]
    record("baas", "Supabase RLS·Firebase 접근 규칙", policies,
           f"정책 파일 {len(policies)}개. 명시적 RLS 구문과 무조건 허용 규칙을 점검하며 배포 정책은 별도 확인.")
    scripts = [n for n in names if n.endswith(SCRIPT)]
    record("client-auth", "화면 인증과 서버 API 가드", scripts if routes_found else [],
           "화면 조건문 직후의 고정 fetch 경로와 같은 HTTP 메서드의 서버 라우트를 대조. 동적 경로·전역 가드는 수동 확인.")
    templates = [n for n in names if PurePosixPath(n).name in {".env.example", ".env.sample"}]
    record("client-keys", "브라우저에 공개되는 서버 전용 키", scripts + templates + [
        e["path"] for e in getattr(files, "sensitive_files", ()) if e["kind"] == "dotenv"],
           "브라우저 공개 접두사와 서버 키 이름, 클라이언트 코드의 리터럴을 확인. 실제 빌드 결과는 수동 확인.")
    langs = [n for n in names if n.endswith((".php", ".rb", ".go", ".vue"))]
    record("languages", "PHP·Ruby·Go·Vue 출력 처리", langs,
           f"대상 {len(langs)}개. 요청값 직접 출력, HTML 신뢰 처리, Vue 원시 HTML 바인딩을 점검.")
    servers = [n for n in names if nginx_config(n) or n.lower().endswith(".headers.http")]
    record("server", "서버 설정·보안 헤더", servers,
           f"설정·응답 파일 {len(servers)}개. Nginx 목록 표시·HSTS 해제와 저장한 2xx 응답의 nosniff·HTML CSP 유무를 점검. 운영 경로별 적용은 별도 확인.")
    operations = [f"{r['method']} {r['path']} ({r['file']}:{r['line']})" for r in routes_found
                  if r["method"] in {"POST", "PATCH", "PUT", "DELETE"} and BUSINESS.search(r["path"])]
    record("business", "결제·주문 등 업무 로직", [n for n in scripts if n.endswith((".js", ".jsx", ".ts", ".tsx"))],
           "결제 생성에 요청 금액을 직접 전달하는 JS/TS 구문을 점검. 서버 가격 재계산, 환불 중복 방지, 허용 상태 전이를 확인하세요."
           + (f" 검토 경로 {len(operations)}개 · " + ", ".join(operations[:12]) if operations else ""))
    return rows
