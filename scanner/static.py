"""Local read-only checks and evidence normalization for committed web sources."""

import ast
import re

from .models import AppProfile
from .detectors import secrets, config, routes, java, dependencies, project
from .detectors.semgrep import convert, semgrep
from .normalize import RawHit, normalize, code_identity


def excerpt(content, line, hidden=()):
    """The real code around a finding, for the person reading it locally; detected secrets keep 4 characters.

    The model never receives this text: it gets the sanitized Context excerpt instead.
    """
    lines = content.splitlines()
    rows = [f"{'>' if n == line else ' '} {n:>4} | {secrets.mask(lines[n - 1], hidden)[:200]}"
            for n in range(max(1, line - 2), min(len(lines), line + 2) + 1)]
    return "\n".join(rows)


def profile(directory, files):
    frameworks = set()
    routes = 0
    auth_signals = set()
    for name in files:
        if not name.endswith(".py"):
            if name.endswith(('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs')) and re.search(
                r'''\b(?:from\s*['"]express['"]|require\(\s*['"]express['"]\s*\))''',
                (directory / name).read_text(encoding='utf-8-sig')):
                frameworks.add('Express')
            continue
        try:
            tree = ast.parse((directory / name).read_text(encoding="utf-8-sig"))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
                for module in modules:
                    package = module.split(".")[0]
                    if package in {"flask_login", "flask_jwt_extended", "jwt", "authlib"}:
                        auth_signals.add(package)
                    label = {"flask": "Flask", "fastapi": "FastAPI", "django": "Django"}.get(module.split(".")[0])
                    if label:
                        frameworks.add(label)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                routes += sum(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                              and d.func.attr in {"route", "get", "post", "put", "patch", "delete"}
                              for d in node.decorator_list)
    auth = "인증 관련 모듈 참조: " + ", ".join(sorted(auth_signals)) if auth_signals else None
    return AppProfile(", ".join(sorted(frameworks)) or None, routes, auth)


class Inspection(list):
    def __init__(self, findings, partial_files, route_rows, settings):
        super().__init__(findings)
        self.partial_files = sorted(set(partial_files))
        self.routes = route_rows
        self.config_summary = settings


def inspect(directory, files):
    allowed = set(files)
    matched = semgrep(directory) if files else []
    raw = [convert(hit, allowed) for hit in matched]
    partial = list(getattr(matched, 'partial_files', []))
    if hasattr(matched, 'scanned_files'):
        supported = ('.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.java',
                     '.html', '.j2', '.jinja', '.vue', '.svelte', '.astro', '.php', '.rb', '.go')
        partial.extend(name for name in allowed - matched.scanned_files if name.lower().endswith(supported))
    if any(name not in allowed for name in partial):
        raise ValueError('부분 실패 파일이 검사 범위 밖입니다.')
    partial += getattr(files, 'skipped', [])
    contents = {name: (directory / name).read_text(encoding='utf-8-sig') for name in files}
    credential_files = set(contents)
    for hit in raw:
        lines = contents[hit.file].splitlines()
        if hit.line > len(lines):
            raise ValueError('검사 근거 줄이 파일 범위 밖입니다.')
        hit.identity = code_identity(contents[hit.file], hit.line, hit.file.endswith('.py'))
    route_rows, settings = [], []
    manifests, pin_count = 0, 0
    if any(name.endswith('.java') for name in contents):
        java_hits, java_routes, java_partial = java.detect(contents)
        raw.extend(java_hits)
        route_rows.extend(java_routes)
        partial.extend(java_partial)
    hidden = {}
    for name, content in contents.items():
        if dependencies.supported(name):
            found, count, incomplete = dependencies.detect(name, content)
            raw.extend(found)
            manifests += 1
            pin_count += count
            if incomplete:
                partial.append(name)
        hidden[name] = set()
        raw.extend(secrets.detect(name, content, hidden[name]))
        found, summary = config.detect(name, content)
        raw.extend(found); settings.extend(summary)
        found, rows = routes.detect(name, content)
        raw.extend(found); route_rows.extend(rows)
        if name.endswith('.py'):
            try:
                ast.parse(content)
            except (SyntaxError, ValueError):
                partial.append(name)
                credential_files.discard(name)
    found, summary, failures = project.detect(contents, route_rows, getattr(files, 'sensitive_files', ()))
    raw.extend(found)
    settings.extend(summary)
    partial.extend(failures)
    for hit in raw:
        if hit.file in contents:
            if any('\n' in value or 'PRIVATE KEY-----' in value for value in hidden[hit.file]):
                hit.evidence = '[여러 줄에 걸친 비밀값 보호를 위해 코드 생략]'
                hit.fix = ''
            elif hit.evidence == '[코드·값 가림]':
                hit.evidence = excerpt(contents[hit.file], hit.line, hidden[hit.file])
            else:
                hit.evidence = secrets.mask(hit.evidence, hidden[hit.file])
    for entry in getattr(files, 'sensitive_files', []) if getattr(files, 'committed', True) else ():
        raw.append(RawHit('secrets', 'vs-secret-file', entry['path'], 1, 'CWE-540', 'VS-01',
            '민감 파일이 Git HEAD에 포함됨', '실제 자격증명이면 교체하고 추적을 해제하세요. .gitignore 추가만으로 과거 커밋에서 삭제되지 않습니다.',
            evidence='[파일 존재만 기록 · 내용 저장/전송 없음]', identity=entry['kind']))
    settings.extend({'file': h.file, 'line': h.line, 'setting': h.rule_id, 'value': '확인 필요'}
                    for h in raw if h.detector == 'semgrep' and h.rule_id in
                    {'vs-js-cors', 'vs-js-cookie', 'vs-js-error'})
    result = Inspection(normalize(raw), partial, route_rows, settings)
    result.credential_files = credential_files
    result.source_checks = project.coverage(files, partial, route_rows, manifests, pin_count,
        dependencies.database()["date"])
    result.committed_sensitive = bool(getattr(files, "sensitive_files", ())) and getattr(files, "committed", True)
    result.inventory_hints = set()
    if any(re.search(r"\b(?:supabase|firebase)\b", text, re.I) for text in contents.values()):
        result.inventory_hints.add("baas")
    if any(name.rsplit("/", 1)[-1] in {"pyproject.toml", "Cargo.toml", "Pipfile", "composer.json"}
           for name in contents):
        result.inventory_hints.add("dependencies")
    result.file_upload = any('request.files' in text or 'UploadFile' in text or 'multer' in text
                             for text in contents.values())
    return result
