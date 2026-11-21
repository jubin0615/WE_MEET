"""Inspect literal framework settings without evaluating application code."""

import ast

from ..normalize import RawHit, code_identity
from ..models import Severity


def detect(name, content):
    hits, summary = [], []
    if not name.endswith('.py'):
        return hits, summary
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return hits, summary

    def add(node, key, category, cwe, title, fix, value):
        summary.append({'file': name, 'line': node.lineno, 'setting': key, 'value': value})
        hits.append(RawHit('config', 'vs-config-' + key, name, node.lineno, cwe, category, title, fix,
                           identity=code_identity(content, node.lineno, True)))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                key = ast.unparse(target)
                setting = (target.slice.value if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                           else target.attr if isinstance(target, ast.Attribute) else key)
                if isinstance(node.value, ast.Constant):
                    value = node.value.value
                    if setting == 'DEBUG' and value is True:
                        add(node, 'debug', 'VS-06', 'CWE-489', '디버그 설정 활성화', '배포 환경에서는 디버그를 끄세요.', True)
                    elif setting in ('SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'CSRF_COOKIE_SECURE') and value is False:
                        cwe = 'CWE-1004' if setting == 'SESSION_COOKIE_HTTPONLY' else 'CWE-614'
                        add(node, 'cookie-flags', 'VS-06', cwe, '쿠키 보호 속성 비활성화',
                            '인증 쿠키에 Secure·HttpOnly·SameSite 정책을 적용하세요.', False)
        if not isinstance(node, ast.Call):
            continue
        function = ast.unparse(node.func)
        kwargs = {k.arg: k.value for k in node.keywords if k.arg}
        literal = {k: v.value for k, v in kwargs.items() if isinstance(v, ast.Constant)}
        if function.endswith(('.run', 'FastAPI', 'Starlette')) and literal.get('debug') is True:
            add(node, 'debug', 'VS-06', 'CWE-489', '디버그 모드 활성화', '배포 환경에서는 디버그를 끄세요.', True)
        callee = function.rsplit('.', 1)[-1]
        if callee in ('CORS', 'add_middleware'):
            cors = callee == 'CORS' or any(ast.unparse(a).rsplit('.', 1)[-1] == 'CORSMiddleware' for a in node.args)
            origin = kwargs.get('allow_origins', kwargs.get('origins'))
            default_wildcard = callee == 'CORS' and 'resources' not in kwargs and all(k.arg for k in node.keywords)
            try:
                origin = ast.literal_eval(origin) if origin is not None else '*' if default_wildcard else None
            except (ValueError, TypeError):
                origin = None
            if cors and (origin == '*' or isinstance(origin, (list, tuple)) and '*' in origin):
                add(node, 'cors', 'VS-06', 'CWE-942', '와일드카드 CORS 설정',
                    '공개 API인지 확인하고 인증 응답은 신뢰한 Origin만 허용하세요.', '*')
        if function.endswith('.set_cookie'):
            # Explicit **kwargs may contain the flags; absence cannot be established there.
            unknown_flags = any(k.arg is None for k in node.keywords) or len(node.args) > 2 or any(
                isinstance(arg, ast.Starred) for arg in node.args)
            missing = [k for k in ('secure', 'httponly') if literal.get(k) is False or
                       (k not in kwargs and not unknown_flags)]
            if ('samesite' not in kwargs and not unknown_flags) or ('samesite' in literal and literal['samesite'] is None):
                missing.append('samesite')
            if missing:
                cwe = 'CWE-614' if 'secure' in missing else 'CWE-1004' if 'httponly' in missing else 'CWE-1275'
                add(node, 'cookie-flags', 'VS-06', cwe, '쿠키 보호 속성 확인 필요',
                    '인증 쿠키인지 확인하고 Secure·HttpOnly·SameSite 속성을 명시하세요.', ', '.join(missing))
                hits[-1].severity = Severity.MEDIUM
    return hits, summary
