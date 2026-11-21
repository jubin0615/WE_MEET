"""Bounded route inventory; missing guards are review candidates, never proof."""

import ast
import re

from ..normalize import RawHit, code_identity

GUARD = re.compile(r'\b(?:login_required|jwt_required|permission_classes|get_current_user|require_auth|requireAuth|isAuthenticated|authenticate|authMiddleware)\b')
ADMIN_GUARD = re.compile(r'\b(?:admin_required|require_admin|requireAdmin|isAdmin)\b')
JS_OWNER = re.compile(r'\b(?:user_id|owner_id|ownerId|userId)\s*:\s*req\.user\.(?:id|_id)\s*(?=[,}])')
DB = re.compile(r'\.(?:execute|query|filter|get_or_404|findOne|findUnique|findById|raw)\s*\(')
ADMIN = re.compile(r'/(?:admin|internal|manage|dashboard)(?:/|$)', re.I)
JS_TOKENS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|`(?:\\.|[^`\\])*`')


def owner_filtered_return(node):
    """Recognize direct Python query chains. Other authorization shapes need review."""
    call = node.value
    while isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
        if call.func.attr in {'filter', 'filter_by', 'get', 'get_or_404'}:
            for kw in call.keywords:
                if kw.arg in {'owner_id', 'user_id'} and ast.unparse(kw.value) in {
                    'current_user.id', 'request.user.id', 'request.user.pk'
                }:
                    return True
            for arg in call.args:
                if (isinstance(arg, ast.Compare) and len(arg.ops) == 1 and isinstance(arg.ops[0], ast.Eq)
                        and isinstance(arg.left, ast.Attribute) and arg.left.attr in {'owner_id', 'user_id'}
                        and ast.unparse(arg.comparators[0]) in {'current_user.id', 'request.user.id', 'request.user.pk'}):
                    return True
        if call.func.attr not in {'filter', 'filter_by', 'first', 'all', 'one', 'one_or_none'}:
            break
        call = call.func.value
    return False


def detect(name, content):
    rows = []
    if name.endswith('.py'):
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return [], []
        prefixes = {}
        global_guard = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
            any(isinstance(d, ast.Attribute) and d.attr == 'before_request' for d in n.decorator_list)
            for n in ast.walk(tree))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg in ('prefix', 'url_prefix') and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        for target in node.targets:
                            prefixes[ast.unparse(target)] = kw.value.value
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('register_blueprint', 'include_router') and node.args:
                for kw in node.keywords:
                    if kw.arg in ('prefix', 'url_prefix') and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        prefixes[ast.unparse(node.args[0])] = kw.value.value
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Do not let comments/docstrings pretend to be guards.
            body = ast.unparse(ast.Module(body=[n for n in node.body if not isinstance(n, ast.Expr)
                           or not isinstance(n.value, ast.Constant) or not isinstance(n.value.value, str)], type_ignores=[]))
            returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
            owner = bool(returns) and all(owner_filtered_return(n) for n in returns)
            body_guard = any(isinstance(n, ast.If) and
                isinstance(n.test, ast.UnaryOp) and isinstance(n.test.op, ast.Not) and
                ast.unparse(n.test.operand) in ('current_user.is_authenticated', 'user.is_authenticated') and
                any(isinstance(x, (ast.Return, ast.Raise)) for x in n.body) for n in node.body)
            for index, d in enumerate(node.decorator_list):
                if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute) or d.func.attr not in ('route', 'get', 'post', 'put', 'patch', 'delete'):
                    continue
                if not d.args or not isinstance(d.args[0], ast.Constant) or not isinstance(d.args[0].value, str):
                    continue
                # A router registers the callable produced by decorators below it.
                guards = {ast.unparse(w.func if isinstance(w, ast.Call) else w).split('.')[-1]
                          for w in node.decorator_list[index + 1:]}
                dependencies = [kw.value for kw in d.keywords if kw.arg == 'dependencies']
                for root in [node.args, *dependencies]:
                    for dep in ast.walk(root):
                        if (isinstance(dep, ast.Call) and ast.unparse(dep.func).split('.')[-1] in ('Depends', 'Security')
                                and dep.args and isinstance(dep.args[0], (ast.Name, ast.Attribute))):
                            guards.add(ast.unparse(dep.args[0]).split('.')[-1])
                admin_guard = any(ADMIN_GUARD.fullmatch(key) for key in guards)
                guard = admin_guard or body_guard or any(GUARD.fullmatch(key) for key in guards)
                path = prefixes.get(ast.unparse(d.func.value), '') + d.args[0].value
                methods = [d.func.attr.upper()] if d.func.attr != 'route' else ['GET']
                for kw in d.keywords:
                    if kw.arg == 'methods' and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [x.value.upper() for x in kw.value.elts if isinstance(x, ast.Constant) and isinstance(x.value, str)]
                for method in methods:
                    rows.append(row(name, node.lineno, path, method, node.name, body,
                                    '가드 참조' if guard else '전역 훅 확인 필요' if global_guard else None, admin_guard, owner))
    elif name.endswith(('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs')):
        # shortcut: literal Express handlers only; mounted routers/cross-file middleware remain unknown.
        masked = JS_TOKENS.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), content)
        for match in re.finditer(r'''\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*(["'])([^"']+)\2\s*,''', content):
            if not masked[match.start():match.start()+3].strip():
                continue
            depth, end = 1, match.end()
            while end < len(masked) and depth:
                depth += (masked[end] == '(') - (masked[end] == ')')
                end += 1
            if depth:
                continue
            arguments = masked[match.end():end - 1]
            before = masked[:match.start()]
            # A named middleware must precede another handler in this registration.
            middleware = re.match(r'(?:\s*[\w$.]+\s*,)*', arguments).group()
            admin_guard = bool(ADMIN_GUARD.search(middleware))
            guard = admin_guard or bool(GUARD.search(middleware))
            queries = list(DB.finditer(arguments))
            owner = bool(queries) and all(js_owner_filter(arguments[q.start():]) for q in queries)
            global_guard = bool(re.search(r'\bapp\.use\s*\([^;]*\b(?:auth|authenticate|requireAuth|authMiddleware)\b', before))
            rows.append(row(name, content.count('\n', 0, match.start())+1, match.group(3), match.group(1).upper(),
                            'Express handler', arguments, '가드 참조' if guard else '전역 미들웨어 확인 필요' if global_guard else None,
                            admin_guard, owner))
    hits = []
    for route in rows:
        if ADMIN.search(route['path']) and not route['admin_guard']:
            hits.append(RawHit('routes', 'vs-route-admin', name, route['line'], 'CWE-862', 'VS-02',
                '관리자 라우트의 관리자 권한 검사 미확인', '로그인한 일반 사용자도 차단되는지 핸들러와 상위 미들웨어의 역할 정책을 확인하세요.'))
        if route['path_params'] and route['db_access'] and not route['ownership_check']:
            hits.append(RawHit('routes', 'vs-route-idor', name, route['line'], 'CWE-639', 'VS-02',
                '객체 조회의 소유자 조건 미확인', '조회 대상과 현재 사용자·테넌트의 권한을 서버에서 대조하세요.'))
    for hit in hits:
        hit.identity = code_identity(content, hit.line, name.endswith('.py'))
    return hits, rows


def js_owner_filter(query):
    # Only a direct flat filter (Mongo) or a single flat where object (Prisma).
    match = re.match(r'\.(?:findOne|findUnique)\s*\(\s*\{\s*(?:(where)\s*:\s*\{)?'
                     r'([^{}()]*)\}(?(1)\s*\})\s*\)', query)
    if not match or '...' in match[2]:
        return False
    keys = [part.partition(':')[0].strip() for part in match[2].split(',')]
    return (all(key.isidentifier() for key in keys) and len(keys) == len(set(keys))
            and bool(JS_OWNER.search(match[2] + '}')))


def row(name, line, path, method, handler, body, guard, admin_guard, owner):
    return {'file': name, 'line': line, 'method': method, 'path': path, 'handler': handler,
            'auth_guard': guard, 'admin_guard': admin_guard, 'path_params': [next(x for x in match if x) for match in
                re.findall(r'<(?:\w+:)?(\w+)>|\{(\w+)\}|:(\w+)', path)],
            'db_access': bool(DB.search(body)), 'ownership_check': owner,
            'state_changing': method in ('POST', 'PUT', 'PATCH', 'DELETE'),
            'rate_limited': bool(re.search(r'limit|throttle', body)),
            'note': '정적 단서 · 상위 미들웨어와 실제 권한 정책은 수동 확인'}
