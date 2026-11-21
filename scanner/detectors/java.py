"""Bounded source-only analysis of Java method calls and Spring MVC routes."""

from collections import defaultdict
from dataclasses import dataclass
import re

from tree_sitter import Language, Parser
import tree_sitter_java

from ..normalize import RawHit, code_identity


def value(node):
    return node.text.decode('utf-8') if node is not None else ''


def field(node, name):
    return node.child_by_field_name(name)


def children(node):
    return [c for c in node.named_children if not c.is_extra] if node is not None else []


def named(node, kind):
    return [c for c in children(node) if c.type == kind]


SPRING = {
    **dict.fromkeys(('RequestParam', 'RestController', 'RequestMapping', 'PostMapping', 'GetMapping',
                     'PutMapping', 'DeleteMapping', 'PatchMapping'), 'org.springframework.web.bind.annotation'),
    'Controller': 'org.springframework.stereotype', 'Order': 'org.springframework.core.annotation',
    'Configuration': 'org.springframework.context.annotation', 'Bean': 'org.springframework.context.annotation',
    'EnableMethodSecurity': 'org.springframework.security.config.annotation.method.configuration',
    'PreAuthorize': 'org.springframework.security.access.prepost',
}


def annotations(node, imports, stars):
    tags = {}
    for mod in named(node, 'modifiers'):
        for a in children(mod):
            if a.type not in ('annotation', 'marker_annotation'):
                continue
            full = value(field(a, 'name'))
            key = full.split('.')[-1]
            pkg = SPRING.get(key)
            if pkg and full != pkg + '.' + key:
                if '.' in full or imports.get(key, pkg + '.' + key if pkg in stars else '') != pkg + '.' + key:
                    continue
            tags[key] = field(a, 'arguments')
    return tags


@dataclass
class Method:
    file: str
    owner: str
    node: object
    params: list
    types: dict
    imports: dict
    stars: list

    def tags(self, node):
        return annotations(node, self.imports, self.stars)

    def resolve(self, typename, known):
        if '.' in typename:
            return typename
        if typename in self.imports:
            return self.imports[typename]
        package = self.owner.rpartition('.')[0]
        local = f'{package}.{typename}' if package else typename
        if local in known:
            return local
        matches = [p + '.' + typename for p in self.stars if p + '.' + typename in known]
        return matches[0] if len(matches) == 1 else local


JDBC = {
    'org.springframework.jdbc.core.JdbcTemplate': {'query', 'queryForList', 'queryForObject', 'queryForMap', 'update', 'execute'},
    'java.sql.Statement': {'execute', 'executeUpdate', 'executeQuery'},
    'java.sql.Connection': {'prepareStatement'},
}
SERVLET = {'jakarta.servlet.http.HttpServletRequest', 'javax.servlet.http.HttpServletRequest'}


def sql_flows(methods, classes, implementations):
    by_signature = defaultdict(list)
    for m in methods:
        by_signature[m.owner, value(field(m.node, 'name')), len(m.params)].append(m)
    known = set(classes) | set(JDBC) | SERVLET
    hits = {}
    partial = set()

    def visit(method, incoming, stack, budget):
        budget[0] -= 1
        if budget[0] < 0 or len(stack) >= 16 or method.node in stack:
            partial.add(method.file)
            return ()
        stack = (*stack, method.node)
        types = method.types.copy()
        env = {}
        location = {'file': method.file, 'line': method.node.start_point.row + 1,
                    'method': value(field(method.node, 'name'))}
        for p, trace in zip(method.params, incoming):
            name = value(field(p, 'name'))
            env[name] = (*trace, location) if trace else ()
            if 'RequestParam' in method.tags(p):
                env[name] = (location,)

        def expr(n):
            if n is None:
                return ()
            if n.type == 'identifier':
                return env.get(value(n), ())
            if n.type == 'binary_expression' and value(field(n, 'operator')) != '+':
                return ()
            if n.type in ('binary_expression', 'parenthesized_expression', 'cast_expression'):
                traces = [expr(c) for c in children(n)]
                return next((t for t in traces if t), ())
            if n.type == 'assignment_expression':
                trace = expr(field(n, 'right'))
                name = value(field(n, 'left'))
                if value(field(n, 'operator')) == '+=':
                    trace = env.get(name) or trace
                env[name] = trace
                return trace
            if n.type != 'method_invocation':
                return ()
            obj = value(field(n, 'object'))
            receiver = types.get(obj, '') if obj not in ('', 'this') else method.owner
            owner = method.resolve(receiver, known)
            name = value(field(n, 'name'))
            args = [expr(a) for a in children(field(n, 'arguments'))]
            if owner in SERVLET and name == 'getParameter':
                return (location,)
            if name in JDBC.get(owner, ()) and args and args[0] and len(args[0]) > 1:
                line = n.start_point.row + 1
                hits[method.file, line] = RawHit('java', 'vs-java-sql-flow', method.file, line, 'CWE-89',
                    'VS-05', '메서드 호출을 거쳐 요청값이 JDBC SQL 본문에 도달',
                    'SQL 본문을 고정하고 요청값은 바인딩 인자로 전달하세요.', trace=list(args[0]))
            targets = by_signature.get((owner, name, len(args)), ())
            if not targets and owner in implementations:
                targets = [candidate for impl in implementations[owner]
                           for candidate in by_signature.get((impl, name, len(args)), ())]
            if any(args) and len(targets) > 1:
                partial.update(t.file for t in targets)
            if any(args) and len(targets) == 1:
                trace = visit(targets[0], args, stack, budget)
                return (*trace, location) if trace else ()
            return ()

        returns = []

        def statement(stmt):
            if stmt.type == 'block':
                for child in children(stmt):
                    if not statement(child):
                        return False
                return True
            if stmt.type == 'return_statement':
                returns.append(expr(next(iter(children(stmt)), None)))
                return False
            if stmt.type == 'throw_statement':
                return False
            if stmt.type == 'if_statement':
                expr(field(stmt, 'condition'))
                initial, declarations = env.copy(), types.copy()
                live = []
                for arm in ('consequence', 'alternative'):
                    env.clear()
                    env.update(initial)
                    types.clear()
                    types.update(declarations)
                    branch = field(stmt, arm)
                    if branch is None or statement(branch):
                        live.append(env.copy())
                types.clear()
                types.update(declarations)
                env.clear()
                for state in live:
                    for key, trace in state.items():
                        if key in initial:
                            env[key] = env.get(key) or trace
                return bool(live)
            if stmt.type == 'local_variable_declaration':
                for d in named(stmt, 'variable_declarator'):
                    name = value(field(d, 'name'))
                    types[name] = value(field(stmt, 'type'))
                    env[name] = expr(field(d, 'value'))
            elif stmt.type == 'expression_statement':
                expr(children(stmt)[0])
            else:
                # Loops and exception edges are outside this bounded analysis.
                partial.add(method.file)
                return False
            return True

        body = field(method.node, 'body')
        if body is not None:
            statement(body)
        return next((t for t in returns if t), ())

    for m in methods:
        if any('RequestParam' in m.tags(p) for p in m.params) or 'getParameter' in value(field(m.node, 'body')):
            try:
                visit(m, [()] * len(m.params), (), [256])
            except RecursionError:
                partial.add(m.file)
    return list(hits.values()), partial


def detect(contents):
    # Test-only beans and methods are absent from the deployed application's classpath.
    groups = defaultdict(dict)
    for path, source in contents.items():
        if not path.endswith('.java'):
            continue
        match = re.search(r'(?:^|/)src/([^/]+)/java/', path)
        group = match[1] if match else 'main'
        groups[group][path] = source
    hits, routes, partial = [], [], set()
    for sources in groups.values():
        found, mapped, incomplete = detect_source_set(sources)
        hits.extend(found)
        routes.extend(mapped)
        partial.update(incomplete)
    return hits, routes, partial


def detect_source_set(contents):
    parser = Parser(Language(tree_sitter_java.language()))
    methods, classes, partial = [], set(), set()
    controllers, chains, enabled = [], [], False
    interfaces = []
    for file, source in contents.items():
        root = parser.parse(source.encode()).root_node
        if root.has_error:
            partial.add(file)
            continue
        packages = named(root, 'package_declaration')
        package = value(children(packages[0])[-1]) if packages else ''
        imports, stars = {}, []
        for imp in named(root, 'import_declaration'):
            path = value(children(imp)[0])
            if named(imp, 'asterisk'):
                stars.append(path)
            else:
                imports[path.split('.')[-1]] = path
        for iface in named(root, 'interface_declaration'):
            classes.add('.'.join(filter(None, [package, value(field(iface, 'name'))])))
        for cls in named(root, 'class_declaration'):
            owner = '.'.join(filter(None, [package, value(field(cls, 'name'))]))
            classes.add(owner)
            body = field(cls, 'body')
            tags = annotations(cls, imports, stars)
            if ('Configuration' in tags and 'EnableMethodSecurity' in tags
                    and not any(k.startswith('Conditional') or k == 'Profile' for k in tags)
                    and value(tags['EnableMethodSecurity']) in ('', '()')):
                enabled = True
            fields = {}
            for decl in named(body, 'field_declaration'):
                for var in named(decl, 'variable_declarator'):
                    key = value(field(var, 'name'))
                    fields[key] = fields['this.' + key] = value(field(decl, 'type'))
            for index, node in enumerate(named(body, 'method_declaration')):
                params = children(field(node, 'parameters'))
                types = {value(field(p, 'name')): value(field(p, 'type')) for p in params}
                method = Method(file, owner, node, params, fields | types, imports, stars)
                methods.append(method)
                if index == 0:
                    for listing in named(field(cls, 'interfaces'), 'type_list'):
                        interfaces.append((method, [value(t) for t in children(listing)]))
                if {'RestController', 'Controller'} & tags.keys():
                    controllers.append((method, tags))
                chain_type = 'org.springframework.security.web.SecurityFilterChain'
                if method.resolve(value(field(node, 'type')), {chain_type}) == chain_type and 'Bean' in method.tags(node):
                    flags = tags.keys() | method.tags(node).keys()
                    conditional = any(k.startswith('Conditional') or k == 'Profile' for k in flags)
                    chains.append((method, conditional))
    implementations = defaultdict(set)
    for method, names in interfaces:
        for iface in names:
            implementations[method.resolve(iface, classes)].add(method.owner)
    hits, incomplete = sql_flows(methods, classes, implementations)
    route_hits, rows = spring_routes(controllers, chains, enabled, partial)
    hits.extend(route_hits)
    for hit in hits:
        hit.identity = code_identity(contents[hit.file], hit.line)
    return hits, rows, partial | incomplete


def string_arg(n):
    text = value(n)
    return text[1:-1] if n.type == 'string_literal' and '\\' not in text else None


def mapping(args):
    items = children(args)
    if not items:
        return ''
    for item in items:
        if item.type == 'element_value_pair':
            if value(field(item, 'key')) not in ('path', 'value'):
                continue
            item = field(item, 'value')
        return string_arg(item)
    return ''


def matcher(path, pattern):
    if pattern.endswith('/**') and not re.search(r'[*?{}]', pattern[:-3]):
        return path == pattern[:-3] or path.startswith(pattern[:-3] + '/')
    if re.search(r'[*?{}]', pattern + path):
        return None
    return path == pattern


def authorize_chain(node, path, verb):
    """Read one ordered, literal HttpSecurity DSL. Unknown DSL keeps the route unresolved."""
    body = children(field(node, 'body'))
    if not body or body[-1].type != 'return_statement':
        return None
    http = [value(field(p, 'name')) for p in children(field(node, 'parameters'))
            if value(field(p, 'type')).split('.')[-1] == 'HttpSecurity']
    if len(http) != 1:
        return None
    declarations = []
    for stmt in body:
        if stmt.type not in ('return_statement', 'expression_statement') or not children(stmt):
            return None
        call = children(stmt)[0]
        chain = []
        while call.type == 'method_invocation':
            chain.append((value(field(call, 'name')), children(field(call, 'arguments'))))
            call = field(call, 'object')
            if call is None:
                return None
        if value(call) != http[0]:
            return None
        declarations.extend(reversed(chain))
    if not declarations or declarations[-1][0] != 'build':
        return None
    if sum(name == 'securityMatcher' for name, _ in declarations) > 1:
        return None
    rules = []
    for name, args in declarations:
        if name == 'build':
            continue
        if name == 'securityMatcher' and len(args) == 1 and string_arg(args[0]) is not None:
            applies = matcher(path, string_arg(args[0]))
            if applies is not True:
                return 'outside' if applies is False else None
            continue
        if name != 'authorizeHttpRequests' or len(args) != 1 or args[0].type != 'lambda_expression':
            return None
        fn = args[0]
        expr = field(fn, 'body')
        expressions = [expr]
        if expr.type == 'block':
            if any(s.type != 'expression_statement' for s in children(expr)):
                return None
            expressions = [children(s)[0] for s in children(expr)]
        for expr in expressions:
            pairs = []
            while expr.type == 'method_invocation':
                operation = (value(field(expr, 'name')), children(field(expr, 'arguments')))
                selector = field(expr, 'object')
                if selector is None or selector.type != 'method_invocation':
                    return None
                pairs.append((value(field(selector, 'name')), children(field(selector, 'arguments')), *operation))
                expr = field(selector, 'object')
                if expr is None:
                    return None
            if value(expr) != value(field(fn, 'parameters')):
                return None
            rules.extend(reversed(pairs))
    for selector, args, action, values in rules:
        if selector == 'requestMatchers':
            if args and re.fullmatch(r'HttpMethod\.[A-Z]+', value(args[0])):
                if verb == 'ANY':
                    return None
                if value(args[0]).split('.')[-1] != verb:
                    continue
                args = args[1:]
            paths = [string_arg(arg) for arg in args]
            if not paths or None in paths:
                return None
            matches = [matcher(path, p) for p in paths]
            if True not in matches:
                if None in matches:
                    return None
                continue
        elif selector != 'anyRequest' or args:
            return None
        if action in ('permitAll', 'authenticated', 'denyAll') and not values:
            return action
        if len(values) == 1 and (action, string_arg(values[0])) in {
            ('hasRole', 'ADMIN'), ('hasAuthority', 'ROLE_ADMIN')
        }:
            return 'admin'
        return None
    return None


def spring_routes(controllers, chains, enabled, partial):
    hits, rows = [], []
    ordered = {}
    for cfg, conditional in chains:
        tags = cfg.tags(cfg.node)
        order = value(tags.get('Order')).strip('() ') if 'Order' in tags else '2147483647'
        if conditional or not re.fullmatch(r'-?\d{1,10}', order) or int(order) in ordered:
            ordered.clear()
            break
        ordered[int(order)] = cfg
    policies = [] if partial else [ordered[n] for n in sorted(ordered)]
    verbs = {'GetMapping': 'GET', 'PostMapping': 'POST', 'PutMapping': 'PUT',
             'DeleteMapping': 'DELETE', 'PatchMapping': 'PATCH', 'RequestMapping': 'ANY'}
    for method, cls in controllers:
        tags = method.tags(method.node)
        for annotation in verbs.keys() & tags.keys():
            prefix, suffix = mapping(cls.get('RequestMapping')), mapping(tags[annotation])
            if prefix is None or suffix is None:
                partial.add(method.file)
                continue
            path = '/' + '/'.join(p.strip('/') for p in (prefix, suffix) if p.strip('/'))
            if '${' in path or '#{' in path:
                partial.add(method.file)
                continue
            verb = verbs[annotation]
            if verb == 'ANY':
                for pair in named(tags[annotation], 'element_value_pair'):
                    if value(field(pair, 'key')) == 'method':
                        enum = value(field(pair, 'value'))
                        if re.fullmatch(r'RequestMethod\.[A-Z]+', enum):
                            verb = enum.split('.')[-1]
            policy, evidence = None, []
            for cfg in policies:
                policy = authorize_chain(cfg.node, path, verb)
                if policy != 'outside':
                    evidence.append({'file': cfg.file, 'line': cfg.node.start_point.row + 1,
                                     'method': value(field(cfg.node, 'name'))})
                    break
                policy = None
            guards = tags if 'PreAuthorize' in tags else cls
            method_rule = children(guards.get('PreAuthorize'))
            if any(k in tags or k in cls for k in ('Secured', 'RolesAllowed', 'DenyAll')) and policy not in ('admin', 'denyAll'):
                policy = None
            if method_rule:
                expression = string_arg(method_rule[0])
                if enabled and expression == 'denyAll()':
                    policy = 'denyAll'
                elif enabled and expression in ("hasRole('ADMIN')", "hasAuthority('ROLE_ADMIN')") and policy != 'denyAll':
                    policy = 'admin'
                elif enabled and expression == 'isAuthenticated()' and policy in ('permitAll', 'authenticated'):
                    policy = 'authenticated'
                elif expression != 'permitAll()' and policy not in ('admin', 'denyAll'):
                    policy = None
            admin = bool(re.search(r'/(?:admin|internal|manage)(?:/|$)', path, re.I))
            line = field(method.node, 'name').start_point.row + 1
            note = '정적 정책 참조 · 활성 프로필 및 실제 접근 권한은 수동 확인'
            rows.append({'file': method.file, 'line': line, 'path': path, 'method': verb,
                         'handler': value(field(method.node, 'name')), 'auth_guard': policy or '수동 확인',
                         'admin_guard': policy in ('admin', 'denyAll'), 'note': note, 'policy_source': evidence})
            if admin and policy in ('permitAll', 'authenticated'):
                hits.append(RawHit('java', 'vs-java-admin-policy', method.file, line, 'CWE-862', 'VS-02',
                    '관리자 경로의 Spring 인가 정책 확인 필요',
                    '해당 경로의 역할 제한과 핸들러 내부 검사를 확인하세요.',
                    impact=f'필터 체인과 메서드 보안 단서에서 확인한 정책은 {policy}입니다. {note}', trace=evidence))
            elif admin and policy is None:
                partial.add(method.file)
    return hits, rows
