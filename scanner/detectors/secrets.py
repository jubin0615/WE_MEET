"""Shared credential recognition for detection and model redaction."""
import ast
import base64
import json
import re

from tree_sitter import Language, Parser
import tree_sitter_java

from ..normalize import RawHit, code_identity
from ..models import Severity

SECRET = re.compile(r"""(?ix)["']?\b[\w.-]*(?:api[_-]?key|secret|password|token)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']""")
KEY = re.compile(r"(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}"
                 r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|[sr]k_live_[A-Za-z0-9]{16,}"
                 r"|sb_secret_[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
                 r"|[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/'\"]+:[^\s@'\"]+@[^\s'\"]+"
                 r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)")
SENSITIVE = re.compile(r"api.?key|secret|password|token|credential|authorization|private.?key|(?:^|_)key$|(?:^|_)(?:pwd|dsn)$", re.I)
ASSIGNMENT = re.compile(r'''["']?([\w.-]+)["']?\s*[:=]\s*["']([^"'\r\n]*)["']''')
PLACEHOLDER = re.compile(r"^(?:your[-_ ].*|x{3,}|example|test|dummy|changeme|placeholder|<.*>|\$\{.*\})$", re.I)
SIGNING = re.compile(r"(?:^|_)(?:secret_key|jwt_secret|session_secret)$")
# A lowercase word or slug ("department", "family-lounge") is an identifier unless the line names a real credential.
SLUG = re.compile(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*")
# People choose passwords, so even word-like values count there; keys and tokens are machine-generated.
PASSWORDISH = re.compile(r"(?:^|_)(?:password|passwd|pwd|pass)$")
METADATA = re.compile(r"(?:^|_)(?:name|label|field|header|prefix|suffix|pattern|regex|env|message|description|property|param|attribute|path|url|id|type|format|length|error|code)s?$")
WORD = re.compile(r"(?:[A-Za-z][a-z]+\d*|[A-Z]{2,}\d*|[vV]?\d+)")
CREDENTIAL_NAME = re.compile(r"(?:^|_)(?:key|apikey|secret|password|passwd|pwd|token|credential|authorization|dsn)s?(?:_|$)")
IDENTIFIER_KEY = re.compile(r"(?:^|_)(?:idempotency|deduplication|cache|object|order|partition|primary|foreign|sort|map|field|lookup|translation)_key$")
TOKEN_REFERENCE = re.compile(r"(?:^|_)token(?:_contract)?(?:_address)?$")
AUTH_KEY = re.compile(r"(?:^|_)(?:api|access|auth|encryption|private|signing|secret|client)_key$")


def java_dynamic_parts(source):
    """Positions of literal operands in a concatenation with a nonliteral operand."""
    def is_concat(node):
        op = node.child_by_field_name('operator') if node.type == 'binary_expression' else None
        return op is not None and op.text == b'+'

    root = Parser(Language(tree_sitter_java.language())).parse(source.encode()).root_node
    pending = [root]
    positions = set()
    while pending:
        node = pending.pop()
        if not is_concat(node):
            pending.extend(node.named_children)
            continue
        operands, literals, dynamic = [node], [], False
        while operands:
            part = operands.pop()
            if is_concat(part):
                operands.extend(c for c in part.named_children if not c.is_extra)
            elif part.type == 'parenthesized_expression':
                operands.extend(c for c in part.named_children if not c.is_extra)
            elif part.type == 'string_literal':
                literals.append(tuple(part.start_point))
            else:
                dynamic = True
                pending.extend(part.named_children)
        if dynamic:
            positions.update(literals)
    return positions


def assignment_name(owner):
    # Normalize spelling for decisions only; keep the original name for evidence and redaction.
    name = re.sub(r'([A-Z])([A-Z][a-z])', r'\1_\2', owner)
    name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name)
    return re.sub(r'[^a-zA-Z0-9]+', '_', name).strip('_').lower()


def mask_name(owner):
    # Model context stays conservative even when a literal does not justify a finding.
    return SENSITIVE.search(owner) or CREDENTIAL_NAME.search(assignment_name(owner))


def looks_random(value):
    """Reject identifiers made of readable words before accepting mixed character classes."""
    kinds = sum(bool(re.search(p, value)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
    if len(value) < 16 or kinds < 2 or re.search(r"\s", value):
        return False
    if re.fullmatch(r'[0-9a-fA-F]{24,}', value):
        return True
    if SLUG.fullmatch(value):
        # Lowercase words joined by -_. ("esg-strategy-2026") are names; a long mixed chunk is a hex/base32 token.
        return any(len(part) >= 12 and re.search("[a-z]", part) and re.search("[0-9]", part)
                   for part in re.split(r"[-_.]", value))
    # Field names can be long, mixed-case and versioned, e.g. detailEvaluationErrorV2.
    # Split acronym boundaries too (HTTPResponse); require every component to look like a word.
    parts = re.split(r'[-_.:/]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', value)
    if all(WORD.fullmatch(part) or part.lower() in {'v', 'a', 'i'} for part in parts):
        return False
    return True
# Lockfiles pair package names ("js-tokens") with versions; only vendor key formats count there.
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "pipfile.lock", "uv.lock", "cargo.lock", "composer.lock", "gemfile.lock", "go.sum"}
# Tests, examples and seed data hold throwaway values; they stay visible but do not raise the risk score.
SAMPLE_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|specs?|fixtures?|seeds?|examples?|samples?|mocks?|__mocks__)/"
                         r"|(?:^|/)(?:test_[^/]*|[^/]*_test\.py|[^/]*\.(?:test|spec)\.[jt]sx?)$", re.I)


def mask(text, values=()):
    """Keep the first four characters so a person can recognise the value; never the rest."""
    for value in sorted(set(values) | set(KEY.findall(text)), key=len, reverse=True):
        if value:
            prefix = value[:4] if len(value) >= 8 else ""
            text = text.replace(value, prefix + "••••")
    return text


def env_fix(name, line, value, var):
    """A diff that reads the value from the environment instead of the source, when the language is known."""
    env = re.sub(r"[^A-Za-z0-9]+", "_", var).strip("_").upper()
    if name.endswith(".py"):
        lookup = f'os.environ["{env}"]'
    elif name.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        lookup = f"process.env.{env}"
    else:
        return ""
    for quote in ('"', "'", "`"):
        literal = quote + value + quote
        if env and literal in line:
            return "\n".join([f"--- a/{name}", f"+++ b/{name}", "-" + mask(line, [value]),
                              "+" + line.replace(literal, lookup, 1)])
    return ""


CLIENT_BINDING = re.compile(r'''(?:^|\b(?:const|let|var)\s+)([\w]+)\s*=\s*(["'\x60])([^"'\x60\r\n]+)\2''', re.M)
ENV_BINDING = re.compile(r'^[ \t]*(?:export[ \t]+)?(\w+)[ \t]*=[ \t]*(.*)$', re.M)


def hidden_values(source, name=""):
    values = set(KEY.findall(source))
    values.update(m.group(2) for m in ASSIGNMENT.finditer(source)
                  if mask_name(m.group(1)) and m.group(2))
    if name.rsplit("/", 1)[-1] in {".env.example", ".env.sample"}:
        for env in ENV_BINDING.finditer(source):
            if PUBLIC_SERVER_VAR.fullmatch(env[1]) and env[2].strip():
                values.add(env[2].strip())
                values.add(env[2].split("#", 1)[0].strip().strip('"\''))
    if client_module(name, source):
        values.update(m[3] for m in CLIENT_BINDING.finditer(source)
                      if PUBLIC_SERVER_VAR.fullmatch("VITE_" + assignment_name(m[1]).upper()) or
                      PUBLIC_SERVER_VAR.fullmatch(m[1]))
    return values


PUBLIC_SERVER_VAR = re.compile(r'\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|VUE_APP_)(?:[A-Z0-9]+_)*'
    r'(?:SERVICE_ROLE(?:_KEY)?|SECRET(?:_KEY)?|PRIVATE_KEY|DATABASE_URL|ADMIN_TOKEN|OPENAI_API_KEY|'
    r'ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET_KEY|PASSWORD)\b')
CLIENT_REMEDIATION = '서버 전용 값을 서버에서만 읽고 필요한 동작을 인증된 API로 제공하세요. 배포 번들에 값이 들어갔다면 키를 교체하세요.'


def client_module(name, content):
    return name.endswith(('.vue', '.svelte')) or (
        name.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs')) and (
            re.search(r'(?:^|/)(?:frontend|client|browser)/', name, re.I) or
            re.match(r'''^\s*["']use client["']\s*(?:;|$)''', content, re.M)))


def supabase_role(value):
    try:
        payload = value.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        return claims.get('role') if claims.get('iss') == 'supabase' or claims.get('role') == 'service_role' else None
    except (ValueError, IndexError, UnicodeError, AttributeError):
        return None


def detect(name, content, hidden=None):
    hits = {}
    if hidden is None:
        hidden = set()
    hidden.update(hidden_values(content, name))
    lines = content.splitlines()
    sample = bool(SAMPLE_PATH.search(name))
    lockfile = name.rsplit("/", 1)[-1].lower() in LOCKFILES
    client = client_module(name, content)
    if name.rsplit("/", 1)[-1] in {".env.example", ".env.sample"}:
        for line, text in enumerate(lines, 1):
            env = ENV_BINDING.match(text)
            if env and PUBLIC_SERVER_VAR.fullmatch(env[1]):
                value = env[2].strip()
                if value:
                    hidden.add(value)
                hits[(line, "vs-client-server-key")] = RawHit("secrets", "vs-client-server-key", name, line,
                    "CWE-522", ["CI-05"], "공개 환경변수 예제에 서버 전용 키 이름 선언", CLIENT_REMEDIATION,
                    Severity.LOW, identity=env[1], evidence=f"{env[1]} · 값 생략")

    def add(line, value, known=False, listed=False, why="인증정보 이름의 변수에 들어 있는 문자열", var=None,
            owner=""):
        """known: a vendor key format (sk-live…, AKIA…), a leak wherever it sits.
        listed: an item of a tuple/list/set, where plain words are vocabulary, not credentials."""
        target = assignment_name(var or owner)
        signing = bool(SIGNING.search(target))
        if not value or (PLACEHOLDER.fullmatch(value) and not signing):
            return
        if not signing and len(value) < 8:
            return
        if not (known or signing):
            if not CREDENTIAL_NAME.search(target) or METADATA.search(target):
                return
            if IDENTIFIER_KEY.search(target):
                return
            if re.fullmatch(r'0x[0-9a-fA-F]{40}', value) and TOKEN_REFERENCE.search(target):
                return
            if target.endswith('password_hash') and value.startswith(('$2a$', '$2b$', '$2y$', '$argon2')):
                # A hash is not evidence of an embedded plaintext login password.
                return
            if (target == 'key' or target.endswith('_key')) and not AUTH_KEY.search(target):
                chunks = re.findall(r'[A-Za-z0-9]{10,}', value)
                if not (re.fullmatch(r'[0-9a-fA-F]{24,}', value) or any(
                    re.search('[a-z]', c) and re.search('[A-Z]', c) and re.search('[0-9]', c) for c in chunks
                )):
                    return
            if target.endswith('_key') and assignment_name(value) == target.removesuffix('_key'):
                return
            if listed and SLUG.fullmatch(value):
                return  # vocabulary in a tuple/list, e.g. ("department", "category")
            if not PASSWORDISH.search(target) and not looks_random(value):
                return  # placeholders such as api_key="codex-oauth" or "your-api-key" are not keys
        weak = signing and len(value) < 32
        hidden.add(value)
        rule = 'weak-signing-key' if weak else 'literal-token'
        codes = ['CI-16'] if weak else ['CI-05']
        title = '약한 고정 서명키' if weak else '소스에 포함된 인증정보 후보'
        role = supabase_role(value)
        if role == 'anon' or value.startswith('sb_publishable_'):
            return
        critical = role == 'service_role' or value.startswith('sb_secret_')
        severity = Severity.CRITICAL if critical else Severity.HIGH
        if critical:
            codes += ['V-04']; title = '권한이 높은 Supabase 서버 키 노출'
        elif sample and not known:
            severity, title = Severity.INFO, '테스트·예제 파일의 인증정보 후보'
        previous = hits.get((line, rule))
        stronger = previous and list(Severity).index(previous.severity) < list(Severity).index(severity)
        if stronger or (previous and previous.severity == severity and (previous.fix or not var)):
            return  # keep the stronger reading of the same line, or the one that can offer a fix
        hit = RawHit('secrets', rule, name, line, 'CWE-321' if weak else 'CWE-798',
            codes, title, '인증에 쓰이는 값인지 사용처를 확인하세요. 실제 자격증명이면 교체하고 환경변수나 비밀 저장소에서 읽으세요.',
            severity, impact=f"{why}을 발견했습니다. 인증에 사용된다면 저장소를 읽을 수 있는 사람이 해당 값을 사용할 수 있습니다.",
            fix=env_fix(name, lines[line - 1], value, var) if var else "",
            identity=code_identity(content, line, name.endswith('.py')))
        hit.secret = value  # lets the evidence excerpt hide exactly this value
        hits[(line, rule)] = hit
    dynamic_parts = None
    for line, text in enumerate(lines, 1):
        for binding in CLIENT_BINDING.finditer(text):
            owner, value = binding[1], binding[3]
            public = PUBLIC_SERVER_VAR.fullmatch(owner)
            if not (public or client and PUBLIC_SERVER_VAR.fullmatch("VITE_" + assignment_name(owner).upper())):
                continue
            hidden.add(value)
            if len(value) < 8 or PLACEHOLDER.fullmatch(value) or value.startswith("sb_publishable_"):
                continue
            hits[(line, "vs-client-server-key")] = RawHit("secrets", "vs-client-server-key", name, line,
                "CWE-798", ["CI-05"], "클라이언트 코드에 서버 전용 키 값 포함", CLIENT_REMEDIATION,
                Severity.HIGH, identity=owner)
        for match in KEY.finditer(text):
            add(line, match.group(), known=True, why="공급자 키 형식의 값")
        if lockfile:
            continue
        for match in ASSIGNMENT.finditer(text):
            if CREDENTIAL_NAME.search(assignment_name(match.group(1))):
                if name.endswith('.java'):
                    if dynamic_parts is None:
                        dynamic_parts = java_dynamic_parts(content)
                    quote_col = len(text[:match.start(2) - 1].encode())
                    if (line - 1, quote_col) in dynamic_parts:
                        continue
                add(line, match.group(2),
                    why=f"'{match.group(1)[:40]}'에 대입된 값", var=match.group(1))
    if name.endswith('.py'):
        try:
            tree = ast.parse(content)
            listed = {id(item) for node in ast.walk(tree) if isinstance(node, (ast.Tuple, ast.List, ast.Set))
                      for item in node.elts}
            # The name a value is assigned to, even when the value sits on a later line.
            owner = {}
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    names = " ".join(ast.unparse(t) for t in targets)
                    owner.update((id(c), names) for c in ast.walk(node.value))
                elif isinstance(node, ast.keyword) and node.arg:
                    owner.update((id(c), node.arg) for c in ast.walk(node.value))
                elif isinstance(node, ast.Dict):
                    for key, item in zip(node.keys, node.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            owner.update((id(c), key.value) for c in ast.walk(item))
            for node in sensitive_literals(tree):
                if isinstance(node, ast.Constant):
                    if node.value:
                        hidden.add(node.value)
                    add(node.lineno, node.value, listed=id(node) in listed, owner=owner.get(id(node), ""))
        except (SyntaxError, ValueError):
            pass
    # A weak signing key is the more specific explanation for the same literal.
    for line, rule in list(hits):
        if (rule == 'weak-signing-key' and (line, 'literal-token') in hits and
                hits[(line, 'literal-token')].secret == hits[(line, rule)].secret):
            hits.pop((line, 'literal-token'), None)
    for hit in hits.values():
        if client and hit.fix:
            hit.fix = ""
            hit.remediation = CLIENT_REMEDIATION
        if hit.fix:
            hit.fix = mask(hit.fix, hidden)
    return list(hits.values())
def sensitive_literals(tree):
    """Find literal values under credential assignments, dict keys and keyword arguments."""
    literals = []
    for node in ast.walk(tree):
        values = []
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(mask_name(ast.unparse(t)) for t in targets) and node.value is not None:
                values.append(node.value)
        if isinstance(node, ast.keyword) and node.arg and mask_name(node.arg):
            values.append(node.value)
        if isinstance(node, ast.Dict):
            values.extend(v for k, v in zip(node.keys, node.values)
                          if isinstance(k, ast.Constant) and isinstance(k.value, str) and mask_name(k.value))
        for value in values:
            pending = [value]
            while pending:
                candidate = pending.pop()
                if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                    literals.append(candidate)
                elif isinstance(candidate, ast.JoinedStr):
                    literals.append(candidate)
                    pending.extend(candidate.values)
                elif isinstance(candidate, (ast.BinOp, ast.Tuple, ast.List)):
                    pending.extend(ast.iter_child_nodes(candidate))
                elif (isinstance(candidate, ast.Call) and isinstance(candidate.func, ast.Attribute)
                      and (candidate.func.attr == "getenv" or
                           candidate.func.attr == "get" and ast.unparse(candidate.func.value).endswith("environ"))):
                    pending.extend(candidate.args[1:2])
                    pending.extend(k.value for k in candidate.keywords if k.arg == "default")
    return literals
