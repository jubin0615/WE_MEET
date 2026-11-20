"""Materialize eligible regular Git blobs at one commit without executing repo code."""

import io
import os
import re
import subprocess
from pathlib import Path, PureWindowsPath

from pathspec import GitIgnoreSpec


EXCLUDED = {".git", ".venv", "venv", "node_modules", "vendor", "dist", "build", "__pycache__"}
EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".toml",
              ".json", ".yaml", ".yml", ".ini", ".cfg", ".properties", ".txt",
              ".vue", ".svelte", ".astro", ".php", ".rb", ".go", ".java", ".kt", ".sql", ".rules", ".conf", ".jinja", ".j2"}
MAX_FILE = 1024 * 1024
MAX_TOTAL = 64 * MAX_FILE


class Files(list):
    def __init__(self, *, committed=True):
        super().__init__()
        self.committed = committed
        self.sensitive_files = []
        self.skipped = []
        self.excluded = set()


def sensitive_kind(path):
    name = path.name.lower()
    if name.startswith('.env') and name not in {'.env.example', '.env.sample'}:
        return 'dotenv'
    if path.suffix.lower() in {'.pem', '.key'} or name.startswith(('id_rsa', 'id_ed25519')):
        return 'private-key'
    if name == 'credentials.json' or name.startswith('serviceaccount') and name.endswith('.json'):
        return 'credentials'
    return None


def languages(files):
    counts = {}
    names = {'.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript',
             '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.html': 'html'}
    for name in files:
        language = names.get(Path(name).suffix.lower(), Path(name).suffix.lower().lstrip('.') or 'config')
        counts[language] = counts.get(language, 0) + 1
    return counts


def git(repo, *args, input_bytes=None):
    run = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args],
                         input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if run.returncode:
        raise ValueError("커밋이 있는 로컬 Git 저장소를 지정하세요.")
    return run.stdout


def ignored(path, ignores):
    chain = list(reversed(path.parents))
    custom = ignores.get(Path(".vibescanignore"))
    # Git cannot re-include a child while its parent directory is excluded.
    for depth, candidate in enumerate([*chain[1:], path], 1):
        suffix = "" if candidate == path else "/"
        decision = None
        for base in chain[:depth]:
            spec = ignores.get(base / ".gitignore")
            if spec:
                match = spec.check_file(candidate.relative_to(base).as_posix() + suffix)
                if match.include is not None:
                    decision = match.include
        if decision or (custom and custom.match_file(candidate.as_posix() + suffix)):
            return True
    return False


def eligible_path(name):
    return not any(part in ("", ".", "..") or part.casefold() in EXCLUDED
                   or part.endswith((" ", ".")) or PureWindowsPath(part).is_reserved()
                   or any(ord(c) < 32 or c in ':\\*?"<>|' for c in part) for part in name.split("/"))


def scan_file(path):
    return (sensitive_kind(path) or path.name.lower().endswith('.headers.http')
            or path.name in {'.env.example', '.env.sample', 'Dockerfile'}
            or (path.suffix.lower() in EXTENSIONS and not path.name.lower().endswith((".min.js", ".min.css"))
                and not path.name.startswith(".")))


def plain_files(repo, source, destination):
    """Read eligible files into the temporary scan directory. Git only lists names."""
    source = source.resolve(strict=True)
    listing = ("--work-tree", str(source), "ls-files", "-z", "--others", "--exclude-standard",
               *(f"--exclude={part}/" for part in sorted(EXCLUDED)))
    files = Files(committed=False)
    custom = source / ".vibescanignore"
    ignores = {}
    if custom.is_file() and custom.resolve() == custom:
        with custom.open("rb") as stream:
            patterns = stream.read(MAX_FILE + 1)
        if len(patterns) > MAX_FILE:
            raise ValueError("제외 규칙 파일이 크기 제한을 초과합니다.")
        ignores[Path(custom.name)] = GitIgnoreSpec.from_lines(patterns.decode("utf-8", "replace").splitlines())
    total = 0
    for raw in git(repo, *listing).split(b"\0"):
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        path = Path(name)
        if not eligible_path(name) or not scan_file(path):
            continue
        original = source / path
        if ignored(path, ignores) or original.resolve() != original or not original.is_file():
            files.excluded.add(name)
            continue
        size = original.stat().st_size
        kind = sensitive_kind(path)
        if kind not in (None, 'dotenv') or size > MAX_FILE:
            if kind:
                files.sensitive_files.append({'path': name, 'kind': kind, 'keys': []})
            else:
                files.skipped.append(name)
            continue
        with original.open("rb") as stream:
            blob = stream.read(MAX_FILE + 1)
        total += len(blob)
        if total > MAX_TOTAL:
            raise ValueError("검사 대상이 64 MiB를 초과합니다. .vibescanignore로 범위를 줄이세요.")
        if len(blob) > MAX_FILE:
            files.skipped.append(name)
        else:
            materialize(destination, path, blob, files)
    files.excluded.update(os.fsdecode(raw).rstrip('/') for raw in
                          git(repo, *listing, "--ignored", "--directory").split(b"\0") if raw)
    return files


def snapshot(repo, destination, folder_source=None):
    root = Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
    if repo.resolve() != root:
        raise ValueError("검사할 Git 저장소의 루트 폴더를 지정하세요.")
    commit = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
    branch = None if branch == "HEAD" else branch
    if folder_source is not None:
        return commit, branch, plain_files(repo, folder_source, destination)
    entries = []
    ignores = {}
    files = Files()
    for record in git(root, "ls-tree", "-rlz", commit).split(b"\0"):
        if not record:
            continue
        meta, raw = record.split(b"\t", 1)
        mode, _, oid, size = meta.split()
        if mode not in (b"100644", b"100755"):
            continue
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        path = Path(name)
        if not eligible_path(name):
            continue
        if path.name in (".gitignore", ".vibescanignore"):
            if int(size) > MAX_FILE:
                raise ValueError("제외 규칙 파일이 크기 제한을 초과합니다.")
            ignores[path] = GitIgnoreSpec.from_lines(git(root, "cat-file", "blob", oid.decode())
                                                     .decode("utf-8", "replace").splitlines())
        elif scan_file(path):
            entries.append((path, oid.decode(), int(size)))

    selected = []
    total = 0
    for path, oid, size in entries:
        if ignored(path, ignores) and not sensitive_kind(path):
            files.excluded.add(path.as_posix())
            continue
        custom = ignores.get(Path('.vibescanignore'))
        if custom and custom.match_file(path.as_posix()):
            files.excluded.add(path.as_posix())
            continue
        if size > MAX_FILE:
            kind = sensitive_kind(path)
            if kind:
                files.sensitive_files.append({'path': path.as_posix(), 'kind': kind, 'keys': []})
            else:
                files.skipped.append(path.as_posix())
            continue
        total += size
        if total > MAX_TOTAL:
            raise ValueError("검사 대상이 64 MiB를 초과합니다. .vibescanignore로 범위를 줄이세요.")
        selected.append((path, oid, size))
    stream = io.BytesIO(git(root, "cat-file", "--batch",
                            input_bytes=b"".join(oid.encode() + b"\n" for _, oid, _ in selected)))
    for path, oid, size in selected:
        header = stream.readline().split()
        if header != [oid.encode(), b"blob", str(size).encode()]:
            raise ValueError("Git 파일 내용을 읽지 못했습니다.")
        blob = stream.read(size)
        if len(blob) != size or stream.read(1) != b"\n":
            raise ValueError("Git 파일이 불완전합니다.")
        materialize(destination, path, blob, files)
    return commit, branch, files


def materialize(destination, path, blob, files):
    name = path.as_posix()
    kind = sensitive_kind(path)
    if kind:
        keys = re.findall(r'(?m)^(?:export\s+)?([A-Z_][A-Z0-9_]{0,127})\s*=', blob.decode('utf-8', 'replace')) if kind == 'dotenv' else []
        files.sensitive_files.append({'path': name, 'kind': kind, 'keys': sorted(set(keys))})
        return
    if name.lower().endswith('.headers.http'):
        # Only persist facts used by the detector. A captured response may also contain session cookies.
        lines = blob.replace(b'\r\n', b'\n').rstrip(b'\n').split(b'\n')
        if (not re.fullmatch(rb'HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) 2\d\d(?: [^\r\n]*)?', lines[0])
                or any(not re.fullmatch(rb'[!#$%&\'*+.^_|\x60~A-Za-z0-9-]+:[^\r\n]*', line) for line in lines[1:])):
            files.skipped.append(name)
            return
        headers = {}
        for line in lines[1:]:
            key, _, value = line.partition(b':')
            headers.setdefault(key.lower(), []).append(value.strip().lower())
        facts = [b'HTTP 2xx']
        if any(v.split(b';', 1)[0].strip() == b'text/html' for v in headers.get(b'content-type', ())):
            facts.append(b'html')
        if any(v for v in headers.get(b'content-security-policy', ())):
            facts.append(b'csp')
        if headers.get(b'x-content-type-options') == [b'nosniff']:
            facts.append(b'nosniff')
        blob = b'\n'.join(facts)
    try:
        blob.decode("utf-8")
    except UnicodeDecodeError:
        files.skipped.append(name)
        return
    if b"\0" in blob:
        files.skipped.append(name)
        return
    target = destination / path
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as output:
            output.write(blob)
    except FileExistsError:
        files.skipped.append(name)
        return
    files.append(name)
