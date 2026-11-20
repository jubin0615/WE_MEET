"""Bounded source context; repository code is parsed, never imported or executed."""

import ast
import difflib
import io
import re
import tokenize
from pathlib import Path

from .detectors.secrets import KEY, SECRET, sensitive_literals, hidden_values

REDACTED = "[REDACTED]"


def sanitize(source, known=()):
    """Remove comments, docstrings and credential literals, retaining source line numbers."""
    hidden = set(known) | hidden_values(source)
    hidden.update(m.group(1) for m in SECRET.finditer(source))
    edits = []
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def position(line, column):
        # AST columns are UTF-8 byte offsets, unlike tokenize columns.
        return offsets[line - 1] + len(lines[line - 1].encode("utf-8")[:column].decode("utf-8"))

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        # Unparsed/non-Python text is not sent as model context.
        return "", hidden
    sensitive = {id(n) for n in sensitive_literals(tree)}
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            docs.add(id(node.value))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if id(node) in sensitive or KEY.search(value):
                hidden.add(value)
        if isinstance(node, ast.JoinedStr):
            # A key split across f-string pieces ("sk-live-{'…'}") is only recognisable once joined.
            joined = "".join(part.value for part in ast.walk(node)
                             if isinstance(part, ast.Constant) and isinstance(part.value, str))
            if KEY.search(joined):
                hidden.add(joined)
    # Pieces inside an f-string cannot be replaced on their own without breaking its quoting,
    # so an f-string is judged on all of its text and redacted as a whole.
    inside_fstring = {id(child) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)
                      for child in ast.walk(node) if child is not node}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Constant, ast.JoinedStr)) or id(node) in inside_fstring:
            continue
        value = node.value if isinstance(node, ast.Constant) else "".join(
            part.value for part in ast.walk(node) if isinstance(part, ast.Constant) and isinstance(part.value, str))
        if id(node) in sensitive or id(node) in docs or (isinstance(value, str) and any(
                secret and (value == secret or len(secret) >= 4 and secret in value) for secret in hidden)):
            if isinstance(value, str) or isinstance(node, ast.JoinedStr):
                replacement = repr(REDACTED if id(node) not in docs else "[DOCSTRING OMITTED]")
                count = node.end_lineno - node.lineno
                if count:
                    replacement = "(" + replacement + "\n" * count + ")"
                edits.append((position(node.lineno, node.col_offset),
                              position(node.end_lineno, node.end_col_offset), replacement))
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            edits.append((offsets[token.start[0] - 1] + token.start[1],
                          offsets[token.end[0] - 1] + token.end[1], ""))
    chosen = []
    end = -1
    for edit in sorted(edits, key=lambda e: (e[0], -e[1])):
        if edit[0] >= end:
            chosen.append(edit)
            end = edit[1]
    for start, stop, replacement in reversed(chosen):
        source = source[:start] + replacement + source[stop:]
    return source, hidden


class Context:
    def __init__(self, directory, files):
        self.sources = {}
        self.trees = {}
        self.hidden = set()
        self.points = []
        self.omitted = 0
        self.aliases = {name: f"file-{i + 1}{Path(name).suffix}" for i, name in enumerate(files)}
        directories = {}
        self.layout = []
        for name in files[:200]:
            parent = str(Path(name).parent)
            directories.setdefault(parent, f"dir-{len(directories) + 1}")
            self.layout.append({"file": self.aliases[name], "directory": directories[parent],
                                "depth": len(Path(name).parts) - 1})
        originals = {}
        for name in files:
            self.hidden.update(hidden_values((directory / name).read_text(encoding="utf-8-sig"), name))
            if not name.endswith(".py"):
                continue
            originals[name] = (directory / name).read_text(encoding="utf-8-sig")
            _, hidden = sanitize(originals[name])
            self.hidden.update(hidden)
        for name, original in originals.items():
            source, _ = sanitize(original, self.hidden)
            if not source:
                self.omitted += 1
                continue
            try:
                tree = ast.parse(source)
            except SyntaxError:
                # A redaction that breaks the file keeps it out of model context instead of failing the scan.
                self.omitted += 1
                continue
            self.sources[name] = source
            self.trees[name] = tree
            for node in ast.walk(self.trees[name]):
                kind = None
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    kind = "import"
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
                    kind = "route_or_guard"
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in {"execute", "executemany", "query", "filter", "raw"}:
                        kind = "database"
                    elif node.func.attr in {"get_json", "json"} or any(
                            isinstance(n, ast.Attribute) and n.attr in {"args", "form", "cookies", "headers", "query_params"}
                            for n in ast.walk(node)):
                        kind = "input"
                if kind:
                    self.points.append({"id": f"S{len(self.points) + 1:03}", "file": name,
                                        "line": node.lineno, "kind": kind})

    def clean(self, text):
        for value in sorted(self.hidden, key=len, reverse=True):
            if len(value) >= 4:
                text = text.replace(value, REDACTED)
        text = KEY.sub(REDACTED, text)
        return SECRET.sub(lambda m: m.group(0).replace(m.group(1), REDACTED), text)

    def excerpt(self, name, line):
        source = self.sources.get(name, "")
        lines = source.splitlines(keepends=True)
        if not 1 <= line <= len(lines):
            return None
        start, end = max(1, line - 8), min(len(lines), line + 8)
        containers = [n for n in ast.walk(self.trees[name]) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and n.lineno <= line <= n.end_lineno and n.end_lineno - n.lineno < 60]
        if containers:
            node = min(containers, key=lambda n: n.end_lineno - n.lineno)
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            end = node.end_lineno
        code = "".join(lines[start - 1:end])
        if len(code) > 6000 or end - start + 1 > 60:
            return None
        return {"start": start, "end": end, "code": code}

    def recon(self):
        excerpts = []
        size = 0
        # Spread the budget over input/database/route/import evidence, not just imports.
        for kind in ("input", "database", "route_or_guard", "import"):
            selected = 0
            for point in (p for p in self.points if p["kind"] == kind):
                if selected >= 3:
                    break
                item = self.excerpt(point["file"], point["line"])
                if item and size + len(item["code"]) <= 24000:
                    excerpts.append({"id": point["id"], "kind": kind,
                                     "file": self.aliases[point["file"]], **item})
                    size += len(item["code"])
                    selected += 1
        return excerpts

    def proposed_diff(self, name, excerpt, replacement):
        if not excerpt or not isinstance(replacement, str) or not 0 < len(replacement) <= 6000:
            raise ValueError("수정 코드가 없거나 허용 크기를 초과했습니다.")
        original = excerpt["code"]
        if replacement.rstrip() == original.rstrip() or self.clean(replacement) != replacement:
            raise ValueError("수정 코드가 같거나 인증정보가 포함되어 있습니다.")
        replacement = replacement.rstrip("\n") + "\n"
        lines = self.sources[name].splitlines(keepends=True)
        patched = "".join(lines[:excerpt["start"] - 1]) + replacement + "".join(lines[excerpt["end"]:])
        ast.parse(patched)
        # Re-run literal filtering on model output; it must not introduce credentials.
        _, hidden = sanitize(replacement if not replacement.startswith((" ", "\t")) else "if True:\n" + replacement)
        if any(v != REDACTED for v in hidden):
            raise ValueError("수정 코드에 인증정보 리터럴이 포함되어 있습니다.")
        diff = difflib.unified_diff(self.sources[name].splitlines(keepends=True),
                                    patched.splitlines(keepends=True),
                                    fromfile="a/" + name, tofile="b/" + name)
        return "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in diff)
