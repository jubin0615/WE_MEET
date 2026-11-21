"""Compare declared, exact package versions to the bundled GHSA snapshot."""

import gzip
import json
import re
from functools import lru_cache
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
from semantic_version import Version as SemVer

from ..models import Confidence, Severity
from ..normalize import RawHit


@lru_cache(maxsize=1)
def database():
    with gzip.open(Path(__file__).resolve().parents[1] / "advisories.json.gz", "rt", encoding="utf-8") as db:
        return json.load(db)


def supported(name):
    base = Path(name).name.lower()
    return base in {"package.json", "package-lock.json", "npm-shrinkwrap.json"} or bool(
        re.fullmatch(r"requirements(?:[-_.][\w.-]+)?\.txt", base))


def pins(name, content):
    """Yield (line, package, version). A missing version marks an unresolved declaration."""
    if name.lower().endswith(".txt"):
        for line, text in enumerate(content.splitlines(), 1):
            text = text.partition("#")[0].strip()
            if not text:
                continue
            try:
                req = Requirement(text)
                spec = list(req.specifier)
                version = spec[0].version if len(spec) == 1 and spec[0].operator == "==" else None
                yield line, canonicalize_name(req.name), version
            except InvalidRequirement:
                yield line, "", None
        return
    # JSON manifests have file-level evidence; never infer a line from a repeated version string.
    doc = json.loads(content)
    if Path(name).name.lower() == "package.json":
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for package, version in doc.get(field, {}).items():
                yield 1, package, version
    elif doc.get("lockfileVersion") in (2, 3):
        for path, meta in doc["packages"].items():
            _, marker, package = ("/" + path).rpartition("/node_modules/")
            if marker and not meta.get("link"):
                yield 1, meta.get("name", package), meta.get("version")
    elif doc.get("lockfileVersion") == 1:
        pending = list(doc.get("dependencies", {}).items())
        while pending:
            package, meta = pending.pop()
            yield 1, package, meta.get("version")
            pending.extend(meta.get("dependencies", {}).items())
    else:
        raise ValueError("unsupported lockfile version")


def release(ecosystem, version):
    if ecosystem == "PyPI":
        return Version(Version(version).public)
    return SemVer(str(SemVer(version)).split("+", 1)[0])


def affected(record, version, ecosystem):
    for exact in record["versions"]:
        try:
            if version == release(ecosystem, exact):
                return True
        except ValueError:
            continue
    for events in record["ranges"]:
        inside = False
        for event in events:
            key, bound = next(iter(event.items()))
            if key == "introduced":
                inside = bound == "0" or version >= release(ecosystem, bound)
            elif key in {"fixed", "limit", "last_affected"}:
                end = release(ecosystem, bound)
                if inside and (version < end or key == "last_affected" and version == end):
                    return True
                inside = False
        if inside:
            return True
    return False


def detect(name, content):
    ecosystem = "PyPI" if name.lower().endswith(".txt") else "npm"
    db = database()
    index = db[ecosystem]
    packages, seen = {}, set()
    partial = False
    count = 0
    try:
        for line, package, value in pins(name, content):
            if not isinstance(value, str) or not isinstance(package, str) or not re.fullmatch(
                    r"(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+", package):
                partial = True
                continue
            try:
                version = release(ecosystem, value)
            except ValueError:
                partial = True
                continue
            if (package, version) in seen:
                continue
            seen.add((package, version))
            count += 1
            matches = {}
            for record in index.get(package, ()):
                try:
                    if affected(record, version, ecosystem):
                        matches[record["id"]] = record["cves"]
                except ValueError:
                    partial = True
            if matches:
                advisories = ", ".join(" ".join([key, *aliases]) for key, aliases in sorted(matches.items()))
                packages.setdefault(package, []).append((line, f"{ecosystem} · {package} {version} · {advisories}"))
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        partial = True
    hits = []
    for package, entries in packages.items():
        hits.append(RawHit("dependencies", "vs-dependency-advisory", name, entries[0][0], "CWE-1395",
            'VS-04', f"{package} 의존성 버전이 보안 공지에 해당", "각 공지의 수정 버전을 확인하고 잠금 파일도 갱신하세요.",
            Severity.MEDIUM, Confidence.LIKELY, evidence="\n".join(row for _, row in entries),
            impact="파일에 선언된 버전이 공지의 영향 범위에 속합니다. 배포 버전과 해당 기능의 사용 여부를 확인하세요.",
            identity=f"{ecosystem}|{package}"))
    return hits, count, partial
