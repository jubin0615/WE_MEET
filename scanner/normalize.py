"""Deterministic finding identity and cross-detector deduplication."""

import ast
import hashlib
import io
import tokenize
from dataclasses import dataclass, field

from .owasp import classify
from .models import Confidence, Finding, Location, Severity


@dataclass
class RawHit:
    detector: str
    rule_id: str
    file: str
    line: int
    cwe: str
    category: str
    title: str
    remediation: str
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.POTENTIAL
    evidence: str = "[코드·값 가림]"
    impact: str = "외부 입력·배포 환경에 따라 악용될 수 있어 검토가 필요합니다."
    fix: str = ""
    identity: str = ""
    trace: list[dict] = field(default_factory=list)
    owasp_ai: list[str] = field(default_factory=list)


def code_identity(content, line, python=False):
    """Keep literal distinctions locally; only a digest leaves this function."""
    lines = content.splitlines()
    code = lines[line - 1] if 0 < line <= len(lines) else ""
    scope = ""
    if python:
        try:
            tree = ast.parse(content)
            nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.lineno <= line <= n.end_lineno]
            if nodes:
                scope = min(nodes, key=lambda n: n.end_lineno - n.lineno).name
            code = repr([(t.type, t.string) for t in tokenize.generate_tokens(io.StringIO(code.strip()).readline)
                         if t.type not in (tokenize.COMMENT, tokenize.NEWLINE, tokenize.NL,
                                           tokenize.ENDMARKER, tokenize.INDENT, tokenize.DEDENT)])
        except (SyntaxError, ValueError, tokenize.TokenError, IndentationError):
            code = code.strip()
    else:
        # shortcut: non-Python identity preserves internal whitespace; upgrade with a JS parser.
        code = code.strip()
    return hashlib.sha256((scope + "|" + code).encode()).hexdigest()


def normalize(hits):
    grouped = {}
    for hit in sorted(hits, key=lambda h: (h.file, h.line, h.rule_id)):
        # Several packages or policy paths may have the same file-level location.
        subject = hit.identity if hit.detector in {"dependencies", "project"} else ""
        grouped.setdefault((hit.file, hit.line, hit.cwe, subject), []).append(hit)
    findings = []
    for number, group in enumerate(grouped.values(), 1):
        hit = min(group, key=lambda h: (list(Severity).index(h.severity), h.rule_id != "vs-client-server-key", h.rule_id))
        methods = sorted({f"static:{h.detector}:{h.rule_id}" for h in group})
        confidence = (Confidence.LIKELY if any(h.confidence == Confidence.LIKELY for h in group)
                      else Confidence.POTENTIAL)
        # Correlated pattern matches do not establish input reachability.
        identity = f"{hit.rule_id}|{hit.file}|{hit.identity}"
        findings.append(Finding(f"F-{number:03}", hit.title, hit.cwe, classify(hit.cwe) or "", hit.severity, confidence,
            Location(hit.file, hit.line), hit.evidence, methods, hit.impact, hit.remediation, hit.fix,
            rule_id=hit.rule_id, fingerprint=hashlib.sha256(identity.encode()).hexdigest()[:16],
            category=hit.category, owasp_ai=sorted({code for h in group for code in h.owasp_ai}), detector=hit.detector,
            trace=hit.trace))
    return findings
