"""Offline classification from the bundled catalogues."""
import json
import sysconfig
from functools import cache
from pathlib import Path


@cache
def catalog(name):
    path = Path(__file__).resolve().parents[1] / "rules/catalog" / (name + ".yml")
    if not path.is_file():
        path = Path(sysconfig.get_path("data")) / "share/vibescan" / path.name
    return json.loads(path.read_text(encoding="utf-8"))


@cache
def _cwe_index():
    return {cwe: row["code"] for row in catalog("owasp-top10-2025")["items"] for cwe in row["cwes"]}


def classify(cwe: str) -> str | None:
    return _cwe_index().get(cwe)
