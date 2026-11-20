"""Build VibeScan's offline index from OSV PyPI/all.zip and npm/all.zip."""

import argparse
import gzip
import json
import zipfile
from datetime import date
from pathlib import Path

from packaging.utils import canonicalize_name


def index(archive, ecosystem):
    packages = {}
    with zipfile.ZipFile(archive) as records:
        for filename in sorted(records.namelist()):
            if not filename.startswith("GHSA-") or not filename.endswith(".json"):
                continue
            advisory = json.loads(records.read(filename))
            if advisory.get("withdrawn"):
                continue
            for affected in advisory["affected"]:
                package = affected["package"]
                if package["ecosystem"] != ecosystem:
                    continue
                ranges = [r["events"] for r in affected.get("ranges", [])
                          if r["type"] in {"ECOSYSTEM", "SEMVER"}]
                versions = affected.get("versions", []) if not ranges else []
                if not ranges and not versions:
                    continue
                name = canonicalize_name(package["name"]) if ecosystem == "PyPI" else package["name"]
                packages.setdefault(name, []).append({
                    "id": advisory["id"], "cves": [a for a in advisory.get("aliases", []) if a.startswith("CVE-")],
                    "ranges": ranges, "versions": versions,
                })
    if not packages:
        raise ValueError(f"No GHSA records for {ecosystem}")
    return packages


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pypi_zip", type=Path)
    parser.add_argument("npm_zip", type=Path)
    parser.add_argument("--date", required=True, type=date.fromisoformat, help="UTC snapshot date")
    args = parser.parse_args()
    data = {"date": str(args.date), "PyPI": index(args.pypi_zip, "PyPI"), "npm": index(args.npm_zip, "npm")}
    output = Path(__file__).resolve().parents[1] / "scanner" / "advisories.json.gz"
    output.write_bytes(gzip.compress(json.dumps(data, separators=(",", ":"), sort_keys=True).encode(), mtime=0))
