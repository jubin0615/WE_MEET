import json
import re
import unittest
from pathlib import Path

from scanner.coverage import compute
from scanner.owasp import catalog, classify


class ClassificationTests(unittest.TestCase):
    def test_complete_official_lists_have_unique_membership(self):
        items = catalog("owasp-top10-2025")["items"]
        # Published CWE counts in the score tables of each 2025 category.
        self.assertEqual([len(row["cwes"]) for row in items], [40, 16, 6, 32, 37, 39, 36, 14, 5, 24])
        all_cwes = [cwe for row in items for cwe in row["cwes"]]
        self.assertEqual(len(all_cwes), len(set(all_cwes)))
        self.assertEqual(classify("CWE-89"), "A05:2025")
        self.assertIsNone(classify("CWE-1427"))

    def test_all_bundled_rule_cwes_are_accounted_for(self):
        root = Path(__file__).resolve().parents[1]
        cwes = set()
        for path in (root / "rules/vibescan").glob("*.yml"):
            for rule in json.loads(path.read_text(encoding="utf8"))["rules"]:
                cwes.add(rule["metadata"]["cwe"])
        for path in [root / "scanner/static.py", *(root / "scanner/detectors").glob("*.py")]:
            cwes.update(re.findall(r"CWE-\d+", path.read_text(encoding="utf8")))
        unmapped = set(catalog("owasp-top10-2025")["unmapped_cwes"])
        self.assertEqual({cwe for cwe in cwes if classify(cwe) is None}, unmapped)

    def test_scope_without_candidates(self):
        vs, web = compute([], {"python": 1}, [])
        states = {row["code"]: row["status"] for row in vs + web}
        self.assertEqual(states["VS-03"], "해당 없음(추정)")
        self.assertEqual(states["VS-08"], "건너뜀")
        self.assertEqual(states["A05:2025"], "검사함 · 미발견")
        self.assertEqual(states["A09:2025"], "수동 확인 필요")
        vs, web = compute([], {"python": 1, "kt": 1}, ["broken.py"])
        self.assertEqual(next(r for r in web if r["code"] == "A05:2025")["status"], "부분 점검")
