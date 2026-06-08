"""Smoke tests for attackmap. Standard library only, no network."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attackmap import (
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    TECHNIQUES,
    TACTIC_ORDER,
    map_findings,
    coverage_heatmap,
    navigator_layer,
    parse_findings,
    lookup_technique,
    resolve_keywords,
)
from attackmap.cli import main

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic", "findings.json")


class TestKnowledgeBase(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "attackmap")
        self.assertTrue(TOOL_VERSION)

    def test_techniques_valid(self):
        for tid, t in TECHNIQUES.items():
            self.assertEqual(tid, t.tid)
            self.assertIn(t.tactic, TACTIC_ORDER)
            self.assertTrue(t.name)

    def test_lookup_case_insensitive_and_parent_fallback(self):
        self.assertEqual(lookup_technique("t1059.001").tid, "T1059.001")
        # unknown sub-technique falls back to known parent
        self.assertEqual(lookup_technique("T1059.999").tid, "T1059.001")
        self.assertIsNone(lookup_technique("T9999"))


class TestResolution(unittest.TestCase):
    def test_keyword_resolution(self):
        ids = resolve_keywords("saw mimikatz dumping lsass and a powershell IEX cradle")
        self.assertIn("T1003.001", ids)
        self.assertIn("T1059.001", ids)

    def test_explicit_id_in_text(self):
        self.assertEqual(resolve_keywords("ref T1486 ransomware"), 
                         sorted({"T1486"}, key=lambda x: x))

    def test_explicit_override(self):
        f = Finding(name="weird thing", description="no keywords here",
                    technique_id="T1190")
        res = map_findings([f])
        self.assertEqual(res["mapped"][0]["techniques"][0]["id"], "T1190")

    def test_unmapped(self):
        res = map_findings([Finding(name="totally benign", description="nothing")])
        self.assertEqual(res["mapped"], [])
        self.assertEqual(len(res["unmapped"]), 1)


class TestHeatmapAndNavigator(unittest.TestCase):
    def setUp(self):
        self.findings = parse_findings(path=DEMO)

    def test_parse_demo(self):
        self.assertEqual(len(self.findings), 7)

    def test_heatmap(self):
        heat = coverage_heatmap(self.findings)
        self.assertGreaterEqual(heat["tactics_covered"], 4)
        # critical lsass finding outweighs info findings
        cred = heat["tactics"]["credential-access"]
        self.assertTrue(any(t["id"] == "T1003.001" for t in cred["techniques"]))

    def test_navigator_schema(self):
        layer = navigator_layer(self.findings)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("versions", layer)
        self.assertTrue(layer["techniques"])
        for t in layer["techniques"]:
            self.assertIn("techniqueID", t)
            self.assertIn("score", t)

    def test_parse_rejects_missing_name(self):
        with self.assertRaises(ValueError):
            parse_findings(raw=json.dumps([{"description": "x"}]))


class TestCLI(unittest.TestCase):
    def _run(self, argv, stdin=None):
        old_out, old_in = sys.stdout, sys.stdin
        sys.stdout = io.StringIO()
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            code = main(argv)
            return code, sys.stdout.getvalue()
        finally:
            sys.stdout, sys.stdin = old_out, old_in

    def test_map_exit_one_on_findings(self):
        code, out = self._run(["map", "--input", DEMO, "--format", "json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertTrue(data["mapped"])

    def test_heatmap_table(self):
        code, out = self._run(["heatmap", "--input", DEMO])
        self.assertEqual(code, 1)
        self.assertIn("Tactics covered", out)

    def test_navigator_json_valid(self):
        code, out = self._run(["navigator", "--input", DEMO, "--format", "json"])
        self.assertEqual(code, 1)
        json.loads(out)  # must be valid JSON

    def test_techniques_listing(self):
        code, out = self._run(["techniques"])
        self.assertEqual(code, 0)
        self.assertIn("T1003.001", out)

    def test_stdin_pipe(self):
        payload = json.dumps([{"name": "phishing email",
                               "description": "spearphishing attachment"}])
        code, out = self._run(["map", "--format", "json"], stdin=payload)
        self.assertEqual(code, 1)
        self.assertIn("T1566.001", out)

    def test_bad_input_exit_two(self):
        code, _ = self._run(["map", "--format", "json"], stdin="not json")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
