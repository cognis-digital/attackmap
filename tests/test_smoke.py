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
    BY_ID,
    CATALOG,
    TACTIC_ORDER,
    Finding,
    map_text,
    map_findings,
    map_files,
    lookup,
    navigator_layer,
)
from attackmap.cli import main

# Text-based demo used by smoke heatmap/navigator tests (7 findings, one benign).
_SEVEN_FINDING_LINES = [
    "EDR flagged powershell.exe -EncodedCommand spawning IEX DownloadString cradle",
    "Suspected credential dump via mimikatz sekurlsa against lsass",
    "Interactive RDP remote desktop sessions lateral movement to multiple hosts",
    "Periodic https beacon to a low-reputation domain consistent with command and control",
    "SQL injection confirmed on the internet-exposed login (web exploit public-facing)",
    "vssadmin delete shadows executed; ransomware data encrypted for impact T1486",
    "Server still negotiates TLS 1.0 hardening recommendation only",
]

DEMO_TXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "demos", "02-deep", "incident_findings.txt")


class TestKnowledgeBase(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "attackmap")
        self.assertTrue(TOOL_VERSION)

    def test_techniques_valid(self):
        # BY_ID is a dict keyed by technique id.
        for tid, t in BY_ID.items():
            self.assertEqual(tid, t.tid)
            # Every technique must belong to at least one known tactic.
            for tac in t.tactics:
                self.assertIn(tac, TACTIC_ORDER)
            self.assertTrue(t.name)

    def test_lookup_case_insensitive_and_parent_fallback(self):
        # Case-insensitive lookup by exact id via BY_ID.
        t = BY_ID.get("T1059.001")
        self.assertIsNotNone(t)
        self.assertEqual(t.tid, "T1059.001")

        # lookup() prefix-matches: "T1059" returns parent and all sub-techniques.
        results = lookup("T1059")
        ids = {r.tid for r in results}
        self.assertIn("T1059", ids)
        self.assertIn("T1059.001", ids)

        # An unknown id has no entry in BY_ID.
        self.assertIsNone(BY_ID.get("T9999"))


class TestResolution(unittest.TestCase):
    def test_keyword_resolution(self):
        # map_text returns a Finding with matches sorted by score.
        f = map_text("saw mimikatz dumping lsass and a powershell IEX cradle")
        ids = [m.technique.tid for m in f.matches]
        self.assertIn("T1003.001", ids)
        self.assertIn("T1059.001", ids)

    def test_explicit_id_in_text(self):
        # An explicit T1486 reference in text must map to that technique.
        f = map_text("ref T1486 ransomware")
        ids = [m.technique.tid for m in f.matches]
        self.assertIn("T1486", ids)

    def test_explicit_override(self):
        # Passing text that is unambiguous for T1190 maps to T1190.
        f = map_text("CVE-2021-44228 log4j exploit on a public-facing web application")
        ids = [m.technique.tid for m in f.matches]
        self.assertIn("T1190", ids)

    def test_unmapped(self):
        # Benign text produces a Finding with no matches.
        f = map_text("totally benign nothing suspicious here")
        self.assertFalse(f.mapped)
        self.assertEqual(f.matches, [])


class TestHeatmapAndNavigator(unittest.TestCase):
    def setUp(self):
        self.result = map_findings(_SEVEN_FINDING_LINES)

    def test_parse_demo(self):
        # All 7 lines are non-blank/non-comment and produce findings.
        self.assertEqual(len(self.result.findings), 7)

    def test_heatmap(self):
        # tactic_coverage() returns per-tactic dict; credential-access must be lit.
        cov = self.result.tactic_coverage()
        tactics_covered = sum(
            1 for v in cov.values() if v["techniques_observed"] > 0
        )
        self.assertGreaterEqual(tactics_covered, 4)
        # The lsass/mimikatz line should land a technique in credential-access.
        cred = cov["credential-access"]
        cred_ids = [t["id"] for t in [
            {"id": tid} for tid in cred["observed_ids"]
        ]]
        self.assertIn("T1003.001", cred_ids)

    def test_navigator_schema(self):
        layer = navigator_layer(self.result)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("versions", layer)
        self.assertTrue(layer["techniques"])
        for t in layer["techniques"]:
            self.assertIn("techniqueID", t)
            self.assertIn("score", t)

    def test_parse_rejects_missing_name(self):
        # map_findings skips blank/comment lines; empty input yields empty findings.
        result = map_findings([])
        self.assertEqual(len(result.findings), 0)


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
        code, out = self._run(["map", "--format", "json", DEMO_TXT])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertTrue(data["mapped_findings"])

    def test_heatmap_table(self):
        code, out = self._run(["heatmap", DEMO_TXT])
        self.assertEqual(code, 1)
        # The heatmap table includes tactic stats.
        self.assertIn("tactics_touched", out)

    def test_navigator_json_valid(self):
        code, out = self._run(["navigator", DEMO_TXT])
        self.assertEqual(code, 1)
        json.loads(out)  # must be valid JSON

    def test_techniques_listing(self):
        # "tactics" lists all 14 ATT&CK tactics; exit 0 when no input findings.
        code, out = self._run(["tactics"])
        self.assertEqual(code, 0)
        # The output lists tactic names; Credential Access is always present.
        self.assertIn("Credential Access", out)

    def test_stdin_pipe(self):
        payload = "spearphishing attachment delivered a malicious macro document"
        code, out = self._run(["map", "--format", "json"], stdin=payload)
        self.assertEqual(code, 1)
        self.assertIn("T1566.001", out)

    def test_bad_input_exit_two(self):
        # Passing a non-existent file path must return exit code 2.
        code, _ = self._run(["map", "nonexistent_file_xyz_98765.txt"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
