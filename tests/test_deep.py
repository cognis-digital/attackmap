"""Deep tests for ATTACKMAP. Standard library only, no network."""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attackmap import (  # noqa: E402
    CATALOG,
    TACTIC_ORDER,
    TOOL_NAME,
    TOOL_VERSION,
    gap_analysis,
    lookup,
    map_findings,
    map_text,
    navigator_layer,
)
from attackmap.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "02-deep", "incident_findings.txt",
)


class TestMetadata(unittest.TestCase):
    def test_names(self):
        self.assertEqual(TOOL_NAME, "attackmap")
        self.assertTrue(TOOL_VERSION)

    def test_catalog_is_substantial(self):
        self.assertGreaterEqual(len(CATALOG), 60)

    def test_catalog_ids_unique(self):
        ids = [t.tid for t in CATALOG]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_technique_has_rules_and_tactics(self):
        for t in CATALOG:
            self.assertTrue(t.tactics, f"{t.tid} has no tactic")
            self.assertTrue(t.keywords or t.regexes,
                            f"{t.tid} has no detection rules")
            for short in t.tactics:
                self.assertIn(short, TACTIC_ORDER, f"{t.tid} bad tactic {short}")

    def test_subtechnique_parent(self):
        self.assertEqual(map_text("powershell").matches[0].technique.parent_id,
                         "T1059")


class TestMapping(unittest.TestCase):
    def test_powershell_maps_to_t1059_001_high(self):
        f = map_text("Attacker ran powershell.exe -EncodedCommand IEX "
                     "DownloadString to fetch a payload")
        ids = [m.technique.tid for m in f.matches]
        self.assertIn("T1059.001", ids)
        top = next(m for m in f.matches if m.technique.tid == "T1059.001")
        self.assertEqual(top.confidence, "high")
        self.assertTrue(top.evidence)

    def test_ransomware_maps_to_impact(self):
        f = map_text("Ransomware encrypted files; .locked extension and a "
                     "ransom note appeared")
        ids = [m.technique.tid for m in f.matches]
        self.assertIn("T1486", ids)

    def test_lsass_dump_credential_access(self):
        f = map_text("mimikatz dumped credentials from lsass via sekurlsa")
        self.assertEqual(f.top.technique.tid, "T1003.001")
        self.assertIn("credential-access", f.top.technique.tactics)

    def test_benign_line_maps_to_nothing(self):
        f = map_text("Routine TLS handshake to the corporate CDN")
        self.assertFalse(f.mapped)

    def test_cve_regex_hits_exploit(self):
        f = map_text("Server was hit by CVE-2021-44228 (log4j) RCE")
        self.assertIn("T1190", [m.technique.tid for m in f.matches])

    def test_min_score_filters_weak(self):
        # A single weak keyword should drop out at a higher threshold.
        text = "exploit was attempted"
        loose = map_text(text, min_score=1)
        strict = map_text(text, min_score=3)
        self.assertGreaterEqual(len(loose.matches), len(strict.matches))


class TestCoverageAndGap(unittest.TestCase):
    def setUp(self):
        with open(DEMO, encoding="utf-8") as fh:
            self.result = map_findings(fh.read().splitlines())

    def test_full_kill_chain_lit(self):
        cov = self.result.tactic_coverage()
        touched = [s for s in TACTIC_ORDER if cov[s]["techniques_observed"]]
        # Ransomware intrusion should touch most of the chain.
        self.assertGreaterEqual(len(touched), 9)
        for must in ("initial-access", "execution", "credential-access",
                     "lateral-movement", "exfiltration", "impact"):
            self.assertIn(must, touched, f"{must} not lit")

    def test_expected_techniques_present(self):
        ids = set(self.result.unique_techniques())
        for tid in ("T1566.001", "T1059.001", "T1003.001", "T1021.002",
                    "T1567.002", "T1486", "T1490"):
            self.assertIn(tid, ids)

    def test_gap_analysis_shape(self):
        g = gap_analysis(self.result)
        self.assertEqual(g["catalog_size"], len(CATALOG))
        self.assertGreater(g["techniques_observed"], 10)
        self.assertEqual(
            g["techniques_observed"] + g["techniques_missing"],
            g["catalog_size"],
        )
        self.assertGreater(g["coverage_pct"], 0.0)
        # Reconnaissance was never observed -> it must show up as a gap.
        self.assertIn("recon", g["missing_by_tactic"])


class TestNavigatorLayer(unittest.TestCase):
    def setUp(self):
        with open(DEMO, encoding="utf-8") as fh:
            self.result = map_findings(fh.read().splitlines())

    def test_layer_is_valid_navigator_json(self):
        layer = navigator_layer(self.result, name="IR test")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        self.assertEqual(layer["name"], "IR test")
        self.assertTrue(layer["techniques"])
        # Round-trips through JSON.
        round_tripped = json.loads(json.dumps(layer))
        self.assertEqual(round_tripped, layer)

    def test_layer_scores_by_confidence(self):
        layer = navigator_layer(self.result)
        scores = {e["score"] for e in layer["techniques"]}
        self.assertTrue(scores <= {33, 66, 100})
        for e in layer["techniques"]:
            self.assertTrue(e["techniqueID"])
            self.assertTrue(e["tactic"])
            self.assertTrue(e["enabled"])


class TestLookup(unittest.TestCase):
    def test_lookup_by_id_prefix(self):
        res = lookup("T1059")
        ids = {t.tid for t in res}
        self.assertIn("T1059", ids)
        self.assertIn("T1059.001", ids)

    def test_lookup_by_keyword(self):
        res = lookup("kerberoast")
        self.assertTrue(any(t.tid == "T1558.003" for t in res))


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        buf, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = buf, err
        try:
            rc = main(argv)
        finally:
            sys.stdout, sys.stderr = old_o, old_e
        return rc, buf.getvalue(), err.getvalue()

    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            self._run(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_map_json_nonzero_on_findings(self):
        rc, out, _ = self._run(["map", "--format", "json", DEMO])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "attackmap")
        self.assertGreater(payload["unique_techniques"], 10)
        self.assertIn("T1486", payload["technique_ids"])

    def test_map_table(self):
        rc, out, _ = self._run(["map", DEMO])
        self.assertEqual(rc, 1)
        self.assertIn("T1059.001", out)

    def test_heatmap_json(self):
        rc, out, _ = self._run(["heatmap", "--format", "json", DEMO])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertIn("coverage", payload)
        self.assertGreater(payload["unique_techniques"], 0)

    def test_gap_table(self):
        rc, out, _ = self._run(["gap", DEMO])
        self.assertEqual(rc, 1)
        self.assertIn("coverage", out.lower())

    def test_gap_json(self):
        rc, out, _ = self._run(["gap", "--format", "json", DEMO])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertIn("missing_by_tactic", payload)

    def test_navigator_stdout(self):
        rc, out, _ = self._run(["navigator", DEMO])
        self.assertEqual(rc, 1)
        layer = json.loads(out)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertTrue(layer["techniques"])

    def test_navigator_writes_file(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_layer.json")
        try:
            rc, out, err = self._run(["navigator", "--out", path, DEMO])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as fh:
                layer = json.load(fh)
            self.assertTrue(layer["techniques"])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_tactics_zero_exit(self):
        rc, out, _ = self._run(["tactics", "--format", "json"])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload["tactics"]), 14)

    def test_lookup_zero_exit(self):
        rc, out, _ = self._run(["lookup", "T1003", "--format", "json"])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertTrue(payload["techniques"])

    def test_clean_input_zero_exit(self):
        clean = os.path.join(os.path.dirname(__file__), "_tmp_clean.txt")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write("ordinary https session to a CDN, nothing of note\n")
        try:
            rc, _, _ = self._run(["map", clean])
            self.assertEqual(rc, 0)
        finally:
            os.remove(clean)

    def test_missing_file_returns_2(self):
        rc, _, _ = self._run(["map", "no_such_file_98765.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
