"""Hardening tests: edge-case input, error handling, and new code paths."""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attackmap.core import (
    MapResult,
    map_findings,
    map_files,
    map_text,
    scan,
    to_json,
)
from attackmap.cli import main


# ---------------------------------------------------------------------------
# core.py – scan() and to_json() aliases
# ---------------------------------------------------------------------------

class TestScanAlias(unittest.TestCase):
    def test_scan_empty_string_returns_empty_findings(self):
        result = scan("")
        self.assertIsInstance(result, MapResult)
        self.assertEqual(result.total_findings, 0)

    def test_scan_whitespace_only_returns_empty_findings(self):
        result = scan("   \n  \t  ")
        self.assertEqual(result.total_findings, 0)

    def test_scan_single_line_maps(self):
        result = scan("mimikatz dumped lsass credentials")
        self.assertGreater(result.mapped_findings, 0)

    def test_scan_multiline(self):
        text = "phishing email with malicious attachment\nransomware encrypted files"
        result = scan(text)
        self.assertEqual(result.total_findings, 2)
        self.assertEqual(result.mapped_findings, 2)

    def test_scan_raises_on_non_string(self):
        with self.assertRaises(TypeError):
            scan(123)  # type: ignore[arg-type]

    def test_to_json_returns_valid_json(self):
        result = scan("powershell IEX DownloadString payload")
        out = to_json(result)
        data = json.loads(out)
        self.assertIn("total_findings", data)
        self.assertIn("findings", data)

    def test_to_json_raises_on_wrong_type(self):
        with self.assertRaises(TypeError):
            to_json({"not": "a MapResult"})  # type: ignore[arg-type]

    def test_to_json_empty_result(self):
        result = scan("")
        out = to_json(result)
        data = json.loads(out)
        self.assertEqual(data["total_findings"], 0)
        self.assertEqual(data["findings"], [])


# ---------------------------------------------------------------------------
# core.py – map_text edge cases
# ---------------------------------------------------------------------------

class TestMapTextEdgeCases(unittest.TestCase):
    def test_empty_string(self):
        f = map_text("")
        self.assertFalse(f.mapped)
        self.assertEqual(f.text, "")

    def test_whitespace_only(self):
        f = map_text("   \t  ")
        self.assertFalse(f.mapped)

    def test_very_long_line(self):
        # A 10 000-char line must not raise.
        long_line = "a" * 10_000
        f = map_text(long_line)
        self.assertIsNotNone(f)

    def test_special_regex_characters_in_text(self):
        # Text containing regex metacharacters must not raise.
        f = map_text("found (malware) [artifact] {packed} + * ? ^ $ | \\")
        self.assertIsNotNone(f)


# ---------------------------------------------------------------------------
# core.py – map_findings edge cases
# ---------------------------------------------------------------------------

class TestMapFindingsEdgeCases(unittest.TestCase):
    def test_empty_iterable(self):
        result = map_findings([])
        self.assertEqual(result.total_findings, 0)
        self.assertEqual(result.mapped_findings, 0)

    def test_all_blank_lines_ignored(self):
        result = map_findings(["", "  ", "\t", "   "])
        self.assertEqual(result.total_findings, 0)

    def test_comment_lines_ignored(self):
        result = map_findings(["# this is a comment", "# another"])
        self.assertEqual(result.total_findings, 0)

    def test_mixed_blank_comment_and_real(self):
        lines = ["", "# header", "mimikatz lsass dump", "", "# footer"]
        result = map_findings(lines)
        self.assertEqual(result.total_findings, 1)

    def test_gap_analysis_empty_result(self):
        from attackmap.core import gap_analysis, CATALOG
        result = map_findings([])
        g = gap_analysis(result)
        self.assertEqual(g["techniques_observed"], 0)
        self.assertEqual(g["catalog_size"], len(CATALOG))
        self.assertEqual(g["coverage_pct"], 0.0)

    def test_tactic_coverage_keys_always_present(self):
        from attackmap.core import TACTIC_ORDER
        result = map_findings([])
        cov = result.tactic_coverage()
        for short in TACTIC_ORDER:
            self.assertIn(short, cov)
            self.assertIn("techniques_observed", cov[short])


# ---------------------------------------------------------------------------
# core.py – map_files error handling
# ---------------------------------------------------------------------------

class TestMapFilesErrors(unittest.TestCase):
    def test_nonexistent_file_raises_oserror(self):
        with self.assertRaises(OSError):
            map_files(["nonexistent_xyz_99999.txt"])

    def test_empty_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            map_files([""])

    def test_whitespace_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            map_files(["   "])


# ---------------------------------------------------------------------------
# cli.py – min_score validation
# ---------------------------------------------------------------------------

class TestCLIMinScore(unittest.TestCase):
    def _run(self, argv):
        buf, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = buf, err
        try:
            with self.assertRaises(SystemExit) as cm:
                main(argv)
            return cm.exception.code, buf.getvalue(), err.getvalue()
        finally:
            sys.stdout, sys.stderr = old_o, old_e

    def test_min_score_zero_exits_nonzero(self):
        code, _, _ = self._run(["map", "--min-score", "0", "--format", "json"])
        self.assertNotEqual(code, 0)

    def test_min_score_negative_exits_nonzero(self):
        code, _, _ = self._run(["map", "--min-score", "-5", "--format", "json"])
        self.assertNotEqual(code, 0)


# ---------------------------------------------------------------------------
# cli.py – missing file returns exit code 2
# ---------------------------------------------------------------------------

class TestCLIMissingFile(unittest.TestCase):
    def _run(self, argv):
        buf, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = buf, err
        try:
            rc = main(argv)
            return rc, buf.getvalue(), err.getvalue()
        finally:
            sys.stdout, sys.stderr = old_o, old_e

    def test_map_missing_file_returns_2(self):
        rc, _, err = self._run(["map", "no_such_file_harden_xyz.txt"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())

    def test_heatmap_missing_file_returns_2(self):
        rc, _, _ = self._run(["heatmap", "no_such_file_harden_xyz.txt"])
        self.assertEqual(rc, 2)

    def test_gap_missing_file_returns_2(self):
        rc, _, _ = self._run(["gap", "no_such_file_harden_xyz.txt"])
        self.assertEqual(rc, 2)

    def test_navigator_missing_file_returns_2(self):
        rc, _, _ = self._run(["navigator", "no_such_file_harden_xyz.txt"])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# webhook.py – validation logic (tested via argument parsing helpers)
# ---------------------------------------------------------------------------

class TestWebhookValidation(unittest.TestCase):
    """Test the webhook helper functions directly — no network calls."""

    def test_validate_url_rejects_empty(self):
        import argparse
        from integrations.webhook import _validate_url
        ap = argparse.ArgumentParser()
        with self.assertRaises(SystemExit):
            _validate_url("", ap)

    def test_validate_url_rejects_no_scheme(self):
        import argparse
        from integrations.webhook import _validate_url
        ap = argparse.ArgumentParser()
        with self.assertRaises(SystemExit):
            _validate_url("example.com/hook", ap)

    def test_validate_url_rejects_ftp_scheme(self):
        import argparse
        from integrations.webhook import _validate_url
        ap = argparse.ArgumentParser()
        with self.assertRaises(SystemExit):
            _validate_url("ftp://example.com/hook", ap)

    def test_validate_url_accepts_https(self):
        import argparse
        from integrations.webhook import _validate_url
        ap = argparse.ArgumentParser()
        # Must not raise
        _validate_url("https://hooks.example.com/endpoint", ap)

    def test_validate_url_accepts_http(self):
        import argparse
        from integrations.webhook import _validate_url
        ap = argparse.ArgumentParser()
        _validate_url("http://localhost:9999/hook", ap)

    def test_validate_header_rejects_no_colon(self):
        import argparse
        from integrations.webhook import _validate_header
        ap = argparse.ArgumentParser()
        with self.assertRaises(SystemExit):
            _validate_header("BadHeader", ap)

    def test_validate_header_accepts_valid(self):
        import argparse
        from integrations.webhook import _validate_header
        ap = argparse.ArgumentParser()
        k, v = _validate_header("Authorization: Bearer tok123", ap)
        self.assertEqual(k, "Authorization")
        self.assertEqual(v, "Bearer tok123")


if __name__ == "__main__":
    unittest.main()
