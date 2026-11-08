"""End-to-end checks for offline HTML/CSV firewall-review exports."""

import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("review.py")
EXAMPLE = SCRIPT.parent / "fixtures" / "iptables_partial_overlap.rules"
SINGLE = SCRIPT.parent / "fixtures" / "iptables_shadow.rules"


class ReportExportTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              capture_output=True, text=True, check=False)

    def test_csv_preserves_findings_and_partial_overlap_evidence(self):
        result = self.run_cli("--format", "iptables-save", "--report-format", "csv", EXAMPLE)
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = list(csv.DictReader(io.StringIO(result.stdout)))
        self.assertEqual(len(rows), 2)
        self.assertEqual([(row["rule_id"], row["code"], row["severity"]) for row in rows], [
            ("INPUT:L8", "UNRESTRICTED_ADMIN_SOURCE", "HIGH"),
            ("INPUT:L8", "PARTIALLY_SHADOWED_RULE", "INFO"),
        ])
        self.assertEqual(rows[1]["policy"], "iptables-save IPv4 filter INPUT")
        self.assertEqual(rows[1]["prior_rule_ids"], "INPUT:L6; INPUT:L7")
        self.assertEqual(rows[1]["overlap_example"],
                         "0.0.0.0/1 → 0.0.0.0/0 (tcp/3389)")
        self.assertIn("real reachability not evaluated", rows[1]["scope"])

    def test_csv_keeps_single_shadow_predecessor_as_structured_evidence(self):
        result = self.run_cli("--format", "iptables-save", "--report-format", "csv", SINGLE)
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = list(csv.DictReader(io.StringIO(result.stdout)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["code"], "SHADOWED_RULE")
        self.assertEqual(rows[0]["rule_id"], "INPUT:L7")
        self.assertEqual(rows[0]["prior_rule_ids"], "INPUT:L6")

    def test_html_is_standalone_and_explains_review_limits(self):
        result = self.run_cli("--format", "iptables-save", "--report-format", "html", EXAMPLE)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("<!doctype html>", result.stdout.lower())
        self.assertIn("<title>Firewall Policy Review</title>", result.stdout)
        self.assertIn("PARTIALLY_SHADOWED_RULE", result.stdout)
        self.assertIn("INPUT:L6", result.stdout)
        self.assertIn("tcp/3389", result.stdout)
        self.assertIn("real reachability not evaluated", result.stdout)
        self.assertNotIn("<script", result.stdout.lower())
        self.assertNotIn("<link ", result.stdout.lower())

    def test_html_escapes_markup_and_csv_neutralizes_spreadsheet_formulas(self):
        policy = {
            "name": '=SUM(1,1)<script>alert("x")</script>',
            "default_action": "deny",
            "rules": [{"id": '=HYPERLINK("https://example.invalid","x")',
                       "action": "allow", "source": "0.0.0.0/0",
                       "destination": "0.0.0.0/0", "protocol": "any", "port": None}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            html = self.run_cli("--report-format", "html", path)
            csv_result = self.run_cli("--report-format", "csv", path)
        self.assertEqual(html.returncode, 1, html.stderr)
        self.assertNotIn("<script>", html.stdout)
        self.assertIn("&lt;script&gt;", html.stdout)
        self.assertIn("=HYPERLINK(&quot;https://example.invalid&quot;", html.stdout)
        self.assertEqual(csv_result.returncode, 1, csv_result.stderr)
        row = next(csv.DictReader(io.StringIO(csv_result.stdout)))
        self.assertEqual(row["policy"], "'" + policy["name"])
        self.assertEqual(row["rule_id"], "'" + policy["rules"][0]["id"])

    def test_output_saves_new_file_without_overwriting_or_partial_invalid_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "review.html"
            created = self.run_cli("--format", "iptables-save", "--report-format", "html",
                                   "--output", destination, EXAMPLE)
            self.assertEqual(created.returncode, 1, created.stderr)
            self.assertEqual(created.stdout, "")
            self.assertIn("<title>Firewall Policy Review</title>",
                          destination.read_text(encoding="utf-8"))

            again = self.run_cli("--format", "iptables-save", "--report-format", "html",
                                 "--output", destination, EXAMPLE)
            self.assertEqual(again.returncode, 2, again.stdout)
            self.assertIn("Cannot save report:", again.stderr)
            self.assertIn("<title>Firewall Policy Review</title>",
                          destination.read_text(encoding="utf-8"))

            invalid_policy = Path(tmp) / "invalid.json"
            invalid_policy.write_text('{"name": "bad", "rules": []}', encoding="utf-8")
            blocked_output = Path(tmp) / "invalid.html"
            refused = self.run_cli("--report-format", "html", "--output", blocked_output,
                                   invalid_policy)
            self.assertEqual(refused.returncode, 2, refused.stdout)
            self.assertEqual(refused.stdout, "")
            self.assertFalse(blocked_output.exists())

    def test_saved_html_and_csv_demos_reproduce_from_synthetic_fixture(self):
        for format_name in ("html", "csv"):
            with self.subTest(format=format_name):
                run = self.run_cli("--format", "iptables-save", "--report-format",
                                   format_name, EXAMPLE)
                self.assertEqual(run.returncode, 1, run.stderr)
                artifact = SCRIPT.parent / "artifacts" / f"partial_overlap_report.{format_name}"
                self.assertEqual(run.stdout, artifact.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
