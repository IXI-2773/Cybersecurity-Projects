"""End-to-end checks for the bounded iptables-save import path."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("review.py")


class IptablesImportTests(unittest.TestCase):
    def run_export(self, contents):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "filter.rules"
            path.write_text(contents, encoding="utf-8")
            return subprocess.run([sys.executable, str(SCRIPT), "--format", "iptables-save",
                                   str(path)], capture_output=True, text=True, check=False)

    def test_imports_filter_input_with_original_line_number_and_risky_admin_allow(self):
        export = """# Fabricated export in iptables-save syntax
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp -s 0.0.0.0/0 -d 10.10.1.20/32 --dport 3389 -j ACCEPT
-A INPUT -s 10.10.0.0/24 -d 10.10.1.5/32 -p tcp --dport 22 -j ACCEPT
-A FORWARD -j ACCEPT
COMMIT
"""
        result = self.run_export(export)

        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["policy"], "iptables-save IPv4 filter INPUT")
        self.assertEqual(report.get("scope"),
                         "Single-earlier-rule shadowing checked; combined coverage and real reachability not evaluated")
        self.assertEqual(report["rule_count"], 2)
        self.assertEqual(report["findings"], [{
            "rule_id": "INPUT:L6", "code": "UNRESTRICTED_ADMIN_SOURCE",
            "severity": "HIGH",
            "detail": "TCP/3389 is allowed from all IPv4 addresses; review source restrictions.",
        }])

    def test_rejects_ipv6_rules_in_ipv4_only_export_mode(self):
        export = """*filter
:INPUT DROP [0:0]
-A INPUT -s ::/0 -d ::/0 -j ACCEPT
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("Invalid policy:", result.stderr)

    def test_rejects_input_rules_before_chain_policy_declaration(self):
        export = """*filter
-A INPUT -j ACCEPT
:INPUT DROP [0:0]
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("Invalid policy:", result.stderr)

    def test_earlier_catchall_drop_shadows_later_admin_allow(self):
        export = """*filter
:INPUT DROP [0:0]
-A INPUT -j DROP
-A INPUT -p tcp -m tcp --dport 3389 -j ACCEPT
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["rule_count"], 2)
        self.assertEqual(report["findings"], [{
            "rule_id": "INPUT:L4", "code": "SHADOWED_RULE", "severity": "INFO",
            "detail": "INPUT:L3 matches all traffic for this later rule; it cannot be reached in this INPUT model.",
        }])

    def test_cidr_subsumption_shadows_subset_but_not_broader_source(self):
        export = """*filter
:INPUT DROP [0:0]
-A INPUT -s 10.0.0.0/8 -d 192.0.2.0/24 -p tcp --dport 22 -j DROP
-A INPUT -s 10.1.0.0/16 -d 192.0.2.10/32 -p tcp --dport 22 -j ACCEPT
-A INPUT -s 0.0.0.0/0 -d 192.0.2.10/32 -p tcp --dport 22 -j ACCEPT
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["findings"], [
            {"rule_id": "INPUT:L4", "code": "SHADOWED_RULE", "severity": "INFO",
             "detail": "INPUT:L3 matches all traffic for this later rule; it cannot be reached in this INPUT model."},
            {"rule_id": "INPUT:L5", "code": "UNRESTRICTED_ADMIN_SOURCE", "severity": "HIGH",
             "detail": "TCP/22 is allowed from all IPv4 addresses; review source restrictions."},
        ])


if __name__ == "__main__":
    unittest.main()
