"""End-to-end checks for the bounded iptables-save import path."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rule_order import combined_shadowed_by_prior_rules


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
                         "Exact single/combined shadowing and partial overlap checked for supported IPv4 INPUT; real reachability not evaluated")
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
            {"rule_id": "INPUT:L5", "code": "PARTIALLY_SHADOWED_RULE", "severity": "INFO",
             "overlapping_rule_ids": ["INPUT:L3"],
             "overlap_example": {"source": "10.0.0.0/8", "destination": "192.0.2.10/32",
                                 "protocol": "tcp", "port": 22},
             "detail": "Earlier terminating INPUT rules match part, but not all, of this rule's traffic; review redundant matches and rule order."},
        ])

    def test_combined_source_coverage_requires_no_gaps(self):
        partial = """*filter
:INPUT DROP [0:0]
-A INPUT -s 0.0.0.0/1 -j DROP
-A INPUT -s 128.0.0.0/2 -j DROP
-A INPUT -p tcp --dport 3389 -j ACCEPT
COMMIT
"""
        partial_result = self.run_export(partial)
        self.assertEqual(partial_result.returncode, 1, partial_result.stderr)
        self.assertEqual(json.loads(partial_result.stdout)["findings"], [
            {"rule_id": "INPUT:L5", "code": "UNRESTRICTED_ADMIN_SOURCE", "severity": "HIGH",
             "detail": "TCP/3389 is allowed from all IPv4 addresses; review source restrictions."},
            {"rule_id": "INPUT:L5", "code": "PARTIALLY_SHADOWED_RULE", "severity": "INFO",
             "overlapping_rule_ids": ["INPUT:L3", "INPUT:L4"],
             "overlap_example": {"source": "0.0.0.0/1", "destination": "0.0.0.0/0",
                                 "protocol": "tcp", "port": 3389},
             "detail": "Earlier terminating INPUT rules match part, but not all, of this rule's traffic; review redundant matches and rule order."},
        ])

        complete = partial.replace("128.0.0.0/2", "128.0.0.0/1")
        complete_result = self.run_export(complete)
        self.assertEqual(complete_result.returncode, 1, complete_result.stderr)
        self.assertEqual(json.loads(complete_result.stdout)["findings"], [{
            "rule_id": "INPUT:L5", "code": "COMBINED_SHADOWED_RULE", "severity": "INFO",
            "covering_rule_ids": ["INPUT:L3", "INPUT:L4"],
            "detail": "INPUT:L3 and INPUT:L4 jointly match all traffic for this later rule; it cannot be reached in this INPUT model.",
        }])

    def test_combined_source_and_destination_coverage(self):
        export = """*filter
:INPUT DROP [0:0]
-A INPUT -s 0.0.0.0/1 -d 10.0.0.0/8 -p tcp --dport 22 -j DROP
-A INPUT -s 0.0.0.0/1 -d 11.0.0.0/8 -p tcp --dport 22 -j DROP
-A INPUT -s 128.0.0.0/1 -d 10.0.0.0/7 -p tcp --dport 22 -j REJECT
-A INPUT -d 10.0.0.0/7 -p tcp --dport 22 -j ACCEPT
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [{
            "rule_id": "INPUT:L6", "code": "COMBINED_SHADOWED_RULE", "severity": "INFO",
            "covering_rule_ids": ["INPUT:L3", "INPUT:L4", "INPUT:L5"],
            "detail": ("INPUT:L3, INPUT:L4, and INPUT:L5 jointly match all traffic "
                       "for this later rule; it cannot be reached in this INPUT model."),
        }])

    def test_combined_coverage_requires_matching_protocol_and_port(self):
        export = """*filter
:INPUT DROP [0:0]
-A INPUT -s 0.0.0.0/1 -p tcp --dport 22 -j DROP
-A INPUT -s 128.0.0.0/1 -p udp --dport 22 -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [
            {"rule_id": "INPUT:L5", "code": "UNRESTRICTED_ADMIN_SOURCE", "severity": "HIGH",
             "detail": "TCP/22 is allowed from all IPv4 addresses; review source restrictions."},
            {"rule_id": "INPUT:L5", "code": "PARTIALLY_SHADOWED_RULE", "severity": "INFO",
             "overlapping_rule_ids": ["INPUT:L3"],
             "overlap_example": {"source": "0.0.0.0/1", "destination": "0.0.0.0/0",
                                 "protocol": "tcp", "port": 22},
             "detail": "Earlier terminating INPUT rules match part, but not all, of this rule's traffic; review redundant matches and rule order."},
        ])

    def test_specific_port_partially_overlaps_later_any_protocol(self):
        export = """*filter
:INPUT DROP [0:0]
-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j DROP
-A INPUT -j ACCEPT
COMMIT
"""
        result = self.run_export(export)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [
            {"rule_id": "INPUT:L4", "code": "ANY_TO_ANY_ALLOW", "severity": "CRITICAL",
             "detail": "Allows all protocols between all IPv4 addresses; verify intent and scope."},
            {"rule_id": "INPUT:L4", "code": "PARTIALLY_SHADOWED_RULE", "severity": "INFO",
             "overlapping_rule_ids": ["INPUT:L3"],
             "overlap_example": {"source": "192.0.2.0/24", "destination": "0.0.0.0/0",
                                 "protocol": "tcp", "port": 443},
             "detail": "Earlier terminating INPUT rules match part, but not all, of this rule's traffic; review redundant matches and rule order."},
        ])

    def test_aborts_exact_coverage_when_region_budget_exceeded(self):
        rules = [
            {"id": "INPUT:L3", "source": "10.0.0.1/32", "destination": "0.0.0.0/0",
             "protocol": "any", "port": None},
            {"id": "INPUT:L4", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
             "protocol": "tcp", "port": 22},
        ]
        with patch("rule_order.MAX_UNCOVERED_REGIONS", 1):
            with self.assertRaisesRegex(ValueError, "coverage too complex"):
                combined_shadowed_by_prior_rules(rules, {})

    def test_retained_iptables_reports_match_current_cli(self):
        base = SCRIPT.parent
        for name in ("iptables_filter", "iptables_shadow", "iptables_combined_shadow",
                     "iptables_partial_overlap"):
            with self.subTest(name=name):
                fixture = (base / "fixtures" / f"{name}.rules").read_text(encoding="utf-8")
                result = self.run_export(fixture)
                self.assertEqual(result.returncode, 1, result.stderr)
                report_name = name.replace("iptables_", "") + "_report.json"
                if name == "iptables_filter":
                    report_name = "iptables_report.json"
                self.assertEqual(json.loads(result.stdout),
                                 json.loads((base / "artifacts" / report_name).read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
