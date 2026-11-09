"""Offline, hand-derived acceptance cases for closed destination-port ranges."""

import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rule_order import combined_shadowed_by_prior_rules


SCRIPT = Path(__file__).with_name("review.py")
EXAMPLE_RULES = [
    "-A INPUT -s 10.0.0.0/24 -p tcp --dport 80:90 -j ACCEPT",
    "-A INPUT -s 10.0.0.128/25 -p tcp --dport 85:95 -j DROP",
]


class PortRangeTests(unittest.TestCase):
    def run_input(self, contents, *args):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.txt"
            path.write_text(contents, encoding="utf-8")
            return subprocess.run([sys.executable, str(SCRIPT), *args, str(path)],
                                  capture_output=True, text=True, check=False)

    def run_rules(self, rules, *args):
        contents = "\n".join(["*filter", ":INPUT DROP [0:0]", *rules, "COMMIT", ""])
        return self.run_input(contents, "--format", "iptables-save", *args)

    def findings(self, rules):
        result = self.run_rules(rules)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return json.loads(result.stdout)["findings"]

    def test_partial_range_overlap_keeps_exact_source_and_port_intersection(self):
        findings = self.findings(EXAMPLE_RULES)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["code"], "PARTIALLY_SHADOWED_RULE")
        self.assertEqual(findings[0]["rule_id"], "INPUT:L4")
        self.assertEqual(findings[0]["overlapping_rule_ids"], ["INPUT:L3"])
        self.assertEqual(findings[0]["overlap_example"], {
            "source": "10.0.0.128/25", "destination": "0.0.0.0/0",
            "protocol": "tcp", "port": 85, "port_end": 90,
        })

    def test_containing_range_fully_shadows_later_range(self):
        findings = self.findings([
            "-A INPUT -s 10.0.0.0/24 -p tcp --dport 80:100 -j DROP",
            "-A INPUT -s 10.0.0.128/25 -p tcp --dport 85:95 -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings], ["SHADOWED_RULE"])
        self.assertEqual(findings[0]["covering_rule_ids"], ["INPUT:L3"])

    def test_touching_closed_ranges_have_one_port_of_overlap(self):
        findings = self.findings([
            "-A INPUT -p tcp --dport 80:90 -j DROP",
            "-A INPUT -p tcp --dport 90:95 -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings], ["PARTIALLY_SHADOWED_RULE"])
        self.assertEqual(findings[0]["overlap_example"], {
            "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
            "protocol": "tcp", "port": 90,
        })

    def test_disjoint_ports_protocols_or_addresses_do_not_overlap(self):
        cases = [
            ("-p tcp --dport 80:89", "-p tcp --dport 90:95"),
            ("-p tcp --dport 80:90", "-p udp --dport 85:95"),
            ("-s 10.0.0.0/24 -p tcp --dport 80:90",
             "-s 10.0.1.0/24 -p tcp --dport 85:95"),
            ("-d 192.0.2.0/25 -p tcp --dport 80:90",
             "-d 192.0.2.128/25 -p tcp --dport 85:95"),
        ]
        for earlier, later in cases:
            with self.subTest(earlier=earlier, later=later):
                result = self.run_rules([f"-A INPUT {earlier} -j DROP",
                                         f"-A INPUT {later} -j ACCEPT"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_adjacent_ranges_jointly_cover_later_range(self):
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                findings = self.findings([
                    f"-A INPUT -p {protocol} --dport 80:84 -j DROP",
                    f"-A INPUT -p {protocol} --dport 85:95 -j REJECT",
                    f"-A INPUT -p {protocol} --dport 80:95 -j ACCEPT",
                ])
                self.assertEqual([f["code"] for f in findings], ["COMBINED_SHADOWED_RULE"])
                self.assertEqual(findings[0]["covering_rule_ids"], ["INPUT:L3", "INPUT:L4"])

    def test_one_port_gap_prevents_combined_full_shadow(self):
        findings = self.findings([
            "-A INPUT -p tcp --dport 80:84 -j DROP",
            "-A INPUT -p tcp --dport 86:95 -j DROP",
            "-A INPUT -p tcp --dport 80:95 -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings], ["PARTIALLY_SHADOWED_RULE"])
        self.assertEqual(findings[0]["overlapping_rule_ids"], ["INPUT:L3", "INPUT:L4"])
        self.assertEqual(findings[0]["overlap_example"]["port"], 80)
        self.assertEqual(findings[0]["overlap_example"]["port_end"], 84)

    def test_separate_address_and_port_unions_do_not_imply_full_coverage(self):
        findings = self.findings([
            "-A INPUT -s 10.0.0.0/25 -p tcp --dport 80:84 -j DROP",
            "-A INPUT -s 10.0.0.128/25 -p tcp --dport 85:95 -j DROP",
            "-A INPUT -s 10.0.0.0/24 -p tcp --dport 80:95 -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings], ["PARTIALLY_SHADOWED_RULE"])
        self.assertEqual(findings[0]["overlapping_rule_ids"], ["INPUT:L3", "INPUT:L4"])

    def test_catchall_still_shadows_range_and_suppresses_admin_warning(self):
        findings = self.findings([
            "-A INPUT -j DROP",
            "-A INPUT -p tcp --dport 3380:3400 -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings], ["SHADOWED_RULE"])

    def test_all_tcp_and_udp_ports_cannot_fully_cover_any_protocol(self):
        findings = self.findings([
            "-A INPUT -p tcp --dport 1:65535 -j DROP",
            "-A INPUT -p udp --dport 1:65535 -j DROP",
            "-A INPUT -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings],
                         ["ANY_TO_ANY_ALLOW", "PARTIALLY_SHADOWED_RULE"])
        self.assertEqual(findings[1]["overlap_example"]["protocol"], "tcp")
        self.assertEqual(findings[1]["overlap_example"]["port_end"], 65535)

    def test_admin_service_inside_range_is_flagged(self):
        findings = self.findings(["-A INPUT -p tcp --dport 20:25 -j ACCEPT"])
        self.assertEqual(findings, [{
            "rule_id": "INPUT:L3", "code": "UNRESTRICTED_ADMIN_SOURCE",
            "severity": "HIGH", "service_port": 22,
            "detail": "TCP/22 is allowed from all IPv4 addresses; review source restrictions.",
        }])

    def test_covered_admin_slice_does_not_warn_for_partially_shadowed_range(self):
        for blockers in (["-A INPUT -p tcp --dport 22 -j DROP"], [
                "-A INPUT -s 0.0.0.0/1 -p tcp --dport 22 -j DROP",
                "-A INPUT -s 128.0.0.0/1 -p tcp --dport 22 -j DROP"]):
            with self.subTest(blockers=blockers):
                findings = self.findings([*blockers,
                    "-A INPUT -p tcp --dport 20:25 -j ACCEPT"])
                self.assertEqual([f["code"] for f in findings], ["PARTIALLY_SHADOWED_RULE"])

    def test_uncovered_admin_slice_keeps_warning(self):
        findings = self.findings([
            "-A INPUT -p tcp --dport 20:21 -j DROP",
            "-A INPUT -p tcp --dport 20:25 -j ACCEPT",
        ])
        self.assertEqual([f["code"] for f in findings],
                         ["UNRESTRICTED_ADMIN_SOURCE", "PARTIALLY_SHADOWED_RULE"])
        self.assertEqual(findings[0]["service_port"], 22)

    def test_only_covered_admin_service_is_suppressed_in_multi_service_range(self):
        findings = self.findings([
            "-A INPUT -p tcp --dport 3389 -j DROP",
            "-A INPUT -p tcp --dport 3380:5990 -j ACCEPT",
        ])
        warnings = [f for f in findings if f["code"] == "UNRESTRICTED_ADMIN_SOURCE"]
        self.assertEqual([f["service_port"] for f in warnings], [5985, 5986])
        self.assertEqual(findings[-1]["code"], "PARTIALLY_SHADOWED_RULE")

    def test_singleton_range_keeps_scalar_report_contract(self):
        findings = self.findings(["-A INPUT -p tcp --dport 3389:3389 -j ACCEPT"])
        self.assertEqual(findings, [{
            "rule_id": "INPUT:L3", "code": "UNRESTRICTED_ADMIN_SOURCE",
            "severity": "HIGH",
            "detail": "TCP/3389 is allowed from all IPv4 addresses; review source restrictions.",
        }])

    def test_json_range_keeps_default_static_analysis_without_order_claims(self):
        policy = {"name": "synthetic", "default_action": "deny", "rules": [
            {"id": "DROP", "action": "deny", "source": "0.0.0.0/0",
             "destination": "0.0.0.0/0", "protocol": "tcp", "port": 22},
            {"id": "RANGE", "action": "allow", "source": "0.0.0.0/0",
             "destination": "192.0.2.10/32", "protocol": "tcp", "port": 20,
             "port_end": 25},
        ]}
        result = self.run_input(json.dumps(policy))
        self.assertEqual(result.returncode, 1, result.stderr)
        findings = json.loads(result.stdout)["findings"]
        self.assertEqual([f["code"] for f in findings], ["UNRESTRICTED_ADMIN_SOURCE"])
        self.assertEqual(findings[0]["service_port"], 22)

    def test_rejects_invalid_or_unsupported_iptables_port_tokens(self):
        for token in ("0:22", "80:65536", "95:85", ":443", "443:",
                      "80:90:100", "80,443", "https", "80-90", "80:90x"):
            with self.subTest(token=token):
                result = self.run_rules([f"-A INPUT -p tcp --dport {token} -j ACCEPT"])
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid policy:", result.stderr)

    def test_rejects_invalid_json_range_endpoints_instead_of_ignoring_them(self):
        rule = {"id": "TEST", "action": "allow", "source": "192.0.2.0/24",
                "destination": "198.51.100.10/32", "protocol": "tcp", "port": 80}
        invalid = [{**rule, "port_end": end}
                   for end in (79, 65536, True, 90.0, "90", None)]
        invalid.append({**rule, "protocol": "any", "port": None, "port_end": 90})
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                result = self.run_input(json.dumps({"name": "synthetic",
                    "default_action": "deny", "rules": [candidate]}))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_csv_and_html_show_range_witness_without_losing_end_bound(self):
        csv_result = self.run_rules(EXAMPLE_RULES, "--report-format", "csv")
        self.assertEqual(csv_result.returncode, 1, csv_result.stderr)
        rows = list(csv.DictReader(io.StringIO(csv_result.stdout)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["overlap_example"],
                         "10.0.0.128/25 → 0.0.0.0/0 (tcp/85:90)")
        html = self.run_rules(EXAMPLE_RULES, "--report-format", "html")
        self.assertEqual(html.returncode, 1, html.stderr)
        self.assertIn("10.0.0.128/25 → 0.0.0.0/0 (tcp/85:90)", html.stdout)

    def test_port_partitioning_respects_existing_region_budget(self):
        rules = [
            {"id": "FIRST", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
             "protocol": "tcp", "port": 90},
            {"id": "LATER", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
             "protocol": "tcp", "port": 80, "port_end": 100},
        ]
        with patch("rule_order.MAX_UNCOVERED_REGIONS", 1):
            with self.assertRaisesRegex(ValueError, "coverage too complex"):
                combined_shadowed_by_prior_rules(rules, {})

    def test_retained_range_reports_reproduce_from_cli(self):
        base = SCRIPT.parent
        for fixture_name, format_name, expected_exit in (
                ("overlap", "json", 1), ("overlap", "html", 1),
                ("overlap", "csv", 1), ("disjoint", "json", 0)):
            with self.subTest(fixture=fixture_name, format=format_name):
                fixture = base / "fixtures" / f"iptables_port_range_{fixture_name}.rules"
                artifact = base / "artifacts" / f"port_range_{fixture_name}_report.{format_name}"
                self.assertTrue(artifact.is_file(), "retained range evidence is missing")
                result = self.run_input(fixture.read_text(encoding="utf-8"),
                                        "--format", "iptables-save", "--report-format", format_name)
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertEqual(result.stdout, artifact.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
