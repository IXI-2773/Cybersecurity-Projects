"""Behavior checks for the offline, illustrative firewall policy reviewer."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("review.py")


class FirewallPolicyReviewTests(unittest.TestCase):
    def run_policy(self, policy):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "policy.json"
            input_path.write_text(json.dumps(policy), encoding="utf-8")
            return subprocess.run([sys.executable, str(SCRIPT), str(input_path)],
                                  capture_output=True, text=True, check=False)

    def test_flags_unrestricted_admin_access_without_flagging_narrow_web_rule(self):
        policy = {
            "name": "synthetic policy",
            "default_action": "deny",
            "rules": [
                {"id": "WEB", "action": "allow", "source": "0.0.0.0/0",
                 "destination": "192.0.2.10/32", "protocol": "tcp", "port": 443},
                {"id": "RDP", "action": "allow", "source": "0.0.0.0/0",
                 "destination": "10.10.1.5/32", "protocol": "tcp", "port": 3389},
                {"id": "MGMT", "action": "allow", "source": "10.10.0.0/24",
                 "destination": "10.10.1.5/32", "protocol": "tcp", "port": 22},
            ],
        }
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["policy"], "synthetic policy")
        self.assertEqual(report["rule_count"], 3)
        self.assertEqual(report["findings"], [
            {"rule_id": "RDP", "code": "UNRESTRICTED_ADMIN_SOURCE", "severity": "HIGH",
             "detail": "TCP/3389 is allowed from all IPv4 addresses; review source restrictions."}
        ])

    def test_flags_any_to_any_allow_and_retains_rule_id(self):
        policy = {"name": "synthetic", "default_action": "deny", "rules": [
            {"id": "BROAD", "action": "allow", "source": "0.0.0.0/0",
             "destination": "0.0.0.0/0", "protocol": "any", "port": None},
        ]}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(run.stdout)["findings"], [
            {"rule_id": "BROAD", "code": "ANY_TO_ANY_ALLOW", "severity": "CRITICAL",
             "detail": "Allows all protocols between all IPv4 addresses; verify intent and scope."}
        ])

    def test_flags_allow_by_default_even_without_explicit_rules(self):
        run = self.run_policy({"name": "synthetic", "default_action": "allow", "rules": []})
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(run.stdout)["findings"], [
            {"rule_id": None, "code": "DEFAULT_ALLOW", "severity": "HIGH",
             "detail": "Policy fallback action is allow; verify explicit least-privilege boundaries."}
        ])

    def test_rejects_ambiguous_policy_fields_instead_of_reporting_clean(self):
        valid_rule = {"id": "TEST", "action": "allow", "source": "192.0.2.0/24",
                      "destination": "198.51.100.10/32", "protocol": "tcp", "port": 443}
        invalid_rules = [
            [{**valid_rule, "action": "permit"}],
            [{**valid_rule, "protocol": "unknown"}],
            [{**valid_rule, "port": 70000}],
            [{**valid_rule, "destination": "2001:db8::/32"}],
            [valid_rule, dict(valid_rule)],
        ]
        for rules in invalid_rules:
            with self.subTest(rules=rules):
                run = self.run_policy({"name": "synthetic", "default_action": "deny",
                                       "rules": rules})
                self.assertEqual(run.returncode, 2, run.stdout)
                self.assertEqual(run.stdout, "")
                self.assertIn("Invalid policy:", run.stderr)

        run = self.run_policy({"name": "synthetic", "default_action": "maybe", "rules": []})
        self.assertEqual(run.returncode, 2, run.stdout)


if __name__ == "__main__":
    unittest.main()
