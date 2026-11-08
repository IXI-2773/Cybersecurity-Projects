"""Contract tests for the offline, synthetic AWS IAM policy reviewer."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("review.py")


class IamPolicyReviewTests(unittest.TestCase):
    def run_policy(self, policy):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "identity_policy.json"
            source.write_text(json.dumps(policy), encoding="utf-8")
            return subprocess.run([sys.executable, str(SCRIPT), str(source)],
                                  capture_output=True, text=True, check=False)

    def test_reports_literal_wildcards_with_statement_evidence(self):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "RoleHandoff", "Effect": "Allow", "Action": ["iam:PassRole"],
             "Resource": "*", "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}},
            {"Sid": "ExplicitDeny", "Effect": "Deny", "Action": "*", "Resource": "*"},
        ]}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["statement_count"], 3)
        self.assertEqual(report["findings"], [
            {"statement_id": "Admin", "code": "ALL_ACTIONS_ALL_RESOURCES",
             "priority": "REVIEW", "condition_present": False,
             "detail": "Allow statement specifies Action * and Resource *; review its intended scope."},
            {"statement_id": "RoleHandoff", "code": "PASSROLE_ALL_RESOURCES",
             "priority": "REVIEW", "condition_present": True,
             "detail": "Allow statement lists iam:PassRole with Resource *; review permitted roles and conditions."},
        ])

    def test_restricted_synthetic_policy_has_no_modeled_findings(self):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "BucketRead", "Effect": "Allow", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::example-bucket/*"},
            {"Effect": "Allow", "Action": "iam:PassRole",
             "Resource": "arn:aws:iam::123456789012:role/example-app-role"},
        ]}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["findings"], [])
        self.assertIn("not effective access", report["scope"])

    def test_flags_literal_service_wildcard_without_assuming_effective_permissions(self):
        policy = {"Version": "2012-10-17", "Statement": {
            "Effect": "Allow", "Action": ["s3:*", "s3:ListBucket"], "Resource": "*"
        }}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["findings"], [{
            "statement_id": "Statement[1]", "code": "SERVICE_ACTIONS_ALL_RESOURCES",
            "priority": "REVIEW", "condition_present": False,
            "detail": "Allow statement lists service-wide action wildcard(s) s3:* with Resource *; review scope.",
        }])

    def test_flags_service_wildcard_with_hyphenated_aws_namespace(self):
        # AWS API Gateway uses execute-api; excluding hyphens misses this valid action namespace.
        policy = {"Version": "2012-10-17", "Statement": {
            "Sid": "AllApiExecution", "Effect": "Allow",
            "Action": "execute-api:*", "Resource": "*"
        }}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual([finding["code"] for finding in report["findings"]],
                         ["SERVICE_ACTIONS_ALL_RESOURCES"])

    def test_passrole_action_matching_is_case_insensitive(self):
        # A case-sensitive check silently misses an AWS-equivalent spelling.
        policy = {"Version": "2012-10-17", "Statement": {
            "Effect": "Allow", "Action": "IAM:passrole", "Resource": "*"
        }}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual([finding["code"] for finding in report["findings"]],
                         ["PASSROLE_ALL_RESOURCES"])

    def test_flags_wildcard_assumerole_but_not_explicit_role_arn(self):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "AnyTrustingRole", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
            {"Sid": "NamedRole", "Effect": "Allow", "Action": "sts:AssumeRole",
             "Resource": "arn:aws:iam::123456789012:role/example-approved-role"},
            {"Sid": "Denied", "Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"},
        ]}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["findings"], [{
            "statement_id": "AnyTrustingRole", "code": "ASSUMEROLE_ALL_RESOURCES",
            "priority": "REVIEW", "condition_present": False,
            "detail": "Allow statement lists sts:AssumeRole with Resource *; review trusting roles and conditions.",
        }])

    def test_independent_action_patterns_in_same_statement_are_not_hidden(self):
        # Ordered branching previously concealed later patterns in a mixed action list.
        policy = {"Version": "2012-10-17", "Statement": {
            "Sid": "MixedActions", "Effect": "Allow",
            "Action": ["S3:*", "IAM:PassRole", "STS:assumerole"],
            "Resource": "*", "Condition": {"StringEquals": {"aws:PrincipalTag/team": "Example"}}
        }}
        run = self.run_policy(policy)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual({finding["code"] for finding in report["findings"]}, {
            "SERVICE_ACTIONS_ALL_RESOURCES", "PASSROLE_ALL_RESOURCES", "ASSUMEROLE_ALL_RESOURCES"
        })
        self.assertEqual(len(report["findings"]), 3)
        self.assertTrue(all(finding["condition_present"] for finding in report["findings"]))

    def test_rejects_unsupported_or_malformed_policy_instead_of_reporting_clean(self):
        statement = {"Effect": "Allow", "Action": "s3:GetObject",
                     "Resource": "arn:aws:s3:::example-bucket/*"}
        invalid = [
            {**statement, "NotAction": "s3:DeleteObject"},
            {**statement, "Principal": "*"},
            {**statement, "Resource": True},
            {**statement, "Action": ["s3:GetObject", 4]},
            {**statement, "Condition": "ignored"},
            {"Effect": "Allow", "Action": "s3:GetObject"},
        ]
        for entry in invalid:
            with self.subTest(statement=entry):
                run = self.run_policy({"Version": "2012-10-17", "Statement": [entry]})
                self.assertEqual(run.returncode, 2, run.stdout)
                self.assertEqual(run.stdout, "")
                self.assertIn("Unsupported policy:", run.stderr)

    def test_retained_synthetic_reports_match_current_cli(self):
        project = SCRIPT.parent
        for name, expected_exit in (("broad", 1), ("restricted", 0),
                                    ("assumerole_broad", 1), ("assumerole_restricted", 0)):
            with self.subTest(name=name):
                source = project / "fixtures" / f"{name}_identity_policy.json"
                report = project / "artifacts" / f"{name}_report.json"
                run = subprocess.run([sys.executable, str(SCRIPT), str(source)],
                                     capture_output=True, text=True, check=False)
                self.assertEqual(run.returncode, expected_exit, run.stderr)
                self.assertEqual(run.stdout, report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
