import copy
import os
import platform
import unittest

from audit_lab import findings, run_lab, validate


class PolicyTests(unittest.TestCase):
    def test_unsafe_modes_match_both_policies(self):
        rows = [{"path": "secrets/service.env", "mode": 0o644},
                {"path": "bin/rotate_logs.sh", "mode": 0o777},
                {"path": "public/notice.txt", "mode": 0o644}]
        self.assertEqual([r["path"] for r in findings(rows)], ["bin/rotate_logs.sh", "secrets/service.env"])

    def test_corrected_modes_preserve_public_read_control(self):
        self.assertEqual(findings([{"path": "secrets/service.env", "mode": 0o600},
                                   {"path": "bin/rotate_logs.sh", "mode": 0o755},
                                   {"path": "public/notice.txt", "mode": 0o644}]), [])

    def test_group_read_alone_still_flags_secret(self):
        self.assertEqual(len(findings([{"path": "secrets/service.env", "mode": 0o640}])), 1)

    def test_other_write_alone_still_flags_script(self):
        self.assertEqual(len(findings([{"path": "bin/rotate_logs.sh", "mode": 0o757}])), 1)

    def test_owner_write_is_not_mistaken_for_other_write(self):
        self.assertEqual(findings([{"path": "bin/rotate_logs.sh", "mode": 0o700}]), [])

    def test_world_writable_public_file_is_not_a_benign_control(self):
        self.assertEqual(len(findings([{"path": "public/notice.txt", "mode": 0o666}])), 1)

    def test_duplicate_asset_rejected(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            findings([{"path": "public/notice.txt", "mode": 0o644}]*2)

class KernelProofTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and os.geteuid() == 0, "Requires isolated Linux UID-drop probe")
    def test_executed_kernel_access_and_unchanged_control(self):
        report = run_lab()
        validate(report)
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(report["after"]["probe"]["access"]["secret_read"], "denied")
        tampered = copy.deepcopy(report)
        tampered["after"]["probe"]["access"]["public_read"] = "denied"
        with self.assertRaises(AssertionError):
            validate(tampered)
        tampered = copy.deepcopy(report)
        tampered["after"]["assets"][0]["sha256"] = "changed"
        with self.assertRaises(AssertionError):
            validate(tampered)


if __name__ == "__main__":
    unittest.main()
