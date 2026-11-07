import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from detect_auth import find_suspicious_logins, parse_timestamp, read_events

BASE = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def event(minute, kind, username="alice", source_ip="192.0.2.15"):
    return {
        "dt": BASE + timedelta(minutes=minute),
        "username": username,
        "source_ip": source_ip,
        "host": "LAB-DC1",
        "event_type": kind,
    }


class DetectionTests(unittest.TestCase):
    def test_synthetic_fixture_has_one_finding(self):
        source = Path(__file__).parent / "auth_events.csv"
        results = find_suspicious_logins(read_events(source))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "alice")
        self.assertEqual(results[0]["failure_count_in_window"], 6)

    def test_below_threshold(self):
        self.assertEqual(find_suspicious_logins(
            [event(i, "login_failure") for i in range(4)] +
            [event(4, "login_success")]), [])

    def test_expired_window(self):
        self.assertEqual(find_suspicious_logins(
            [event(i, "login_failure") for i in range(5)] +
            [event(20, "login_success")]), [])

    def test_user_and_ip_isolation(self):
        events = [event(i, "login_failure") for i in range(5)]
        events.extend([event(5, "login_success", "bob"),
                       event(6, "login_success", "alice", "198.51.100.44")])
        self.assertEqual(find_suspicious_logins(events), [])

    def test_out_of_order(self):
        events = [event(6, "login_success")] + [
            event(i, "login_failure") for i in range(5)]
        self.assertEqual(len(find_suspicious_logins(events)), 1)

    def test_inclusive_window_boundary(self):
        events = [event(i, "login_failure") for i in range(5)]
        events.append(event(10, "login_success"))
        self.assertEqual(len(find_suspicious_logins(events)), 1)

    def test_invalid_timestamp(self):
        with self.assertRaises(ValueError):
            parse_timestamp("not-a-time")

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            find_suspicious_logins([], threshold=0)

    def test_suppress_consecutive_successes(self):
        events = [event(i, "login_failure") for i in range(5)]
        events.extend([event(5, "login_success"), event(6, "login_success")])
        self.assertEqual(len(find_suspicious_logins(events)), 1)


    def test_success_resets_below_threshold(self):
        events = [event(i, "login_failure") for i in range(3)]
        events += [event(3, "login_success"), event(4, "login_failure"),
                   event(5, "login_failure"), event(6, "login_success")]
        self.assertEqual(find_suspicious_logins(events), [])

    def test_new_burst_after_nonalerting_success(self):
        events = [event(i, "login_failure") for i in range(3)]
        events += [event(3, "login_success")]
        events += [event(i, "login_failure") for i in range(4, 9)]
        events += [event(9, "login_success")]
        results = find_suspicious_logins(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["failure_count_in_window"], 5)
        self.assertEqual(results[0]["earliest_failure_utc"], "2026-10-01T09:04:00Z")

    def test_interleaved_different_users_are_independent(self):
        events = [event(i * 2, "login_failure", "alice") for i in range(5)]
        events += [event(i * 2 + 1, "login_failure", "bob") for i in range(5)]
        events += [event(9, "login_success", "alice"),
                   event(10, "login_success", "bob")]
        results = find_suspicious_logins(events)
        self.assertEqual({r["username"] for r in results}, {"alice", "bob"})

    def test_reject_malformed_csv_row(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "bad.csv"
            csv_path.write_text(
                "timestamp,username,source_ip,host,event_type\n"
                "2026-10-01T09:00:00Z,alice,192.0.2.15,LAB-DC1,login_failure,EXTRA\n",
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Line 2"):
                read_events(csv_path)

    def test_validation_matrix_expected_matches_python_detector(self):
        import json
        from validate_matrix import normalized_python_rows, normalized_expected_rows
        directory = Path(__file__).parent
        actual = normalized_python_rows(find_suspicious_logins(
            read_events(directory / "validation_events.csv")))
        expected = normalized_expected_rows(json.loads(
            (directory / "expected_findings.json").read_text(encoding="utf-8")))
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 5)

    def test_export_checker_rejects_missing_findings(self):
        import tempfile
        import json
        from validate_matrix import read_splunk_export, normalized_expected_rows
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "empty.csv"
            export.write_text("timestamp,username,source_ip,failure_count_in_window\n",
                              encoding="utf-8")
            expected = normalized_expected_rows(json.loads(
                (Path(__file__).parent / "expected_findings.json").read_text(
                    encoding="utf-8")))
            self.assertNotEqual(read_splunk_export(export), expected)


if __name__ == "__main__":
    unittest.main()
