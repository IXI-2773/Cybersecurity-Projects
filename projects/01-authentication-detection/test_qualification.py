import csv
import tempfile
import unittest
from pathlib import Path
from qualify_exports import HERE, qualify, read_raw_rows

RAW_FIELDS = ("timestamp", "username", "source_ip", "host", "event_type", "scenario")
OUT_FIELDS = ("timestamp", "username", "source_ip", "failure_count_in_window")


def copy_csv_rows(rows, path, fields):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in fields} for row in rows)


def rows_from_csv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class QualificationExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.raw_path = Path(self.temp.name) / "raw.csv"
        self.findings_path = Path(self.temp.name) / "findings.csv"
        self.raw_rows = rows_from_csv(HERE / "validation_events.csv")
        self.expected = __import__("json").loads(
            (HERE / "expected_findings.json").read_text(encoding="utf-8"))["expected_findings"]
        copy_csv_rows(self.raw_rows, self.raw_path, RAW_FIELDS)
        copy_csv_rows(self.expected, self.findings_path, OUT_FIELDS)

    def test_identical_fixture_comparison_passes_but_not_runtime(self):
        report = qualify(self.raw_path, self.findings_path)
        self.assertEqual(report["status"], "CSV_PARITY_PASS")
        self.assertEqual(report["raw_events_expected"], 64)
        self.assertEqual(report["findings_expected"], 5)
        self.assertFalse(report["splunk_runtime_validated"])
        self.assertEqual(report["source_authenticity"], "NOT_ESTABLISHED")

    def test_missing_raw_event_rejected(self):
        copy_csv_rows(self.raw_rows[:-1], self.raw_path, RAW_FIELDS)
        report = qualify(self.raw_path, self.findings_path)
        self.assertEqual(report["status"], "CSV_PARITY_FAIL")
        self.assertEqual(report["raw_missing"], 1)

    def test_duplicate_raw_event_rejected(self):
        copy_csv_rows(self.raw_rows + [self.raw_rows[0]], self.raw_path, RAW_FIELDS)
        report = qualify(self.raw_path, self.findings_path)
        self.assertEqual(report["raw_unexpected"], 1)
        self.assertFalse(report["raw_records_match"])

    def test_missing_detection_rejected(self):
        copy_csv_rows(self.expected[:-1], self.findings_path, OUT_FIELDS)
        report = qualify(self.raw_path, self.findings_path)
        self.assertEqual(report["findings_missing"], 1)
        self.assertEqual(report["status"], "CSV_PARITY_FAIL")

    def test_malformed_raw_export_rejected(self):
        self.raw_path.write_text("timestamp,username\nbad,a\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing required columns"):
            read_raw_rows(self.raw_path)

    def test_invalid_findings_count_rejected(self):
        invalid = [dict(self.expected[0], failure_count_in_window="four")]
        copy_csv_rows(invalid, self.findings_path, OUT_FIELDS)
        with self.assertRaises(ValueError):
            qualify(self.raw_path, self.findings_path)


if __name__ == "__main__":
    unittest.main()
