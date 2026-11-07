from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "analyze_account.py"


def load_module():
    spec = importlib.util.spec_from_file_location("account_lab", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load analyzer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AccountAnalysisTests(unittest.TestCase):
    def test_analysis_matches_frozen_oracle_and_order(self) -> None:
        result = load_module().analyze_events(HERE / "account_events.csv")
        expected = json.loads((HERE / "expected_analysis.json").read_text())
        self.assertEqual(result, expected)
        times = [event["timestamp_utc"] for event in result["timeline"]]
        self.assertEqual(times, sorted(times))

    def test_detects_failure_success_and_privilege_chain(self) -> None:
        result = load_module().analyze_events(HERE / "account_events.csv")
        self.assertEqual(
            [finding["id"] for finding in result["findings"]],
            ["ACCT_FAILURE_BURST", "ACCT_SUCCESS_AFTER_FAILURES", "ACCT_PRIVILEGE_CHANGE"],
        )
        self.assertEqual(result["subject_account"], "dlopez")
        self.assertIn("administrator", result["alternative_explanations"].lower())

    def test_rejects_unknown_event_id(self) -> None:
        header = "timestamp_utc,event_id,account,source_ip,host,outcome,detail\n"
        row = "2026-10-20T16:00:00Z,9999,user,192.0.2.1,DC01,success,Unknown\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text(header + row, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "event_id"):
                load_module().load_events(path)

    def test_rejects_invalid_timestamp(self) -> None:
        header = "timestamp_utc,event_id,account,source_ip,host,outcome,detail\n"
        row = "not-a-time,4624,user,192.0.2.1,DC01,success,Login\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text(header + row, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "timestamp"):
                load_module().load_events(path)


if __name__ == "__main__":
    unittest.main()
