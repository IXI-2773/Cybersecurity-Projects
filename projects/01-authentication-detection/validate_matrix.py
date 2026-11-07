"""Verify the Python reference corpus; optionally compare a real Splunk CSV export.

Passing the offline checks does NOT establish that Splunk executed the SPL.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from detect_auth import find_suspicious_logins, read_events

HERE = Path(__file__).resolve().parent
FIELDS = ("timestamp", "username", "source_ip", "failure_count_in_window")


def normalized_python_rows(findings: list[dict]) -> list[tuple]:
    return sorted((
        f["observed_at_utc"], f["username"], f["source_ip"],
        int(f["failure_count_in_window"])
    ) for f in findings)


def normalized_expected_rows(data: dict) -> list[tuple]:
    if data.get("schema") != "portfolio.auth-validation.v1":
        raise ValueError("Unrecognized validation expectation format")
    return sorted((
        row["timestamp"], row["username"], row["source_ip"],
        int(row["failure_count_in_window"])
    ) for row in data["expected_findings"])


def read_splunk_export(path: Path) -> list[tuple]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not set(FIELDS).issubset(reader.fieldnames):
            raise ValueError("Splunk CSV export missing required fields: " +
                             ", ".join(sorted(set(FIELDS) - set(reader.fieldnames or []))))
        return sorted((
            row["timestamp"].strip(), row["username"].strip(),
            row["source_ip"].strip(), int(row["failure_count_in_window"])
        ) for row in reader)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--splunk-export", type=Path, help="Actual Splunk search Results CSV; omitted = offline only")
    args = parser.parse_args()
    try:
        expected = normalized_expected_rows(json.loads(
            (HERE / "expected_findings.json").read_text(encoding="utf-8")))
        actual_python = normalized_python_rows(find_suspicious_logins(
            read_events(HERE / "validation_events.csv")))
        if actual_python != expected:
            print(json.dumps({"status": "FAIL", "check": "offline_python_oracle",
                              "expected": expected, "actual": actual_python}, indent=2))
            raise SystemExit(1)
        print(json.dumps({"status": "PASS", "check": "offline_python_oracle",
                          "expected_findings": len(expected),
                          "splunk_runtime_validated": False}))
        if args.splunk_export is None:
            print("Splunk runtime status: NOT VALIDATED (no Splunk export supplied)")
            return
        actual_splunk = read_splunk_export(args.splunk_export)
        if actual_splunk != expected:
            print(json.dumps({"status": "FAIL", "check": "splunk_result_comparison",
                              "expected": expected, "actual": actual_splunk}, indent=2))
            raise SystemExit(1)
        print(json.dumps({"status": "PASS", "check": "splunk_result_comparison",
                          "rows_compared": len(actual_splunk),
                          "scope": "provided_csv_only",
                          "note": "CSV match does not authenticate the source or prove deployment."}))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Verification input error: {exc}\n")


if __name__ == "__main__":
    main()
