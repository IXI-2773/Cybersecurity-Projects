"""Fail-closed comparison for independently exported synthetic Splunk lab evidence.

This script never connects to Splunk and cannot prove search execution.
Matching a supplied CSV is *not* runtime qualification by itself.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from validate_matrix import read_splunk_export, normalized_expected_rows

HERE = Path(__file__).resolve().parent
RAW_FIELDS = ("timestamp", "username", "source_ip", "host", "event_type", "scenario")


def read_raw_rows(path: Path) -> list[tuple[str, ...]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not set(RAW_FIELDS).issubset(reader.fieldnames):
            raise ValueError("Raw export missing required columns: " +
                             ", ".join(sorted(set(RAW_FIELDS) - set(reader.fieldnames or []))))
        rows = []
        for number, row in enumerate(reader, start=2):
            if None in row or any(row.get(field) is None for field in RAW_FIELDS):
                raise ValueError(f"Malformed raw event CSV line {number}")
            rows.append(tuple(row[field].strip() for field in RAW_FIELDS))
        return sorted(rows)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualify(raw_export: Path, findings_export: Path) -> dict:
    expected_raw = read_raw_rows(HERE / "validation_events.csv")
    observed_raw = read_raw_rows(raw_export)
    expected_findings = normalized_expected_rows(json.loads(
        (HERE / "expected_findings.json").read_text(encoding="utf-8")))
    observed_findings = read_splunk_export(findings_export)
    raw_matches = observed_raw == expected_raw
    findings_match = observed_findings == expected_findings
    missing_raw = sum((Counter(expected_raw) - Counter(observed_raw)).values())
    unexpected_raw = sum((Counter(observed_raw) - Counter(expected_raw)).values())
    missing_findings = sum((Counter(expected_findings) - Counter(observed_findings)).values())
    unexpected_findings = sum((Counter(observed_findings) - Counter(expected_findings)).values())
    return {
        "schema": "portfolio.splunk-csv-qualification.v1",
        "status": "CSV_PARITY_PASS" if raw_matches and findings_match else "CSV_PARITY_FAIL",
        "splunk_runtime_validated": False,
        "source_authenticity": "NOT_ESTABLISHED",
        "note": "This tool only compares supplied CSV bytes/values. A real Splunk session, search-job provenance and evidence screenshots must be independently reviewed.",
        "raw_events_expected": len(expected_raw),
        "raw_events_observed": len(observed_raw),
        "raw_records_match": raw_matches,
        "raw_missing": missing_raw,
        "raw_unexpected": unexpected_raw,
        "findings_expected": len(expected_findings),
        "findings_observed": len(observed_findings),
        "findings_match": findings_match,
        "findings_missing": missing_findings,
        "findings_unexpected": unexpected_findings,
        "sha256": {
            "validation_events_csv": sha256(HERE / "validation_events.csv"),
            "expected_findings_json": sha256(HERE / "expected_findings.json"),
            "splunk_search": sha256(HERE / "splunk.spl"),
            "provided_raw_export": sha256(raw_export),
            "provided_findings_export": sha256(findings_export),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", type=Path, required=True,
                        help="CSV from Splunk raw event field export")
    parser.add_argument("--findings-export", type=Path, required=True,
                        help="CSV from final SPL results table")
    parser.add_argument("--report", type=Path,
                        help="Optional output path for JSON comparison report")
    args = parser.parse_args()
    try:
        report = qualify(args.raw_export, args.findings_export)
        rendered = json.dumps(report, indent=2) + "\n"
        print(rendered, end="")
        if args.report is not None:
            args.report.write_text(rendered, encoding="utf-8")
        return 0 if report["status"] == "CSV_PARITY_PASS" else 1
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Invalid or unreadable qualification evidence: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
