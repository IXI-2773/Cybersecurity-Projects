#!/usr/bin/env python3
"""Correlate a bounded enterprise account activity fixture."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ("timestamp_utc", "event_id", "account", "source_ip", "host", "outcome", "detail")
KNOWN_EVENTS = {"4624", "4625", "4728"}


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"timestamp must be UTC: {value}")
    return parsed


def load_events(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError("CSV fields do not match the required schema")
        events = []
        for row_number, row in enumerate(reader, 2):
            if any(not row[field].strip() for field in FIELDS):
                raise ValueError(f"row {row_number} contains an empty field")
            if row["event_id"] not in KNOWN_EVENTS:
                raise ValueError(f"unknown event_id: {row['event_id']}")
            parsed = dict(row)
            parsed["_time"] = _parse_time(row["timestamp_utc"])
            events.append(parsed)
    if not events:
        raise ValueError("event fixture must not be empty")
    return sorted(events, key=lambda item: item["_time"])


def analyze_events(path: Path) -> dict:
    events = load_events(path)
    failures: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for event in events:
        if event["event_id"] == "4625" and event["outcome"] == "failure":
            failures[(event["account"], event["source_ip"])].append(event)
    candidates = [items for items in failures.values() if len(items) >= 3 and (items[-1]["_time"] - items[0]["_time"]).total_seconds() <= 600]
    if len(candidates) != 1:
        raise ValueError("fixture must contain exactly one three-failure burst")
    burst = candidates[0]
    account = burst[0]["account"]
    source_ip = burst[0]["source_ip"]
    successes = [event for event in events if event["event_id"] == "4624" and event["outcome"] == "success" and event["account"] == account and event["source_ip"] == source_ip and 0 <= (event["_time"] - burst[-1]["_time"]).total_seconds() <= 600]
    changes = [event for event in events if event["event_id"] == "4728" and event["account"] == account and successes and 0 <= (event["_time"] - successes[0]["_time"]).total_seconds() <= 600]

    findings = [
        {"id": "ACCT_FAILURE_BURST", "severity": "medium", "label": "Three failures from one source in four minutes"},
    ]
    if successes:
        findings.append({"id": "ACCT_SUCCESS_AFTER_FAILURES", "severity": "high", "label": "Successful sign-in followed the failure burst"})
    if changes:
        findings.append({"id": "ACCT_PRIVILEGE_CHANGE", "severity": "high", "label": "Privilege change followed the successful sign-in"})

    subject_events = [event for event in events if event["account"] == account]
    timeline = [{field: event[field] for field in FIELDS} for event in subject_events]
    return {
        "case_id": "LAB-ID-001",
        "subject_account": account,
        "source_ip": source_ip,
        "event_count": len(events),
        "timeline": timeline,
        "findings": findings,
        "assessment": "Escalate the linked sign-in and privilege change for account validation and containment.",
        "alternative_explanations": "An authorized administrator, help-desk reset, or approved automation could produce part of this sequence; change records and identity telemetry are required.",
        "limitations": "Lab-created normalized events; no domain controller, identity provider, endpoint or ticketing system was queried.",
    }


def evidence_summary(result: dict) -> dict:
    timeline = result["timeline"]
    selected = (timeline[0], timeline[2], timeline[3], timeline[4])
    labels = ("First failure", "Third failure", "Sign-in", "Privilege change")
    return {
        "case_id": result["case_id"],
        "title": "Enterprise account investigation",
        "status": "Completed event correlation",
        "metrics": [
            {"label": "Events reviewed", "value": str(result["event_count"])},
            {"label": "Linked events", "value": str(len(timeline))},
            {"label": "Findings", "value": str(len(result["findings"]))},
        ],
        "timeline": [
            {"time": item["timestamp_utc"][11:16] + "Z", "label": label, "state": "finding" if index >= 2 else "observed"}
            for index, (item, label) in enumerate(zip(selected, labels))
        ],
        "findings": result["findings"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("events", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    result = analyze_events(args.events)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    if args.summary:
        args.summary.write_text(json.dumps(evidence_summary(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
