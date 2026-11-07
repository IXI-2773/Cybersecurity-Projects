"""Detect synthetic failure bursts followed by authentication success.

Standard-library-only educational detector. Flags a triage hypothesis,
not a confirmed incident. No network access or production integration.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable

REQUIRED = {"timestamp", "username", "source_ip", "host", "event_type"}
ALLOWED = {"login_failure", "login_success"}


def parse_timestamp(value: str) -> datetime:
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"Invalid UTC timestamp: {value!r}") from exc
    return result.replace(tzinfo=timezone.utc)


def read_events(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames):
            raise ValueError(f"Missing required columns: {sorted(REQUIRED - set(reader.fieldnames or []))}")
        events = []
        for line_number, row in enumerate(reader, start=2):
            try:
                if None in row or any(row.get(column) is None for column in REQUIRED):
                    raise ValueError("Malformed CSV row or unexpected field count")
                if not row["username"] or not row["host"]:
                    raise ValueError("Empty username or host")
                if row["event_type"] not in ALLOWED:
                    raise ValueError("Unexpected event_type")
                ip_address(row["source_ip"])
                events.append({**row, "dt": parse_timestamp(row["timestamp"])})
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Line {line_number}: {exc}") from exc
    return events


def find_suspicious_logins(
    events: Iterable[dict], *, threshold: int = 5, window_minutes: int = 10
) -> list[dict]:
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")
    history: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    findings = []
    for event in sorted(events, key=lambda e: e["dt"]):
        key = (event["username"], event["source_ip"])
        cutoff = event["dt"] - timedelta(minutes=window_minutes)
        recent = history[key]
        while recent and recent[0] < cutoff:
            recent.popleft()
        if event["event_type"] == "login_failure":
            recent.append(event["dt"])
        elif event["event_type"] == "login_success":
            if len(recent) >= threshold:
                findings.append({
                    "observed_at_utc": event["dt"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "host": event["host"],
                    "failure_count_in_window": len(recent),
                    "earliest_failure_utc": recent[0].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "assessment": "Suspicious authentication sequence; investigate, not confirmed compromise",
                    "attack_hypothesis": "MITRE ATT&CK T1110 (Brute Force)",
                })
            # Every success closes the failed-login streak, even if no alert fired.
            recent.clear()
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()
    try:
        findings = find_suspicious_logins(
            read_events(args.csv_file),
            threshold=args.threshold,
            window_minutes=args.window,
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps({"source": "synthetic_lab", "findings": findings}, indent=2))


if __name__ == "__main__":
    main()
