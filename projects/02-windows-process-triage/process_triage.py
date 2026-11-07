"""Offline triage of synthetic Windows Security 4688 process-creation logs.

Detects two command-line patterns for analyst review, not malware attribution.
No system access, network requests, or third-party dependencies.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

REQUIRED = {"timestamp", "event_id", "host", "username", "image", "command_line", "parent_image", "process_id"}
ENCODED_FLAG = re.compile(r"(?<![\w-])-(?:enc|encodedcommand)(?=\s|$|:)", re.IGNORECASE)
URLCACHE_FLAG = re.compile(r"(?<![\w-])-urlcache(?=\s|$)", re.IGNORECASE)
FORCE_FLAG = re.compile(r"(?<![\w-])-f(?=\s|$)", re.IGNORECASE)


def parse_utc(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Expected UTC timestamp YYYY-MM-DDTHH:MM:SSZ: {value!r}") from exc


def read_events(path: str | Path) -> list[dict]:
    """Reject malformed rows instead of treating them as clean telemetry."""
    with Path(path).open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not REQUIRED.issubset(reader.fieldnames):
            missing = REQUIRED.difference(reader.fieldnames or [])
            raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")
        rows = []
        for line_no, row in enumerate(reader, 2):
            try:
                if None in row or any(row.get(k) is None for k in REQUIRED):
                    raise ValueError("Incorrect CSV field count")
                dt = parse_utc(row["timestamp"])
                if row["event_id"] != "4688":
                    raise ValueError("Expected Windows process creation event ID 4688")
                if not row["host"].strip() or not row["username"].strip() or not row["image"].strip():
                    raise ValueError("Missing host, user, or process image")
                pid = int(row["process_id"])
                if pid < 1:
                    raise ValueError("process_id must be positive")
                rows.append({**row, "_time": dt, "process_id": pid})
            except (ValueError, TypeError) as exc:
                raise ValueError(f"CSV line {line_no}: {exc}") from exc
    return rows


def inspect_event(event: dict) -> list[dict]:
    """Rule-based candidate findings; these are not maliciousness verdicts."""
    image = PureWindowsPath(str(event["image"]).replace("/", "\\")).name.casefold()
    command = str(event["command_line"])
    matches = []
    if image in {"powershell.exe", "pwsh.exe"} and ENCODED_FLAG.search(command):
        matches.append(("PS_ENCODED_COMMAND", "PowerShell encoded-command argument", "T1059.001"))
    if image == "certutil.exe" and URLCACHE_FLAG.search(command) and FORCE_FLAG.search(command):
        matches.append(("CERTUTIL_URLCACHE_FETCH", "certutil URL cache and force flags", "T1105"))
    return [{
        "timestamp": event["timestamp"],
        "host": event["host"],
        "username": event["username"],
        "image": event["image"],
        "parent_image": event["parent_image"],
        "process_id": event["process_id"],
        "rule_id": rule_id,
        "matched_behavior": reason,
        "attack_technique_hypothesis": technique,
        "assessment": "Triage candidate only — requires corroboration",
    } for rule_id, reason, technique in matches]


def triage(events: list[dict]) -> list[dict]:
    findings = []
    for event in sorted(events, key=lambda item: (item["_time"], item["host"], item["process_id"])):
        findings.extend(inspect_event(event))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path, help="synthetic Windows 4688 CSV fixture")
    args = parser.parse_args()
    try:
        findings = triage(read_events(args.csv_file))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps({"source": "synthetic_windows_4688", "finding_count": len(findings), "findings": findings}, indent=2))


if __name__ == "__main__":
    main()
