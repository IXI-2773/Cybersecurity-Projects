#!/usr/bin/env python3
"""Verify and examine a bounded forensic evidence package."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED_FILES = ("browser_history.csv", "case_notes.txt", "scheduled_tasks.xml")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    for member in members:
        path = PurePosixPath(member.filename)
        mode = member.external_attr >> 16
        if path.is_absolute() or ".." in path.parts or not path.parts or member.is_dir():
            raise ValueError(f"unsafe archive path: {member.filename}")
        if (mode & 0o170000) == 0o120000:
            raise ValueError(f"unsafe archive path: {member.filename}")
    names = tuple(sorted(member.filename for member in members))
    if names != REQUIRED_FILES:
        raise ValueError("archive contents do not match the required evidence set")
    return sorted(members, key=lambda member: member.filename)


def _read_history(data: bytes) -> list[dict]:
    reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
    expected = ("timestamp_utc", "url", "title")
    if tuple(reader.fieldnames or ()) != expected:
        raise ValueError("browser history schema is invalid")
    rows = list(reader)
    if len(rows) != 2 or any(not row[field] for row in rows for field in expected):
        raise ValueError("browser history evidence is incomplete")
    return rows


def _read_task(data: bytes) -> dict:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("scheduled task XML is invalid") from exc
    task = root.find("Task")
    if task is None:
        raise ValueError("scheduled task evidence is missing")
    values = {
        "name": task.get("name", ""),
        "timestamp_utc": task.findtext("CreatedUTC", ""),
        "command": task.findtext("Command", ""),
        "trigger": task.findtext("Trigger", ""),
    }
    if any(not value for value in values.values()):
        raise ValueError("scheduled task evidence is incomplete")
    return values


def examine_package(path: Path, expected_sha256: str) -> dict:
    original_sha256 = sha256_file(path)
    if original_sha256 != expected_sha256:
        raise ValueError("evidence package SHA-256 does not match the acquisition manifest")
    with tempfile.TemporaryDirectory() as directory:
        working = Path(directory) / "working-copy.zip"
        shutil.copyfile(path, working)
        working_sha256 = sha256_file(working)
        if working_sha256 != original_sha256:
            raise ValueError("working-copy SHA-256 does not match the original")
        with zipfile.ZipFile(working) as archive:
            members = _validate_members(archive)
            blobs = {member.filename: archive.read(member) for member in members}
            inventory = [
                {
                    "artifact": member.filename,
                    "modified_utc": "%04d-%02d-%02dT%02d:%02d:%02dZ" % member.date_time,
                    "sha256": hashlib.sha256(blobs[member.filename]).hexdigest(),
                    "size_bytes": len(blobs[member.filename]),
                }
                for member in members
            ]
    history = _read_history(blobs["browser_history.csv"])
    task = _read_task(blobs["scheduled_tasks.xml"])
    download = history[1]
    timeline = [
        {"artifact": "browser_history.csv", "event": "Portal sign-in recorded", "timestamp_utc": history[0]["timestamp_utc"]},
        {"artifact": "browser_history.csv", "event": "Remote-support download URL recorded", "timestamp_utc": download["timestamp_utc"]},
        {"artifact": "scheduled_tasks.xml", "event": "SupportUpdate scheduled task created", "timestamp_utc": task["timestamp_utc"]},
    ]
    return {
        "case_id": "LAB-DFIR-001",
        "original_sha256": original_sha256,
        "working_copy_sha256": working_sha256,
        "inventory": inventory,
        "timeline": timeline,
        "findings": [
            {
                "id": "FORENSIC_DOWNLOAD_SEQUENCE",
                "label": "Download record precedes task creation by two minutes",
                "severity": "medium",
                "artifact": "browser_history.csv",
                "timestamp_utc": download["timestamp_utc"],
            },
            {
                "id": "FORENSIC_PERSISTENCE_REFERENCE",
                "label": "Scheduled task references the downloaded filename",
                "severity": "high",
                "artifact": "scheduled_tasks.xml",
                "timestamp_utc": task["timestamp_utc"],
            },
        ],
        "assessment": "The supplied artifacts support a download-to-scheduled-task sequence in this lab fixture.",
        "limitations": "Artifacts are lab-created and do not establish execution, user intent, malware behavior, or a real incident.",
    }


def evidence_summary(result: dict) -> dict:
    return {
        "case_id": result["case_id"],
        "title": "Forensic evidence examination",
        "status": "Verified working-copy analysis",
        "metrics": [
            {"label": "Artifacts inventoried", "value": str(len(result["inventory"]))},
            {"label": "Timeline events", "value": str(len(result["timeline"]))},
            {"label": "Findings", "value": str(len(result["findings"]))},
        ],
        "timeline": [
            {
                "time": item["timestamp_utc"][11:16] + "Z",
                "label": item["event"],
                "state": "finding" if index else "observed",
            }
            for index, item in enumerate(result["timeline"])
        ],
        "findings": [
            {key: finding[key] for key in ("id", "label", "severity")}
            for finding in result["findings"]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("expected_sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    result = examine_package(args.package, args.expected_sha256)
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
