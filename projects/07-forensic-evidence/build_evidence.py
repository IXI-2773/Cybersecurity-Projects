#!/usr/bin/env python3
"""Build a deterministic, lab-created forensic evidence package."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

FIXED_ZIP_TIME = (2026, 10, 15, 9, 0, 0)
REQUIRED_FILES = ("browser_history.csv", "case_notes.txt", "scheduled_tasks.xml")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_package(source: Path, output: Path) -> dict:
    if not source.is_dir():
        raise ValueError("evidence source must be a directory")
    discovered = tuple(sorted(path.name for path in source.iterdir() if path.is_file()))
    if discovered != REQUIRED_FILES:
        raise ValueError(f"evidence source must contain exactly: {', '.join(REQUIRED_FILES)}")
    output.parent.mkdir(parents=True, exist_ok=True)
    files = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in REQUIRED_FILES:
            data = (source / name).read_bytes()
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            files.append({"artifact": name, "sha256": sha256_bytes(data), "size_bytes": len(data)})
    package = output.read_bytes()
    return {
        "case_id": "LAB-DFIR-001",
        "acquired_utc": "2026-10-15T09:00:00Z",
        "package_sha256": sha256_bytes(package),
        "package_size_bytes": len(package),
        "files": files,
        "scope": "Deterministic lab-created evidence; no real person, device, or incident.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    result = build_package(args.source, args.output)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
