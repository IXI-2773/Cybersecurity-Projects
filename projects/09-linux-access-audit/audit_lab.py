"""Run a Linux/SQLite permissions lab, confined to a new TemporaryDirectory.

Root is required only to drop a child process to UID/GID 65534. No accounts,
services or existing system files are changed; the dummy script is never run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
POLICIES = (
    ("secrets/service.env", 0o044, 0o600, "Group/other read access to a dummy service secret"),
    ("bin/rotate_logs.sh", 0o022, 0o755, "Group/other write access to a dummy maintenance script"),
    ("public/notice.txt", 0o022, 0o644, "Group/other write access to a public notice"),
)
FIXTURES = (
    ("secrets/service.env", 0o644, b"LAB_ONLY_TOKEN=not_a_real_secret\n"),
    ("bin/rotate_logs.sh", 0o777, b"#!/bin/sh\n# Dummy training file; never executed.\nexit 0\n"),
    ("public/notice.txt", 0o644, b"Public lab notice. This file should remain readable.\n"),
)
PROBE = r'''
import errno,json,os,sys
root=sys.argv[1]
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
result={"uid":os.geteuid(),"gid":os.getegid(),"groups":os.getgroups(),"access":{}}
for name,relative,flags in [
    ("secret_read","secrets/service.env",os.O_RDONLY),
    ("script_write","bin/rotate_logs.sh",os.O_WRONLY),
    ("public_read","public/notice.txt",os.O_RDONLY),
]:
    try:
        fd=os.open(os.path.join(root,relative),flags|os.O_NOFOLLOW)
    except PermissionError as exc:
        if exc.errno != errno.EACCES: raise
        result["access"][name]="denied"
    else:
        os.close(fd)
        result["access"][name]="allowed"
print(json.dumps(result))
'''


def source_hashes():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("audit_lab.py", "audit.sql")}


def inventory(root):
    rows = []
    for relative, _, _ in FIXTURES:
        path = root / relative
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Expected a regular fixture file: " + relative)
        rows.append({"path": relative, "mode": stat.S_IMODE(info.st_mode),
                     "mode_octal": format(stat.S_IMODE(info.st_mode), "04o"),
                     "uid": info.st_uid, "gid": info.st_gid,
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return rows


def findings(rows):
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE assets(path TEXT PRIMARY KEY, mode INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 4095))")
        db.execute("CREATE TABLE policies(path TEXT PRIMARY KEY, forbidden_mask INTEGER, target_mode INTEGER, risk TEXT)")
        db.executemany("INSERT INTO assets VALUES (?, ?)", [(r["path"], r["mode"]) for r in rows])
        db.executemany("INSERT INTO policies VALUES (?, ?, ?, ?)", POLICIES)
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute((HERE / "audit.sql").read_text())]


def probe(root):
    result = subprocess.run([sys.executable, "-I", "-c", PROBE, str(root)],
                            capture_output=True, text=True, timeout=10, check=True)
    data = json.loads(result.stdout)
    if (data["uid"], data["gid"], data["groups"]) != (65534, 65534, []):
        raise ValueError("Probe did not run as the declared unprivileged identity")
    return data


def validate(report):
    assert report["schema"] == "portfolio.linux-access-audit.v1"
    before, after = report["before"], report["after"]
    assert {r["path"] for r in before["findings"]} == {"secrets/service.env", "bin/rotate_logs.sh"}
    assert after["findings"] == []
    assert before["probe"]["access"] == {"secret_read": "allowed", "script_write": "allowed", "public_read": "allowed"}
    assert after["probe"]["access"] == {"secret_read": "denied", "script_write": "denied", "public_read": "allowed"}
    for stage in (before, after):
        assert (stage["probe"]["uid"], stage["probe"]["gid"], stage["probe"]["groups"]) == (65534, 65534, [])
        assert {r["path"] for r in stage["assets"]} == {p[0] for p in POLICIES}
        assert all(r["uid"] == 0 and r["gid"] == 0 for r in stage["assets"])
    initial = {r["path"]: r for r in before["assets"]}
    for row in after["assets"]:
        assert row["sha256"] == initial[row["path"]]["sha256"], "File contents changed"
        assert row["mode"] == next(p[2] for p in POLICIES if p[0] == row["path"])
    assert initial["public/notice.txt"]["mode"] == 0o644
    assert report["parent_uid_after_probe"] == 0


def run_lab():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("Run on Linux as root for the isolated UID-drop probe; no success result was produced")
    report = {"schema": "portfolio.linux-access-audit.v1",
              "executed_at_utc": datetime.now(timezone.utc).isoformat(),
              "environment": {"system": platform.system(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version},
              "execution_context": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_SHA", "GITHUB_REPOSITORY")},
              "scope": "Three dummy regular files in an isolated temporary directory; standard Unix mode bits only",
              "source_sha256": source_hashes()}
    with tempfile.TemporaryDirectory(prefix="portfolio-access-audit-") as folder:
        root = Path(folder)
        root.chmod(0o755)  # Permit traversal so the file access probes are meaningful.
        for relative, mode, content in FIXTURES:
            path = root / relative
            path.parent.mkdir(exist_ok=True)
            path.parent.chmod(0o755)
            path.write_bytes(content)
            path.chmod(mode)
        before = inventory(root)
        matches = findings(before)
        report["before"] = {"assets": before, "findings": matches, "probe": probe(root)}
        for row in matches:
            (root / row["path"]).chmod(row["target_mode"])
        after = inventory(root)
        report["after"] = {"assets": after, "findings": findings(after), "probe": probe(root)}
        report["parent_uid_after_probe"] = os.geteuid()
        validate(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the actual execution report after validation")
    parser.add_argument("--check", action="store_true", help="Validate published evidence and repeat the experiment without rewriting it")
    args = parser.parse_args()
    if args.check and args.output:
        parser.error("--check and --output are mutually exclusive")
    if args.check:
        published = json.loads((HERE / "artifacts/executed_report.json").read_text())
        validate(published)
        if published["source_sha256"] != source_hashes():
            raise ValueError("Published execution report belongs to different source bytes")
    report = run_lab()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: 2 permission findings -> 0 under the same SQL policies")
    print("UID 65534: secret read allowed -> denied; script write allowed -> denied")
    print("Control: public read allowed -> allowed; file contents unchanged; parent UID remains 0")
    print("Scope: isolated Linux dummy files; no production system, account or service changed")


if __name__ == "__main__":
    main()
