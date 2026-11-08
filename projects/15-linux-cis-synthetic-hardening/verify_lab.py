#!/usr/bin/env python3
"""Re-run a synthetic, read-only CIS section-5 comparison using imported upstream source."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CASE_DIR.parents[1]
DEFAULT_TOOL = REPO_ROOT / "third_party/community/linux-cis-hardening-auditor/src/cisaudit.sh"
TARGET_IDS = ("5.2.2", "5.2.6", "5.2.8", "5.2.11", "5.3.1", "5.4.1", "5.4.2", "5.4.3", "5.5.1")


def scan(tool: Path, phase: str) -> dict:
    fixture = CASE_DIR / "fixtures" / phase
    proc = subprocess.run(
        ["bash", str(tool), "--test-root", str(fixture), "--categories", "5",
         "--format", "json", "--quiet"],
        capture_output=True, text=True, check=True, timeout=30,
    )
    report = json.loads(proc.stdout)
    if report.get("os_id") != "synthetic" or report.get("os_version") != "1":
        raise ValueError("Scanner target was not the synthetic fixture")
    report.pop("hostname", None)
    report.pop("timestamp", None)
    return report


def verify(tool: Path) -> None:
    actual = {}
    for phase in ("before", "after"):
        actual[phase] = scan(tool, phase)
        saved = json.loads((CASE_DIR / "reports" / f"{phase}.json").read_text(encoding="utf-8"))
        if actual[phase] != saved:
            raise AssertionError(f"{phase} run differs from the checked-in normalized report")

    baseline = {item["id"]: item for item in actual["before"]["controls"]}
    hardened = {item["id"]: item for item in actual["after"]["controls"]}
    if baseline.keys() != hardened.keys():
        raise AssertionError("Control inventory changed between fixtures")
    changed = [
        ident for ident in baseline
        if baseline[ident]["status"] == "FAIL" and hardened[ident]["status"] == "PASS"
    ]
    if len(changed) != 17 or not set(TARGET_IDS).issubset(changed):
        raise AssertionError(f"Unexpected remediated controls: {changed}")
    if actual["before"]["summary"]["score_percent"] != 10:
        raise AssertionError("Unexpected before score")
    if actual["after"]["summary"]["score_percent"] != 95:
        raise AssertionError("Unexpected after score")
    for phase in ("before", "after"):
        summary = actual[phase]["summary"]
        if summary["pass"] + summary["fail"] + summary["skip"] + summary["warn"] != 23:
            raise AssertionError("Unexpected control count")
    remaining = [item["id"] for item in actual["after"]["controls"] if item["status"] == "FAIL"]
    if remaining != ["5.1.1"]:
        raise AssertionError(f"Unexpected remaining failures: {remaining}")
    print("PASS: synthetic section-5 fixture review")
    print("Before: 2 PASS / 18 FAIL / 3 SKIP (10% scored)")
    print("After:  19 PASS / 1 FAIL / 3 SKIP (95% scored)")
    print("Transitions: 17 FAIL->PASS; remaining FAIL 5.1.1 (cron)")
    print("Limits: this is NOT production remediation or CIS certification")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=Path, default=DEFAULT_TOOL,
                        help="Path to the imported cisaudit.sh (for an isolated source checkout)")
    args = parser.parse_args()
    verify(args.tool.resolve())
