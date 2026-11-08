#!/usr/bin/env python3
"""Offline pattern review of a bounded AWS IAM identity-policy JSON subset.

No AWS calls, credentials, permissions simulation, or policy modifications.
Candidates are syntax-based prompts for human review, not effective access.
"""

import argparse
import json
from pathlib import Path
import re
import sys


SCOPE = (
    "Literal syntax checks of identity-policy Allow statements only; "
    "not effective access. Conditions, explicit denies, boundaries, SCPs, "
    "session and resource policies are not evaluated together."
)
ROOT_ELEMENTS = {"Version", "Statement", "Id"}
STATEMENT_ELEMENTS = {"Sid", "Effect", "Action", "Resource", "Condition"}
SERVICE_WILDCARD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*:\*$")


def _unique_json_keys(pairs):
    """Reject ambiguous JSON objects instead of silently keeping the last key."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _terms(value, label):
    """Accept only explicit nonempty string(s), never guessed AWS expressions."""
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list) and value:
        values = value
    else:
        raise ValueError(f"{label} must be a nonempty string or list of strings")
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{label} contains a non-string or empty value")
    return values


def _statements(document):
    if not isinstance(document, dict):
        raise ValueError("policy must be a JSON object")
    if set(document) - ROOT_ELEMENTS:
        raise ValueError("unsupported policy-level element")
    if document.get("Version") != "2012-10-17":
        raise ValueError("only IAM policy Version 2012-10-17 is supported")
    if "Id" in document and not isinstance(document["Id"], str):
        raise ValueError("Id must be a string")
    entries = document.get("Statement")
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Statement must be a nonempty object or list")

    seen_sids = set()
    validated = []
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or set(entry) - STATEMENT_ELEMENTS:
            raise ValueError(f"Statement[{index}]: unsupported statement elements")
        if entry.get("Effect") not in ("Allow", "Deny"):
            raise ValueError(f"Statement[{index}]: Effect must be Allow or Deny")
        actions = _terms(entry.get("Action"), f"Statement[{index}].Action")
        resources = _terms(entry.get("Resource"), f"Statement[{index}].Resource")
        if "Condition" in entry and not isinstance(entry["Condition"], dict):
            raise ValueError(f"Statement[{index}]: Condition must be an object")
        sid = entry.get("Sid", f"Statement[{index}]")
        if not isinstance(sid, str) or not sid.strip() or sid in seen_sids:
            raise ValueError(f"Statement[{index}]: Sid must be unique, nonempty text")
        seen_sids.add(sid)
        validated.append((entry, sid, actions, resources))
    return validated


def analyze(document):
    """Return syntax-only review candidates and traceable statement references."""
    statements = _statements(document)
    findings = []
    for entry, identifier, actions, resources in statements:
        if entry["Effect"] != "Allow" or "*" not in resources:
            continue
        common = {"statement_id": identifier, "priority": "REVIEW",
                  "condition_present": "Condition" in entry}
        if "*" in actions:
            findings.append({
                **common, "code": "ALL_ACTIONS_ALL_RESOURCES",
                "detail": "Allow statement specifies Action * and Resource *; review its intended scope.",
            })
        else:
            if any(action.casefold() == "iam:passrole" for action in actions):
                findings.append({
                    **common, "code": "PASSROLE_ALL_RESOURCES",
                    "detail": "Allow statement lists iam:PassRole with Resource *; review permitted roles and conditions.",
                })
            if any(action.casefold() == "sts:assumerole" for action in actions):
                findings.append({
                    **common, "code": "ASSUMEROLE_ALL_RESOURCES",
                    "detail": "Allow statement lists sts:AssumeRole with Resource *; review trusting roles and conditions.",
                })
            broad = sorted({action for action in actions if SERVICE_WILDCARD.fullmatch(action)})
            if broad:
                findings.append({
                    **common, "code": "SERVICE_ACTIONS_ALL_RESOURCES",
                    "detail": ("Allow statement lists service-wide action wildcard(s) "
                               f"{', '.join(broad)} with Resource *; review scope."),
                })

    return {"statement_count": len(statements), "findings": findings, "scope": SCOPE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path, help="Local synthetic identity-policy JSON file")
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.policy.read_text(encoding="utf-8"),
                              object_pairs_hook=_unique_json_keys)
        report = analyze(document)
    except (OSError, ValueError, TypeError) as exc:
        print(f"Unsupported policy: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
