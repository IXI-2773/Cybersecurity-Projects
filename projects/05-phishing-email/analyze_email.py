#!/usr/bin/env python3
"""Offline parser for the LAB-MAIL-001 portfolio email fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
REQUIRED_HEADERS = ("From", "Reply-To", "To", "Subject", "Date", "Message-ID")


def _mailbox(value: str) -> tuple[str, str]:
    addresses = getaddresses([value])
    if len(addresses) != 1 or "@" not in addresses[0][1]:
        raise ValueError("header must contain one valid mailbox")
    address = addresses[0][1].lower()
    return address, address.rsplit("@", 1)[1]


def _auth_results(value: str) -> dict[str, str]:
    lowered = value.lower()
    result = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}=([a-z_]+)", lowered)
        result[mechanism] = match.group(1) if match else "absent"
    return result


def _defang(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("unsupported URL")
    host = parts.hostname.replace(".", "[.]")
    port = f":{parts.port}" if parts.port else ""
    query = f"?{parts.query}" if parts.query else ""
    fragment = f"#{parts.fragment}" if parts.fragment else ""
    return f"hxxp{'s' if parts.scheme == 'https' else ''}://{host}{port}{parts.path}{query}{fragment}"


def analyze_message(path: Path) -> dict:
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    for header in REQUIRED_HEADERS:
        if not message.get(header):
            raise ValueError(f"required header missing: {header}")

    sender_address, sender_domain = _mailbox(str(message["From"]))
    reply_address, reply_domain = _mailbox(str(message["Reply-To"]))
    auth = _auth_results(str(message.get("Authentication-Results", "")))
    body = message.get_body(preferencelist=("plain",))
    text = body.get_content() if body is not None else message.get_content()
    urls = []
    seen = set()
    for match in URL_RE.findall(str(text)):
        clean = match.rstrip(".,);]")
        if clean in seen:
            continue
        seen.add(clean)
        parts = urlsplit(clean)
        urls.append({
            "scheme": parts.scheme.lower(),
            "host": (parts.hostname or "").lower(),
            "defanged": _defang(clean),
        })

    mismatch = sender_domain != reply_domain
    failed = [name for name, value in auth.items() if value in {"fail", "softfail", "none", "absent"}]
    findings = []
    if mismatch:
        findings.append({"id": "MAIL_REPLY_TO_MISMATCH", "severity": "high", "label": "Sender and Reply-To domains differ"})
    if failed:
        findings.append({"id": "MAIL_AUTH_FAILURES", "severity": "high", "label": "SPF, DKIM or DMARC did not pass"})
    if any(item["host"] != sender_domain for item in urls):
        findings.append({"id": "MAIL_LINK_DOMAIN_MISMATCH", "severity": "medium", "label": "Linked host differs from sender domain"})

    return {
        "case_id": "LAB-MAIL-001",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "message_id": str(message["Message-ID"]),
        "subject": str(message["Subject"]),
        "from": {"address": sender_address, "domain": sender_domain},
        "reply_to": {"address": reply_address, "domain": reply_domain},
        "sender_reply_to_mismatch": mismatch,
        "authentication": auth,
        "urls": urls,
        "findings": findings,
        "assessment": "Suspicious lab message; quarantine and verify through a trusted channel.",
        "limitations": "Lab-created message; no mailbox, DNS, proxy, endpoint or user-action telemetry was queried.",
    }


def evidence_summary(result: dict) -> dict:
    auth_failures = sum(value != "pass" for value in result["authentication"].values())
    return {
        "case_id": result["case_id"],
        "title": "Phishing email investigation",
        "status": "Completed offline analysis",
        "metrics": [
            {"label": "URLs reviewed", "value": str(len(result["urls"]))},
            {"label": "Auth concerns", "value": str(auth_failures)},
            {"label": "Findings", "value": str(len(result["findings"]))},
        ],
        "timeline": [
            {"time": "01", "label": "Preserved", "state": "observed"},
            {"time": "02", "label": "Headers parsed", "state": "observed"},
            {"time": "03", "label": "Indicators reviewed", "state": "finding"},
            {"time": "04", "label": "Handoff written", "state": "observed"},
        ],
        "findings": result["findings"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("message", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    result = analyze_message(args.message)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    if args.summary:
        args.summary.write_text(json.dumps(evidence_summary(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
