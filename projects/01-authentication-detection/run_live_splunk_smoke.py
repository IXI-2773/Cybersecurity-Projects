"""Run the seven-event synthetic Splunk smoke search via authenticated REST API.

This is a read-only search. It does NOT ingest logs, edit Splunk configuration,
provide credentials, or assert that a third party independently verified a run.

Requires Python 3.10+, an authorized Splunk REST endpoint and a scoped token.
TLS certificate verification is mandatory; redirects are blocked to protect tokens.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENDPOINT = "/services/search/v2/jobs/export"
EXPECTED = {
    "timestamp": "2026-10-05T09:05:00Z",
    "username": "smoke_user",
    "source_ip": "192.0.2.99",
    "host": "SYNTHETIC-SPLUNK-SMOKE",
    "failure_count_in_window": "5",
}
RESPONSE_LIMIT = 256 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("REST endpoint redirect rejected; check the management URL")


def validate_base_url(url: str) -> str:
    """Accept only an HTTPS management origin, with no embedded credentials."""
    parts = urllib.parse.urlsplit(url.strip())
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path not in ("", "/")
            or parts.query or parts.fragment):
        raise ValueError("SPLUNK_MGMT_URL must be an HTTPS origin (example: https://localhost:8089)")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid management URL port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid management URL port")
    return url.strip().rstrip("/")


def decode_csv(body: bytes) -> list[dict]:
    if len(body) > RESPONSE_LIMIT:
        raise ValueError("Search results exceed bounded smoke-test limit")
    try:
        decoded = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Splunk did not return UTF-8 CSV") from exc
    reader = csv.DictReader(io.StringIO(decoded))
    if reader.fieldnames is None or not set(EXPECTED).issubset(reader.fieldnames):
        raise ValueError("Splunk returned no CSV header or required result fields")
    rows = list(reader)
    if any(None in row or any(row.get(field) is None for field in EXPECTED) for row in rows):
        raise ValueError("Malformed Splunk CSV result row")
    return rows


def check_result(rows: list[dict]) -> bool:
    return len(rows) == 1 and all(str(rows[0][key]).strip() == expected
                                  for key, expected in EXPECTED.items())


def execute(base_url: str, token: str, *, opener=None) -> dict:
    """Submit a single deterministic search; returns a scrubbed evidence summary."""
    base = validate_base_url(base_url)
    if not token.strip():
        raise ValueError("A nonempty Splunk REST token is required")
    search = (HERE / "SPLUNK_SMOKE_TEST.spl").read_text(encoding="utf-8").strip()
    payload = urllib.parse.urlencode({
        "search": search,
        "output_mode": "csv",
        "earliest_time": "0",
        "latest_time": "now",
    }).encode("utf-8")
    request = urllib.request.Request(
        base + ENDPOINT,
        data=payload,
        headers={
            "Authorization": "Bearer " + token.strip(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/csv",
        },
        method="POST",
    )
    transport = opener if opener is not None else urllib.request.build_opener(NoRedirect)
    try:
        with transport.open(request, timeout=60) as response:
            raw = response.read(RESPONSE_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        # Never serialize the HTTP error body: a proxy may echo sensitive headers.
        raise ValueError(f"Splunk REST API returned HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise ValueError("Could not establish a TLS-verified Splunk REST connection") from None

    rows = decode_csv(raw)
    correct = check_result(rows)
    return {
        "schema": "portfolio.splunk-smoke-execution.v1",
        "status": "SMOKE_RESULT_PASS" if correct else "SMOKE_RESULT_FAIL",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_classification": "authenticated_rest_response",
        "independently_attested": False,
        "api_path": ENDPOINT,
        "query_sha256": hashlib.sha256(search.encode("utf-8")).hexdigest(),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_result_count": len(rows),
        "expected_result_count": 1,
        "matches_expected_values": correct,
        "note": "Validates the received smoke search CSV only. Full 64-event ingest, SPL parity, source authenticity, and independent review require separate evidence.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional local JSON evidence file; review before sharing")
    args = parser.parse_args()
    url = os.getenv("SPLUNK_MGMT_URL", "")
    token = os.getenv("SPLUNK_API_TOKEN", "").strip()
    if not token and sys.stdin.isatty():
        token = getpass.getpass("Scoped Splunk REST API token (hidden): ").strip()
    if not url or not token:
        parser.error("Set SPLUNK_MGMT_URL and supply a scoped token in SPLUNK_API_TOKEN or interactively")
    try:
        result = execute(url, token)
        output = json.dumps(result, indent=2) + "\n"
        print(output, end="")
        if args.report:
            args.report.write_text(output, encoding="utf-8")
        return 0 if result["status"] == "SMOKE_RESULT_PASS" else 1
    except (ValueError, OSError) as exc:
        # User-supplied endpoint values/tokens are never included in errors.
        print("Splunk smoke test could not pass: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
