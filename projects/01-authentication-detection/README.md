# Authentication detection — reproducible synthetic lab

**Implemented:** Python detector and focused tests.  
**Partial Splunk runtime evidence:** A [seven-event screenshot](SPLUNK_SMOKE_OBSERVATION_2026-10-23.md) matches the expected smoke result. **Not verified:** indexed CSV parity, independently authenticated job exports, real SIEM deployment or accuracy. Original 64-event result was 3/5; corrected result screenshot shows 5/5.

## Run
```sh
python -m unittest discover -s projects/01-authentication-detection -v
python projects/01-authentication-detection/detect_auth.py projects/01-authentication-detection/auth_events.csv
```
No third-party libraries required. Python 3.10+.

The fabricated CSV has one suspicious sequence (alice / 192.0.2.15, six failures followed by success) plus other benign or non-qualifying sequences. A finding supports triage, **not a claim that the account was compromised**.

## Rule
Group by username and source IP. Count failures in the preceding ten-minute window. At the next success, flag if count is at least five. Clear that burst to suppress duplicate successes. Documented hypothesis: [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/).

## Coverage & limits
No real users, infrastructure scanning, network I/O, MFA information, production telemetry, or evidence of attack attribution. Rotating-source attempts, absent data, clock skew and distributed login patterns can evade this heuristic. Validate the `splunk.spl` query independently; matching behavior has not yet been established.

The test suite covers positive fixture, negative threshold, expired window, per-key isolation, chronological sorting, inclusive time boundary, malformed time, invalid configuration, and duplicate-success suppression.

## SOC investigation expansion — v2.1

- [Simulated incident report](SOC_CASE_REPORT.md): observable timeline, hypothesis, gaps and explicitly synthetic disposition.
- [Installable SOC dashboard, indexing and disabled alert package](../../splunk_workflow/README.md) — fully prepared in GitHub; runtime verification of the new components pending.
- [Splunk ingestion and comparison runbook](SPLUNK_RUNBOOK.md): required on-platform steps and artifact capture checklist.
- [Independent scenario fixture](validation_events.csv) and [expected findings](expected_findings.json): nine constructed scenario families, **five expected findings**.
- [Offline and optional CSV comparison tool](validate_matrix.py): `python projects/01-authentication-detection/validate_matrix.py`. This verifies Python behavior; it **does not** validate the Splunk runtime without a genuine Splunk export.
- [SPL design](splunk.spl): use one streak per account/source IP; **any** successful login closes the previous burst. Global chronological sort is required before a time-windowed `streamstats`. This remains a **draft pending real Splunk execution**.

The v2.1 tests add regressions for non-alerting success resets, independent identities, malformed CSV data and validation matrix expectations. The project now has **31** focused Python unit tests.

## Splunk runtime qualification gate (next milestone)

1. **Stage A passed:** The [seven-event smoke query](SPLUNK_SMOKE_TEST.spl) matches the [reviewed Splunk screenshot](SPLUNK_SMOKE_OBSERVATION_2026-10-23.md).
2. **Stage B observed failure:** The [original 64-event matrix](SPLUNK_MATRIX_IN_MEMORY.spl) returned **3 of 5** expected findings in Splunk. [Failure report](SPLUNK_MATRIX_FIRST_RUN_2026-10-23.md).
3. **Stage B2 screenshot-reviewed PASS:** The [explicit-inclusive 64-event query](SPLUNK_MATRIX_BOUNDARY_RETEST.spl) is consistent with a [real five-row Statistics screenshot](SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md), matching the frozen oracle. Search/SID not shown in the cropped image.
4. Follow the [runbook](SPLUNK_RUNBOOK.md) to ingest the 64-event matrix exactly once and export both raw event rows and five detection findings.
5. Use [`qualify_exports.py`](qualify_exports.py) to compare **both** supplied CSV files against the frozen fixtures and emit SHA-256 provenance hashes. Passing a CSV comparison **never** certifies a live Splunk run.
6. Attach authentic Splunk version, job IDs, sanitized screenshots and run settings before updating the public portfolio's qualification status.

The SPL query now parses the UTC offset explicitly instead of interpreting the trailing `Z` as timezone-free text. The synthetic 64-event Stage B2 **result screenshot matches 5/5**; complete indexed-data qualification remains **not performed**.

### Live smoke runner prepared
Run `python projects/01-authentication-detection/run_live_splunk_smoke.py` on an **authorized** host with `SPLUNK_MGMT_URL` pointing to the HTTPS management origin. A scoped REST token is entered invisibly at the terminal, or sourced from `SPLUNK_API_TOKEN`. The runner makes **one read-only Splunk v2 search/export call**, enforces TLS verification and blocks redirects. It fails closed unless the response contains exactly one expected result. Its ten focused tests use **mock transport** and **do not execute Splunk**.
