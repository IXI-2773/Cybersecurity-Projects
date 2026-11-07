# Stage B — Splunk 64-Event In-Memory Matrix

> Historical record from the original portfolio snapshot. Its `scripts/check_case_evidence.py` command and CI output refer to that checkout; [inspect the original checker](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/scripts/check_case_evidence.py).

**Owner:** Don Lopez · **Status:** **EXECUTED IN SPLUNK — PARITY FAILURE 3/5** on October 23, 2026 (operator screenshot). Original query retained as a regression artifact; [revised candidate](SPLUNK_MATRIX_BOUNDARY_RETEST.spl) remains **not yet executed**.  
**Prerequisite:** The separate [seven-event upload-free smoke test](SPLUNK_SMOKE_TEST.spl) produced the expected one-row result in a user-provided screenshot on October 23, 2026.

## Observed first run and next action

The original query returned **3 rows**, each showing 64 fixture events and nine scenarios, but failed to report `user_boundary` at 13:10 UTC and `user_alpha` at 13:40 UTC. Both missing events involve the exact ten-minute boundary. [See observed row-by-row evidence and limitations](SPLUNK_MATRIX_FIRST_RUN_2026-10-23.md).

**Follow-up:** The later [boundary-corrected retest screenshot](SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md) matches 5/5 frozen expected rows. This original SPL remains preserved as a failed regression case; do **not** present it as a passing query.

## Original Stage B reproduction — intentionally preserved

1. Open Splunk Enterprise **Search & Reporting** and set the time range to **All time**.
2. Open the [in-memory 64-event matrix search](SPLUNK_MATRIX_IN_MEMORY.spl), select **Raw**, copy its full contents, paste into Splunk Search and execute.
3. Open **Statistics**. The first real execution showed three findings, not five. Retain the actual output as a reproducible failure, then use the Stage B2 corrected candidate. Save the search job ID and Splunk version where available.
4. Compare every row to [the independent expected findings](expected_findings.json). If anything differs, record the raw result; **do not change the oracle merely to make it pass**.

Expected: **five finding rows**, each carrying `fixture_event_count=64` and `fixture_scenario_count=9` with these UTC timestamps, accounts and source IPs:

| Scenario | UTC time | Account | Source IP | Failures |
| --- | --- | --- | --- | ---: |
| threshold | 2026-10-05T09:05:00Z | user_threshold | 192.0.2.10 | 5 |
| post_success_burst | 2026-10-05T10:39:00Z | user_reset | 192.0.2.13 | 5 |
| ten_minute_boundary | 2026-10-05T13:10:00Z | user_boundary | 203.0.113.10 | 5 |
| interleaved_users | 2026-10-05T13:40:00Z | user_alpha | 203.0.113.20 | 5 |
| interleaved_users | 2026-10-05T13:41:00Z | user_beta | 203.0.113.21 | 5 |

Five other scenario families intentionally do **not** alert: below-threshold attempts, a non-alerting intervening success, expired window, other user and other source IP. (The total is nine scenario labels, including the multi-alert interleaved case.)

### What the in-memory test demonstrates

It reproduces all 64 rows of [the frozen CSV corpus](validation_events.csv) inside SPL using `makeresults`, `makemv`, `mvexpand`, `split` and `mvindex`. It then uses the same detection operators as [`splunk.spl`](splunk.spl). The CSV file is the authoritative corpus; the `fixture_rows` string is deterministically derived from it, and a [repository evidence check](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/scripts/check_case_evidence.py) guards against drift.

**It does not establish file upload, indexing, CSV field extraction, search-job export provenance, or operational telemetry equivalence.** Full qualification still requires [the 64-row upload/export runbook](SPLUNK_RUNBOOK.md) and validation of both raw and finding exports.

### If zero or unexpected rows appear

- Verify **All time** is selected. The fabricated data are dated October 5, 2026.
- Capture the actual error message or statistics rows without changing any alert thresholds.
- Confirm that the entire single long `fixture_rows="..."` line was copied intact.
- If needed, run the complete matrix through the [CSV upload path](SPLUNK_RUNBOOK.md) to distinguish SPL behavior from in-memory fixture generation.

**Safety:** All accounts and IPs are synthetic/documentation-only. No credentials, production logs, external data collection, index creation or remote API access are needed.
