# Splunk SOC Lab — Execution and Verification Runbook

**Owner:** Don Lopez · **Data:** synthetic only · **Status:** offline Python scenarios checked; seven-event Splunk smoke **PASS (operator screenshot, October 23, 2026)**; full 64-event and indexed-data qualification **PENDING**.

## Objective
Detect >=5 failed logins within a rolling 10-minute window for the same user and source IP, followed by a success. Any success clears that key's previous failures, **including a non-alerting success**. A detection signals analyst review, not a real compromise.

## Prerequisites
- Access to a Splunk Enterprise / Cloud search environment where you are authorized to upload synthetic CSV data.
- Permission to use a dedicated test index such as `lab_auth`; otherwise replace `index=lab_auth` in the SPL with your permitted index.
- An upload mechanism that extracts CSV headers as fields; assign sourcetype `portfolio:auth` or replace it consistently in the query.
- **No credentials or real organization data** in these fixtures.

## 0. Run the upload-free Splunk smoke test first

Paste [`SPLUNK_SMOKE_TEST.spl`](SPLUNK_SMOKE_TEST.spl) directly into **Splunk Search**. It generates seven entirely synthetic events in SPL and does **not** require an index or file ingestion.

Expected: exactly **one** result: `smoke_user`, `192.0.2.99`, timestamp `2026-10-05T09:05:00Z`, count **5**. The second success at 09:06 must not produce another alert. This smoke query has a [screenshot-reviewed result from Splunk Enterprise](SPLUNK_SMOKE_OBSERVATION_2026-10-23.md); version, job ID and public screenshot provenance are still missing. Save the search job ID, version and a genuine screenshot if it runs.

**Stage B result:** The original [64-event in-memory query](SPLUNK_MATRIX_IN_MEMORY.spl) actually returned **3/5** expected rows in an operator screenshot. [Observed failure report](SPLUNK_MATRIX_FIRST_RUN_2026-10-23.md). Both missing matches depend on the exact 600-second boundary; do **not** change the frozen oracle. **Follow-up:** The [boundary-corrected matrix results screenshot](SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md) matches all **5/5** expected rows. Its cropped view does not show the query or SID. Further indexed CSV ingestion and job/export provenance are **optional next qualifications**, not needed to present the bounded synthetic debugging demonstration.

## 1. Upload and verify
1. Open Splunk's **Add Data → Upload** (interface labels vary by version).
2. Upload [`validation_events.csv`](validation_events.csv), choose CSV source type / field extraction, map the `timestamp` field to event time with its explicit UTC `Z` offset (or assign UTC as the source timezone and verify preview values), and select the permitted destination index. Check that time extraction is correct before submitting.
3. Check that the **event-time** range includes **October 5, 2026**, and use the corresponding time picker range (or All time for the isolated test index).
4. Run:
   ```spl
   index=lab_auth sourcetype="portfolio:auth"
   | stats count as events dc(username) as distinct_users dc(scenario) as scenario_count
   ```
   Expected: **64 events** spanning **9 scenario labels**, assuming precisely one ingestion of the validation fixture. Any other count is a data-integrity problem; stop rather than continuing.
5. Inspect at least two raw events and confirm extracted fields: `timestamp, username, source_ip, host, event_type, scenario`. A wrong time picker or field extraction is an ingestion issue, not a detection result.
6. If you previously uploaded a fixture, use a fresh lab index or carefully filter `source` to avoid duplicate ingestion. **Do not erase production data.**

## 2. Run the detection search
Paste [`splunk.spl`](splunk.spl) into Splunk Search, replacing the index/sourcetype selectors only if needed.

**UTC correction:** The search transforms the suffix `Z` into `+0000` and parses with `%z`, which explicitly declares an offset. The original `timestamp` field is preserved in output; do not rebuild a literal `Z` using a local-time `strftime`. This improvement follows Splunk time-zone guidance but has **not** been tested in a Splunk runtime. See [Splunk time-zone interpretation](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-manual/dates-and-time/time-zones) and [time variables](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-manual/dates-and-time/using-time-variables).

**Important qualification hold:** The indexed-file query [`splunk.spl`](splunk.spl) still contains the same `time_window=10m` predicate implicated in Stage B's real **3/5 parity failure**. It must **not** be labeled validated or used as a production alert. The [bounded Stage B2 query](SPLUNK_MATRIX_BOUNDARY_RETEST.spl) produced a matching five-row screenshot, but indexed-file query parity remains untested.

**Implementation detail (original, currently failing the full matrix):** The first `streamstats current=f` computes the number of *prior* successful logins per (username, source_ip), providing a streak identifier. After every success, the next event for that key belongs to a new streak. The second `streamstats time_window=10m` counts only failures in the current streak. Sorting by global `_time` ensures that the time window is forward-looking in event processing order. Events with equal timestamps need an explicit deterministic tie-breaker; this fixture avoids ties.

The query is **SPL (Splunk Search Processing Language)**, not SPL2. Splunk's `streamstats` has a configurable maximum event window (often 10,000 events), so large-scale ingestion needs separate qualification.

## 3. Compare results against an independent expected fixture
Export **both** datasets from the same authorized isolated lab:

A. Raw event fields, using a separate query:
```spl
index=lab_auth sourcetype="portfolio:auth"
| table timestamp username source_ip host event_type scenario
```
Export as `splunk_raw_events.csv`; this must contain exactly **64 synthetic rows**.

B. The detection search **Statistics** results as `splunk_findings.csv`, ensuring fields `timestamp, username, source_ip, failure_count_in_window` are present and exactly **five** rows are returned.

**Do not compare only the five findings.** A wrong source, missing rows, or duplicate upload can otherwise produce misleading apparent agreement.

Run:
```sh
python projects/01-authentication-detection/validate_matrix.py
python projects/01-authentication-detection/validate_matrix.py --splunk-export path/to/splunk_findings.csv
python projects/01-authentication-detection/qualify_exports.py --raw-export path/to/splunk_raw_events.csv --findings-export path/to/splunk_findings.csv --report local_qualification.json
```

The first command checks the **Python reference detector** against the fixed expected matrix; it **does not execute Splunk**. The second independently checks provided result rows. The third compares **all 64 raw source events and five detection rows** to frozen expected values and writes SHA-256 digests of the inputs and query. **None of these commands can authenticate that Splunk produced the supplied CSV.** The JSON intentionally sets `splunk_runtime_validated=false` even if all rows match.

Only separately reviewing genuine Splunk search-job provenance, version, input/upload settings and search screenshots can substantiate on-platform execution.

Expected: **5 findings** (and 4 non-detecting scenario families) across these nine synthetic scenarios:

| Scenario | Expected alerts | Reason |
| --- | ---: | --- |
| threshold | 1 | five failures, then success |
| below | 0 | only four failures |
| intervening_success | 0 | earlier benign success breaks the streak |
| post_success_burst | 1 | five *new* failures after benign success |
| expired | 0 | successes outside ten-minute window |
| other_user | 0 | failures cannot be borrowed from another account |
| other_ip | 0 | failures cannot be borrowed from another source IP |
| ten_minute_boundary | 1 | event exactly ten minutes prior is inclusive |
| interleaved_users | 2 | two independent username/IP sequences |

The expected JSON contains the **five exact timestamp/user/IP/count rows** and is independent of the implementation.

## 4. Capture employer-grade evidence (once actually executed)
- Screenshot of Splunk Add Data field/timestamp preview, with personal identifiers removed.
- Screenshot of the smoke test's one result plus screenshot of the full query and its five result rows, with time picker and search index visible but no credentials.
- Saved raw-events and findings CSV exports, with the qualification report's SHA-256 hashes.
- Actual Splunk product/version, two search-job IDs (raw/detection), index/sourcetype, UTC/timezone settings, search time picker, and deviations from the runbook.
- A short paragraph explaining observed differences and how you resolved them.
- Verification output and local Python version, including any failing negative cases.

**Do not publish simulated Splunk screenshots or label Python output as live Splunk execution.**

## 5. Security and interpretation limitations
A five-failure success sequence is **not proof** of account takeover or password guessing; it can arise from authorized work. Conversely, source-IP rotation, missing events, NAT, clock skew, and distributed attempts can hide a real issue. Confirm MFA/identity logs, session behavior, account owner context and endpoint/network corroboration before asserting an incident.

## Sources
- [Splunk `streamstats` reference](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/streamstats)
- [Splunk source types and structured CSV extraction](https://help.splunk.com/en/splunk-cloud-platform/get-data-in/get-started-with-getting-data-in/10.2.2510/configure-source-types/manage-source-types)
- [Splunk timestamp parsing and UTC considerations](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/specify-time-ranges/how-time-zones-are-processed-by-the-splunk-platform)

## 6. Optional authenticated REST execution of the upload-free smoke test

The [read-only runtime runner](run_live_splunk_smoke.py) uses the **current Splunk REST v2 export endpoint**: `POST /services/search/v2/jobs/export`. An authorized token with search permissions and **TLS-verified access to Splunk management port** are required. This does not upload files, run scans, write Splunk configuration or produce production incidents. It sends only the [seven fabricated events query](SPLUNK_SMOKE_TEST.spl).

**Windows PowerShell** (run on a computer that can reach the authorized Splunk management endpoint):
```powershell
$env:SPLUNK_MGMT_URL = "https://your-authorized-splunk-host:8089"
python projects/01-authentication-detection/run_live_splunk_smoke.py --report smoke_local.json
```

The script prompts for an API token **without echoing it** if `SPLUNK_API_TOKEN` is not configured and a terminal is available. Do not paste API tokens into GitHub issues, chat, public screenshots, or the repository. The URL must be an HTTPS management origin with a trusted certificate; there is **no insecure TLS bypass**.

Run **without** `--report` to avoid writing an output file. Reports only record a minimal search-result comparison and cryptographic hashes, and intentionally do not include hostnames, tokens, usernames, or server version.

Expected returned report status: `SMOKE_RESULT_PASS`, one result at `2026-10-05T09:05:00Z`, username `smoke_user`, IP `192.0.2.99`, five failed logins. Passing verifies only the returned response (not the full lab, nor the operator's claimed execution environment); additional independent screenshots and job provenance still matter.

**Splunk Cloud Free Trial:** REST API access may be unavailable in the trial. In that case, use the Splunk Search UI and capture genuine results rather than weakening security controls or treating a failed API connection as a failed detection.

Do not commit `smoke_local.json` or any export without reviewing it first. For export and incident-report evidence, follow sections 1–5.

[Splunk REST API search/v2/jobs/export reference](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions) · [Splunk authentication token reference](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-user-manual/10.6/rest-api-user-manual/basic-concepts-about-the-splunk-platform-rest-api)
