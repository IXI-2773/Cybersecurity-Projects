# Indexed evidence → fired alert → analyst handoff

**Implementation status:** the preparation/verifier is covered by offline tests. **Live Splunk execution has not occurred in this development session:** no management endpoint or token is configured, and the connected desktop is offline. No new ingestion, fired-alert, dashboard or scheduled-execution accomplishment is claimed.

The existing app and runbooks already provide the searches and disabled alert. This command-line aid removes manual CSV comparison and handoff assembly. It creates bounded search jobs and reads an existing fired-alert job through authenticated REST; it does **not** upload events, install apps, enable a schedule, send notifications or modify accounts.

## 1. Establish the canonical indexed data

Use an authorized **empty development index** named `lab_auth` or `lab_auth_<suffix>`; the verifier accepts only this naming family. Follow [INGESTION.md](INGESTION.md) to upload the original [64-row fixture](../projects/01-authentication-detection/validation_events.csv) once, with sourcetype `portfolio:auth` and correct UTC event times. Keep its six source field names unchanged.

Do this **before** generating the fresh replay. The current-time success must still be inside the alert's five-minute filter when the scheduled search executes.

## 2. Prepare the controlled alert

Use the existing [alerting guide](ALERTING.md) and [indexed alert search](searches/08_alert_preview_indexed.spl). In the authorized lab, create a separate temporary saved alert, for example `Portfolio Replay`, in Search & Reporting. Substitute the selected lab index if needed.

- Search lookback: **20 minutes**, ending now.
- For this short demonstration, schedule every minute; the saved package remains disabled and unchanged.
- Trigger when results exceed zero; retain triggered-alert tracking (`alert.track=1`).
- Keep email, webhook, script, and other external actions off.
- Record its actual owner, app and name. The commands below use `admin` and `search` only as examples.
- Disable the temporary schedule after collecting the evidence.

The verifier observes a native fired-alert record; it does not infer scheduler origin or suppression behavior from its existence. Those remain separate checks.

## 3. Generate and upload the fresh replay

From the repository root, with Python 3.10 or newer:

```sh
python splunk_workflow/verify_execution.py prepare --output local_splunk_run
```

This creates a new directory and refuses to overwrite an existing one. It contains:

| File | Purpose |
| --- | --- |
| `canonical.csv` | Byte-identical copy of the original fixture; **do not upload it again** if step 1 is complete |
| `replay.csv` | Five failures followed by one success; the oldest failure is exactly 600 seconds before the current UTC success |
| `manifest.json` | Unique replay identity, UTC anchor and file hashes |

Upload **only `replay.csv`** to the same lab index and sourcetype, using the existing parsing/UTC preview checks. It uses a unique synthetic account and scenario, a documentation-range IP, and a synthetic host label. No credentials or real account activity are involved.

The expected combined index is now **70 events: 64 canonical plus six replay rows**. Wait for the actual triggered-alert entry. A manually run preview is insufficient. If the five-minute window expires first, use a new approved empty lab index and a new prepared directory for another attempt; preserve prior evidence and avoid duplicate uploads.

## 4. Collect and verify the native evidence

Set `SPLUNK_MGMT_URL` and a scoped `SPLUNK_API_TOKEN` in the **local process environment**. Do not put the token in a command argument, repository file or chat. Use a trusted HTTPS management origin such as `https://localhost:8089`; TLS verification and redirect rejection are mandatory. If the lab uses a private CA, configure Python's trusted CA bundle locally rather than disabling verification.

The token needs permission to search the isolated lab index and read the relevant fired-alert entry and job results. It does not need configuration-write privileges for this verifier.

```sh
python splunk_workflow/verify_execution.py verify --output local_splunk_run --index lab_auth --owner admin --app search --alert-name "Portfolio Replay"
```

The verifier checks:

1. Canonical/replay file custody and exactly 70 indexed rows, rejecting missing or duplicate data.
2. Native indexed event time against every source UTC timestamp, before the detection SPL recalculates time.
3. All 64 canonical rows and the five original expected findings using the existing [CSV qualifier](../projects/01-authentication-detection/qualify_exports.py), plus host/scenario binding.
4. A native fired-alert instance with the requested name and replay time range, followed by its completed job's exact replay finding. Its original `request.search` must match the existing indexed alert SPL for the selected lab index, and its owner/app ACL must match the requested namespace. A generating query or a same-looking result from another index cannot qualify. Failed, prematurely finalized, truncated or inconsistent search results are rejected.

Only after all checks pass does it write `INDEXED_AND_FIRED_ALERT_EVIDENCE_PASS`, the compared CSV exports, source/query/artifact hashes, job SIDs, and `handoff.md`. Reports and handoffs reset to an unverified state before another attempt, including connection failures. Missing connection settings produce `BLOCKED_NO_CONNECTION`.

Keep this directory private until reviewed. The suggested `local_splunk_run*` directories are ignored by git. These are authenticated-response checks, not independent attestation, a claim of production efficacy, proof of dashboard rendering, or validation of scheduler/suppression behavior. **Offline protocol tests cannot supply execution evidence.**

## API and reproduction references

The implementation uses the official [Splunk search endpoint reference](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions): job creation/status under `search/jobs`, completed results under `search/v2/jobs/{search_id}/results`, and native fired-alert entries under `alerts/fired_alerts/{name}`. Owner/app namespaces must match the actual alert. The documented API reference is 10.2; the installed instance/version remains to be qualified.

```sh
python -m unittest discover -s splunk_workflow -p 'test_*.py'
python -m unittest discover -s projects/01-authentication-detection -p 'test_*.py'
python scripts/check_splunk_workflow.py
```
