# Stage C — Authorized CSV Indexing and Investigation

**Status: NOT EXECUTED in the user's Splunk trial.** This runbook builds on an independently checked 64-event CSV, not an operational log stream.

## Before upload

1. Only use the checked-in, completely fabricated [`validation_events.csv`](../projects/01-authentication-detection/validation_events.csv). It contains 64 rows (plus header), nine scenario labels, and UTC timestamps dated **October 5, 2026**.
2. Use an **empty dedicated development index** named `lab_auth` if your trial permits index creation. Do not upload to a production index or overwrite data. If you cannot create an index, use an approved empty index and update the nine query files accordingly.
3. Splunk **Settings → Add Data → Upload**, select the CSV, preview and validate parsing. Choose sourcetype `portfolio:auth` if you can configure it; otherwise record the actual sourcetype and substitute it consistently.
4. Ensure the six fields appear with exact names: `timestamp, username, source_ip, host, event_type, scenario`.
5. Ensure event time uses the original `timestamp` in **UTC** (ISO-8601 with `Z`). On an authorized standalone Enterprise instance, CSV sourcetype parsing can be configured with `INDEXED_EXTRACTIONS = CSV`, `TIMESTAMP_FIELDS = timestamp`, `TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ`, and `TZ = UTC` in an appropriate sourcetype `props.conf`; use GUI preview to check before upload. Do not assume the app package automatically configures ingestion.
6. Review preview field mapping and index; only then submit. Record ingestion date, actual index, sourcetype, Splunk build, and input path. Do not upload twice.

## Verify first, without running the detector

Set Search & Reporting to **All time** or the explicit historical day and run:

```spl
index=lab_auth sourcetype="portfolio:auth"
| stats count as event_count dc(scenario) as scenario_count dc(username) as users
```

Expected: `event_count=64`, `scenario_count=9`. If not, **stop** and troubleshoot source paths, duplicate uploads, indexes and field extraction.

Check event-time range:

```spl
index=lab_auth sourcetype="portfolio:auth"
| stats min(_time) as first_seen max(_time) as last_seen
| eval first_seen=strftime(first_seen,"%Y-%m-%dT%H:%M:%S%z"), last_seen=strftime(last_seen,"%Y-%m-%dT%H:%M:%S%z")
```

Check the first and last records are consistent with October 5, 2026; render timezone output explicitly and do not infer UTC from the local web UI.

Inspect and export representative raw records using [`03_indexed_event_timeline.spl`](searches/03_indexed_event_timeline.spl). Confirm `_time`, `event_type`, `username`, `source_ip`, `scenario`.

## Run the actual indexed workflow

1. Run [`07_indexed_auth_detection.spl`](searches/07_indexed_auth_detection.spl).
2. Expected **five** candidate rows, with unchanged [oracle](../projects/01-authentication-detection/expected_findings.json). No added or missing rows.
3. Open the app's **SOC Authentication | Indexed CSV Investigation** dashboard, using the same authorized index and sourcetype settings. Screenshots remain **pending actual execution**.
4. Export **raw events** and **finding rows**, then compare using the existing [export qualifier](../projects/01-authentication-detection/qualify_exports.py) after confirming its required column names. Preserve job SID, timestamp and source provenance.
5. Mark a failure **as a failure**. Do not adjust the expected five detections simply to make a test pass.

### Limits

The original [`splunk.spl`](../projects/01-authentication-detection/splunk.spl) uses the `time_window=10m` behavior that yielded 3/5 in the in-memory test, so **do not use that query as the final indexed comparator**. Use `07_indexed_auth_detection.spl` and explicitly label results synthetic.

No uploaded fixture is proof of SOC production skill beyond the stated exercise. For actual investigation, correlate MFA, sign-in history and endpoint telemetry.
