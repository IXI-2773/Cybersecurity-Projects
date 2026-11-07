# SOC Triage Assistant

Working Python 3.11+ command-line tool for local CSV/JSON security exports.
Standard library only; run from a clone of this repository. No home PC, Splunk,
network, endpoint agent, third-party package or live account access is required.
The process-pattern checks reuse `../02-windows-process-triage/process_triage.py`.

## Run

From the repository root, choose a **new** output directory:

```sh
python projects/10-soc-triage/triage.py projects/10-soc-triage/fixtures/authentication.csv projects/10-soc-triage/fixtures/processes.json --output-dir /tmp/soc-triage-case
```

On Windows, replace `/tmp/soc-triage-case` with a new local directory such as
`soc-triage-case`. Open `report.html` in a browser and inspect `case.json` for the
machine-readable record. Existing output is never overwritten.

Exit **0** means complete processing under the declared schema; **2** means
partial processing with rejected rows preserved; **1** means fatal format/I/O
failure. A complete parse is not a security verdict. The public demo deliberately
returns **2**, because malformed rows must not disappear or look like clean data.

## Supported export contract

CSV requires unique headers; JSON requires an array of objects without duplicate
keys or non-finite numbers. Inputs are bounded to eight files, 5 MiB/file and 5,000
rows/file. This is a bounded utility, not an EVTX parser or universal vendor adapter.

| Field | Accepted names | Meaning |
| --- | --- | --- |
| Timestamp | `timestamp`, `time`, `TimeCreated` | ISO 8601 with explicit timezone; normalized to UTC |
| User | `username`, `user`, `User` | Required; case preserved; no domain alias inference |
| Host | `host`, `computer`, `Computer` | Required; trimmed and lowercased |
| Event type | `event_type`, `action` | `login_failure`, `login_success`, `process_start`; `event_id=4688` can identify a process event |
| Source IP | `source_ip`, `src_ip`, `IpAddress` | Required for authentication; validated IP; mapped IPv4 normalized |
| Stable event ID | `event_uid`, `record_uid` | Optional; must be stable and unique within a host across supplied exports |
| Process fields | `image`, `command_line` | Required for process records; parent image and positive process ID optional |

Conflicting aliases reject the row. A conflicting host/event UID quarantines all
rows carrying that key. An invalid copy with an unambiguous host and event UID
also quarantines otherwise valid copies of that identity. Matching normalized records with the same key coalesce
and keep every source reference. Rows without an event UID remain distinct;
lookalike rows alone do not prove duplicate events. A CSV with extra values is
retained as named fields plus an `extra_values` list, and quarantined.

References such as `S01:R000006` identify input file 1, data record 6. For CSV these
are records after the header, not physical line numbers (quoted multiline fields
can span lines). JSON uses one-based array positions. Input file hashes cover
exact bytes; parsed-record hashes cover the preserved canonical JSON structure.
The output also binds the executed triage and reused process source with hashes.
Reports include original parsed log content; review them before sharing.

## Review checks and limits

- Five or more earlier authentication failures within inclusive 600 seconds,
  followed by success for the same user, host and source IP. Every success resets
  the history. Failures tied with a success timestamp are excluded because their
  ordering is unknown. This is deliberately stricter than the older user/IP lab.
- Reused PowerShell encoded-command and certutil URL-cache/force patterns. The
  tool neither decodes/runs commands nor fetches URLs. Benign use can match.
- No automated severity assignment, compromise verdict, endpoint collection,
  notification, containment or remediation. Rejected rows limit completeness.

## Executed walkthrough and reproduction

The committed fixtures are synthetic and include harmless placeholder commands,
reserved documentation IPs and `example.invalid`. They are not incident telemetry.
The CLI itself was executed against these inputs; report data is not hand-authored.

| Input rows | Accepted events | Duplicate rows | Rejected rows | Review candidates |
| ---: | ---: | ---: | ---: | ---: |
| 20 | 13 | 1 | 6 | 3 |

The candidates are one authentication sequence, one encoded PowerShell command
and one certutil command. The controls include a below-threshold login sequence,
a diagnostic PowerShell command and a certutil hash check. Six quarantined rows
cover missing timezone, invalid IP, missing command, missing host and two
conflicting copies of one event UID.

1. Open [the actual report](artifacts/report.html) and inspect its PARTIAL status.
2. Follow a candidate's source references to the preserved records.
3. Compare the six rejected records and the duplicate to accepted timeline events.
4. Reproduce the run and verify its exact retained outputs:

```sh
python -m unittest discover -s projects/10-soc-triage -p 'test_*.py' -v
python projects/10-soc-triage/run_demo.py --check
```

[Recorded JSON](artifacts/case.json) · [CLI stdout](artifacts/execution.txt)

`run_demo.py` executes the real CLI in a temporary directory, requires its partial
exit status, checks independently declared counts/rule IDs/source references,
then compares JSON, HTML and stdout bytes. Omit `--check` to refresh those retained
artifacts after intentional source/input changes. No speed or production efficacy
claim is made. No private log upload or live SIEM workflow is performed.
