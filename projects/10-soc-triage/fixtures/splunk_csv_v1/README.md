# Offline authentication CSV contract — v1

Status: **synthetic contract and fixtures prepared; importer change pending**.
These files were authored for an offline test, not exported from Splunk. They
do not establish live connectivity or native Splunk export compatibility.
The production importer does not yet recognize `_time`.

## Input format

Use UTF-8 CSV with one authentication event per record and this header:

```csv
_time,username,host,source_ip,event_type,event_uid
```

| Column | Existing normalized field | Contract |
| --- | --- | --- |
| `_time` | `timestamp` | ISO 8601 with `T` and an explicit timezone (`Z` or numeric offset); normalized to UTC. No epoch values or inferred local timezone. |
| `username` | `username` | Required, nonempty user name. |
| `host` | `host` | Required host; existing normalization case-folds it. |
| `source_ip` | `source_ip` | Required valid IP address; existing canonicalization applies. |
| `event_type` | `event_type` | Exactly `login_failure` or `login_success`. The producer must provide these values; no vendor-field inference. |
| `event_uid` | `event_uid` | Optional stable identity within a host across supplied files. Blank or absent IDs remain distinct; do not invent IDs to deduplicate events. |

This is an explicitly shaped event export, not an aggregate alert-count input.
Unrecognized named fields are preserved but not interpreted; recognized aliases
retain existing validation and conflict checks. Existing restrictions remain:
at most eight files, 5 MiB and 5,000 records per file, and unique nonempty
headers. Incorrect field counts are rejected; extra values remain in the source
record. Do not silently repair malformed records.

## Evidence and rejection behavior

Reuse the existing reader, normalizer, investigation logic and report generator.
Retain each input file's SHA-256, parsed raw fields, record hash, source reference
and rejection reason. Parsed records are not a byte-for-byte representation of
CSV quoting: retain the original CSV file alongside its hash.

Preserve existing alias-conflict behavior: stripped strings are compared before
timestamp parsing. If `_time` and another timestamp alias disagree, reject the
record even if the two strings represent the same instant. Keep host-aware
grouping, same-time ordering rules and invalid/conflicting-identity quarantine.

## Fixture pair and previously observed diagnostic

The completed diagnostic used the unchanged source at commit
`0a3049fdf864c55867ee198b038821404769837b`, then temporarily appended `_time` to
`ALIASES['timestamp']` in memory and restored the tuple afterward. It did not edit
the importer. It exited 0; the results below summarize that earlier diagnostic,
which was **not rerun during this save-only slice**. No generated case JSON or
HTML report was retained. These are diagnostic observations, not a shipped
integration test or genuine-export validation.

| Input and mode | Input records | Accepted | Rejected | Review candidates |
| --- | ---: | ---: | ---: | ---: |
| Both fixtures, unchanged importer | 14 | 0 | 14 | 0 |
| `valid.csv`, temporary alias | 8 | 8 | 0 | 1 |
| `malformed.csv`, temporary alias | 6 | 0 | 6 | 0 |
| Both fixtures, temporary alias | 14 | 7 | 7 | 0 |

- `valid.csv`: five failures followed by success at the inclusive 600-second
  boundary; a separate one-failure/success negative control. The first timestamp
  normalizes from `12:00:00+02:00` to `10:00:00Z`. Candidate references cover rows
  1–6; original `_time` remains in the parsed raw record.
- `malformed.csv`: invalid timestamp, absent timezone, invalid IP, absent host,
  unsupported event type and an extra CSV field. The extra value is retained.
- Combined: the invalid first record in `malformed.csv` intentionally shares
  host and UID with the first valid record. Both copies are quarantined, leaving
  four burst failures and no candidate. All 14 parsed source records are retained.

The diagnostic also checked source references in the in-memory HTML report.

| Artifact | SHA-256 |
| --- | --- |
| `valid.csv` | `b76966b8cdef9dfc0e14e26f18a16384815d8797c2973dfc22df70c391265514` |
| `malformed.csv` | `ea92256f387b8cb2aaeca4a18a7ab0b81b3fd100a13fb2d42934d738b8ed01ce` |
| `triage.py` baseline | `f74800fa490303e2a62d061b53ca2d0ffdc6ebbbcc5b83800495a84ae1787fd7` |
| `process_triage.py` baseline | `cd8784969935356a724d55a2a5f1e7885f6338fe5b1d5d4137e0578398412064` |

## Smallest next implementation slice

1. Append `_time` to the existing timestamp alias tuple in `triage.py`. No
   separate converter, new detection rule or intermediate normalized file.
2. Add focused tests for the fixture outcomes above, conflicting timestamp
   aliases, rejected naive/epoch timestamps and preserved blank-UID behavior.
3. Retain a small CLI case/report with hashes tied to the changed source before
   publishing an implemented outcome. Do not rerun the whole lab or full suite.

The alias table is also used by existing JSON-array input; this change would not
add support for native Splunk JSON envelopes or streaming exports. Keep the new
integration labeled **offline synthetic validation** until an authorized genuine
event export is processed. Live Splunk, PC access, Commander, credentials,
notifications and containment are outside this slice.
