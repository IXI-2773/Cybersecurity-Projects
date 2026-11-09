# Authentication Export → Analyst Case Report

A working Python workflow turns an authentication CSV into a readable analyst
handoff: a UTC timeline, review candidates, original source records and explicit
rejection reasons. It reuses the existing investigation logic and HTML report
generator rather than adding a separate conversion pipeline.

## What the execution demonstrates

| Input | Accepted events | Rejected records | Review candidates | CLI exit |
| --- | ---: | ---: | ---: | ---: |
| Eight-event authentication export | 8 | 0 | 1 | 0 — complete |
| Same export plus six malformed records | 7 | 7 | 0 | 2 — partial |

The candidate is five failures followed by a success within the inclusive
600-second window, for the same user, host and source IP. A separate
below-threshold sequence does not produce a candidate. Follow source references
`S01:R000001` through `S01:R000006` in the valid report to inspect the evidence.

In the mixed run, an invalid record shares an identity with a valid event. Both
copies are quarantined, leaving four burst failures. The resulting zero-candidate
output is **partial evidence, not an all-clear**. All 14 source records remain
available, including the extra malformed CSV value.

Analyst follow-up: confirm account ownership, MFA context and whether the activity
was approved. Mistyped credentials, an authorized test or a credential change
are benign alternatives to investigate. The tool does not assign incident
severity, establish compromise or take response actions.

## Retained outputs

- Valid input: [case.json](valid/case.json) · [report.html](valid/report.html).
- Mixed input: [case.json](mixed-rejected/case.json) · [report.html](mixed-rejected/report.html).
- [CLI execution record](execution.txt) · [Input contract and fixtures](../../fixtures/splunk_csv_v1/README.md).

Download an HTML report and open it in a browser; GitHub displays its source.

## Methodology and scope

Executed on 2026-11-09 using synthetic authentication events, clearly named lab
hosts and documentation IP addresses. The inputs were shaped to the declared
CSV contract; they are not captured incident telemetry or genuine Splunk exports.
The real CLI produced these files. No report findings were hand-authored, and no
live Splunk connection, endpoint collection or response action was used.

The importer now accepts `_time` as an explicit-timezone timestamp alias.
Existing validation, alias conflicts, identity quarantine, source hashes and
HTML escaping remain active. The shared JSON-array path also validates `_time`.
This is not a claim of universal vendor-format support or production efficacy.

Nine new contract tests failed against the original importer and passed after
the change. Four nearby existing checks passed. The original 20-row demo was
executed once to refresh its source-bound artifacts; its declared counts, rule
IDs and source references were unchanged. No full-suite run was performed.

## Reproduce

From the repository root, use new output directories (existing directories are
never overwritten):

```sh
python -B -m unittest discover -s projects/10-soc-triage -p test_splunk_csv.py -v
python projects/10-soc-triage/triage.py projects/10-soc-triage/fixtures/splunk_csv_v1/valid.csv --output-dir auth-export-valid
python projects/10-soc-triage/triage.py projects/10-soc-triage/fixtures/splunk_csv_v1/valid.csv projects/10-soc-triage/fixtures/splunk_csv_v1/malformed.csv --output-dir auth-export-mixed
```

The mixed command intentionally returns exit 2. Both case files record the input
file hashes and these executed source hashes:

| Source | SHA-256 |
| --- | --- |
| `triage.py` | `c10abcf1c3b79227d36a1825e480dd8568b55c5b699effd5f5241f494a54b976` |
| `process_triage.py` | `cd8784969935356a724d55a2a5f1e7885f6338fe5b1d5d4137e0578398412064` |

| Retained output | SHA-256 |
| --- | --- |
| Valid case JSON | `494ee0650988e1f3bfdab43ad568266d99cc15f6e47445c77a43df634b20c010` |
| Valid HTML report | `a0a9d06b96b859ff51e79830d8c36b6adee5c224149235ed4ad75a9c497d3d5b` |
| Mixed case JSON | `d2ec2f87ea9efa300070b87415f519126d33be99f8b299333484def94d48c403` |
| Mixed HTML report | `699f24143601fd00873f7ca66cf4d3e284e7e599d09c9586633cc53f523e6860` |
