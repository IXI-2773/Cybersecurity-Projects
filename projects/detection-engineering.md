# Detection Engineering & Rule Development

Build detections that explain the behavior they match—and the benign activity they can confuse.

Splunk SPL · Python · MITRE ATT&CK · 2026

**Public authentication validation:** 64 events, nine scenarios and five expected findings. Corrected Splunk output matches all five.

## The investigation problem

A rule that matches a suspicious command or a login burst is a starting point. Its value depends on the behavior it is intended to detect, the data it needs and the legitimate activity that can produce the same pattern.

## What I validated

I investigated why an authentication search returned three of five expected findings on a frozen 64-event training matrix. Both misses depended on the exact ten-minute boundary. An explicit inclusive 600-second comparison replaced the original window assumption; the corrected query and saved Splunk panel displayed all five expected findings.

This measures agreement with the fixture's expected findings. It is not a false-positive reduction, a precision/recall estimate or evidence of production detection performance.

**Inspect the evidence:** [Source events](01-authentication-detection/validation_events.csv) · [Expected findings](01-authentication-detection/expected_findings.json) · [Corrected SPL](01-authentication-detection/SPLUNK_MATRIX_BOUNDARY_RETEST.spl) · [Observed-result record](01-authentication-detection/SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md).

The [interactive rule laboratory](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/detection-engineering.html#auth-lab-title) replays the public fixture locally in JavaScript. It does not run Splunk.

## How I explain a detection

- **Define the behavior.** State the account, host, command or time-window relationship that makes an event relevant.
- **Choose the telemetry.** Identify fields, timestamp meaning and required source coverage before interpreting a match.
- **Challenge the rule.** Compare simulated attack activity with benign administration and normal authentication failures.
- **Tune and document.** Record what changed, what was excluded and which blind spots remain.

## Existing rules and controls

| Capability | Inspectable condition | Evidence and controls |
| --- | --- | --- |
| Authentication correlation | At least five preceding failures in the same account/IP stream, with ages zero through 600 seconds; every success resets the streak | [Python detector](01-authentication-detection/detect_auth.py), [boundary and isolation tests](01-authentication-detection/test_detect_auth.py), corrected SPL above |
| Windows command candidates | PowerShell encoded-command flags; certutil URL-cache and force flags are a separate predicate | [Rule source](02-windows-process-triage/process_triage.py), [benign and flag-boundary controls](02-windows-process-triage/test_process_triage.py) |
| Recorded AD correlation | Distinct-account failures, RC4 service tickets and remote PowerShell retain exact source references and competing explanations | [Conditions and evidence joins](08-ad-investigation/CASE_REPORT.md), [isolation and missing-corroboration tests](08-ad-investigation/test_analysis.py) |

The [rule-to-evidence matrix](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/docs/DETECTION_EVIDENCE_MATRIX.md) maps inputs, implementations, verification and remaining gaps. These are existing public examples, not the original résumé rule collection. The AD Python analysis is executed; its SPL/Sigma translations remain unexecuted candidates and do not implement the complete host/session/network correlation.

## Earlier résumé lab work

My résumé reports more than five SPL/Sigma rules for brute force, encoded PowerShell and lateral movement, and approximately 30% fewer false positives during lab validation. The original rule collection and before/after event sets are not published here. Reproducing that result requires the original rules, labeled inputs, false-positive counts and denominators, matching criteria and tuning procedure. The public authentication and AD examples have their own inputs and results; they do not substantiate that earlier percentage.

## Scope and evidence

The authentication case uses synthetic inputs and a genuine screenshot-reviewed Splunk result. The AD case separately analyzes OTRF recorded emulation in Python. Indexed ingestion, scheduled alert firing and production detection efficacy remain unverified.

Background reference

[MITRE ATT&CK: brute-force behavior ↗](https://attack.mitre.org/techniques/T1110/). This reference informs the investigation approach; it does not verify my lab results.

[Choose another case study ↗](https://ixi-2773.github.io/Cybersecurity_Portfolio/explore.html)

## Academic foundation

Completed coursework: IST 4210 Advanced Networking & Security and IST 5250 Incident Handling & Cyber Investigation (Fall 2024).

[Explore the academic background](https://ixi-2773.github.io/Cybersecurity_Portfolio/education.html).
