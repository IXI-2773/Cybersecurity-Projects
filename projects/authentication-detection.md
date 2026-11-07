# Authentication Detection & Triage

**Reproducible synthetic SOC lab · 31 focused Python tests**

The lab parses fabricated authentication events and flags **at least five failures within ten minutes, followed by success**, grouped by username and source IP. Every success ends its failure streak so an earlier non-alerting success cannot contaminate a later finding.

| Evidence | Observation |
| --- | --- |
| [Synthetic CSV](01-authentication-detection/auth_events.csv) | One fabricated `alice` event sequence qualifies |
| [Python detection source](01-authentication-detection/detect_auth.py) | Deterministic rule and JSON output |
| [Validation matrix](01-authentication-detection/expected_findings.json) | 64 artificial events; five expected findings across nine scenario families |
| [Focused unit tests](01-authentication-detection/test_detect_auth.py) | Regression, isolation and malformed input behavior |
| [Analyst case report](01-authentication-detection/SOC_CASE_REPORT.md) | Timeline, alternative explanations and uncertain findings |
| [Splunk runbook](01-authentication-detection/SPLUNK_RUNBOOK.md) | Seven-event smoke and corrected 64-event result screenshots reviewed; 5/5 corrected findings. Indexed ingestion and alert firing remain unverified. |

**ATT&CK:** T1110 is an investigative hypothesis only. Fabricated events do not prove compromised credentials, operational detection efficacy, or any real intrusion.

[All GitHub-readable case studies](CASE_STUDIES.md) · [Visual case study](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/authentication-detection.html)
