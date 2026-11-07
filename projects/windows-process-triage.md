# Windows Process Execution Triage

**Reproducible synthetic Windows Event 4688 exercise · 11 focused tests**

The lab examines fabricated process-creation records for patterns worth reviewing: PowerShell encoded-command arguments and certutil URL-cache/force flags. Neither pattern establishes malicious execution without corroborating process lineage, script content, user context and independent endpoint or network data.

| Evidence | Description |
| --- | --- |
| [Synthetic 4688 fixture](02-windows-process-triage/events_4688.csv) | Fabricated benign and candidate events |
| [Python triage analyzer](02-windows-process-triage/process_triage.py) | Local command-line pattern checks |
| [Focused unit tests](02-windows-process-triage/test_process_triage.py) | Rule and validation behavior |
| [Analyst playbook](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/docs/SOC_TRIAGE_PLAYBOOK.md) | Investigation, evidence handling and handoff |

**Hypotheses:** ATT&CK T1059.001 (PowerShell execution) and T1105 (ingress tool transfer) are classifications for analyst review, not confirmed attacks.

No real endpoints were monitored. No production EDR deployment is claimed.

[All case studies](CASE_STUDIES.md) · [Designed page, after Pages activation](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/windows-process-triage.html)

**Detailed analyst write-up:** [LAB-PROC-001 source timeline and evidence-based disposition](02-windows-process-triage/CASE_REPORT.md).

## Academic foundation

Completed coursework: IST 4910 Enterprise Systems Administration and IST 5250 Incident Handling & Cyber Investigation (Fall 2024).

[Explore the academic background](https://ixi-2773.github.io/Cybersecurity_Portfolio/education.html).
