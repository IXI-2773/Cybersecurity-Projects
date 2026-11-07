# Windows Process Execution Triage — synthetic Event ID 4688 lab

**What it is:** An offline, standard-library Python tool that analyzes fabricated Windows process-creation data. It emits candidate findings for PowerShell encoded-command switches and certutil URL-cache/force flags.

**What it is not:** Antivirus, a validated endpoint detection solution, malware attribution, or a live Windows Event Log collector.

## Run (Python 3.10+)

```bash
python -m unittest discover -s projects/02-windows-process-triage -p 'test_*.py' -v
python projects/02-windows-process-triage/process_triage.py projects/02-windows-process-triage/events_4688.csv
```

**Expected:** 11 passing tests and two rule-based triage candidates in synthetic data. The input uses an invented host/account and `example.invalid`, which is not a download endpoint.

| Rule | Trigger | Technique hypothesis |
| --- | --- | --- |
| `PS_ENCODED_COMMAND` | PowerShell image and encoded-command flag | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| `CERTUTIL_URLCACHE_FETCH` | certutil image with `-urlcache` and `-f` | [T1105](https://attack.mitre.org/techniques/T1105/) |

**Limitations:** Command-line logging may not be available; flag matching is simple and can match legitimate administration or miss obfuscation. The test suite uses only fabricated data. No live environment was scanned or monitored. Technique hypotheses are not findings of compromise.

**Analyst follow-up:** Verify signer and executable path, parent process and account, contextual PowerShell/EDR records, and proxy/file telemetry. Escalate only with corroboration.

## SOC analyst case report

Read [LAB-PROC-001 — simulated investigation](CASE_REPORT.md) for a source-row timeline, both rule matches, three negative controls, benign alternatives, and authorization-aware evidence requests. This is a reproducible fixture review, not a production endpoint incident.
