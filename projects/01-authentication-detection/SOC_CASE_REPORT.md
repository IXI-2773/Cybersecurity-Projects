# LAB-AUTH-001 — Authentication Signal Investigation

**Analyst:** Don Lopez · **Classification:** Fabricated SOC exercise, **not a real incident**  
**Data:** [16 synthetic login events](auth_events.csv) · **Rule:** five or more failures within 10 minutes, then success for the same user/IP  
**Observed synthetic outcome:** One alert · **Disposition:** `SIMULATED_REVIEW_REQUIRED`  
**Runtime:** [Python detector](detect_auth.py) verified in focused tests; **Separate synthetic Splunk smoke and corrected-matrix screenshots have been reviewed; indexed ingestion and alert firing remain unverified**

## 30-second analyst summary

In the fabricated October 1, 2026 event stream, account `alice` at `192.0.2.15` has **six consecutive failed logins from 09:00–09:05 UTC**, then a success at **09:06 UTC**. That matches the detection rule. It does **not** demonstrate password guessing by an attacker or a compromised account. Review MFA/session context and legitimate-user activity before deciding whether to escalate.

## Source-attributed timeline

| UTC time | CSV evidence | Observable fact | Rule consequence |
| --- | --- | --- | --- |
| 09:00–09:05 | [Rows 2–7](auth_events.csv) | Six `alice` failures, same documentation IP `192.0.2.15` | Failure threshold satisfied |
| 09:06 | [Row 8](auth_events.csv) | Matching success for `alice` | **One synthetic finding** |
| 09:07–09:09 | [Rows 9–11](auth_events.csv) | `bob` has two failures then success | Below threshold; **no alert** |
| 09:10–09:14 | [Rows 12–16](auth_events.csv) | `charlie` has five failures, but no success | Completion condition absent; **no alert** |
| 09:15 | [Row 17](auth_events.csv) | `alice` succeeds from a different IP | IP isolation prevents borrowing prior failures |

All addresses are documentation-only ranges, and the accounts and dates are invented. These are rows in the checked-in synthetic CSV, not a real identity-provider audit log.

## Analyst reasoning

**Supported conclusion:** A successful authentication immediately followed a threshold-matching burst of failures for one user/source pair. The detector generated one finding using this constructed input.

**Threat hypothesis:** The sequence is *consistent with* a [MITRE ATT&CK T1110 brute-force](https://attack.mitre.org/techniques/T1110/) investigation lead. It does not identify an adversary, prove credential compromise, or confirm account takeover.

**Alternative explanations:** Authorized password retries, a stale password in automation, help-desk activity, or a time/source normalization issue.

**Evidence missing:** MFA challenges and outcomes, session activity, historical account baselines, device ownership, identity-provider confirmation, IP context, privilege changes, endpoint actions, and actual user verification.

## Triage disposition and escalation boundary

**Disposition:** `SYNTHETIC_SIGNAL_ONLY — INVESTIGATE IF REPRODUCED ON AUTHORIZED REAL DATA`.

For an authorized production investigation: verify the source and event-time interpretation, examine MFA/session activity, check account and device history, and document corroborating/contradicting evidence. Escalation would be based on verified impact and local policy; **do not disable an account on this pattern alone**.

## Reproduce and challenge the detector

From repository root:

```bash
python projects/01-authentication-detection/detect_auth.py projects/01-authentication-detection/auth_events.csv
python -m unittest discover -s projects/01-authentication-detection -p 'test_*.py' -v
python projects/01-authentication-detection/validate_matrix.py
```

- [Expected findings](expected_findings.json) and [64-event validation corpus](validation_events.csv) cover **nine scenario families** with **five expected findings**.
- Regressions include boundary times, missing success, identity/IP isolation, CSV validation, and **a successful login breaking a failure streak even below the alert threshold**.
- The lab currently has **31 focused unit tests**. A prior bug carried old failures across a non-alerting success; the corrected Python implementation clears the streak on **every** success.
- [Splunk SPL draft](splunk.spl), [smoke test](SPLUNK_SMOKE_TEST.spl), and [runtime qualification runbook](SPLUNK_RUNBOOK.md) exist, with separate [reviewed corrected-matrix screenshot evidence](SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md). This 16-event report and that 64-event matrix are distinct exercises; indexed ingestion and alert firing remain unverified.

**Verification boundary:** Tests establish behavior against fabricated fixtures. They do not establish operational accuracy, false-positive rate, runtime equivalence in Splunk, or response authority.
