# Synthetic Linux Access Hardening — Section 5 Review

**Work type:** authored fixture, offline execution and analysis using a **third-party** Linux CIS auditor. The auditor itself is ©AngelaMos (2026), imported unmodified from [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/6c8ac8547cf52edaa06935e637a1fe11ac45b865/PROJECTS/beginner/linux-cis-hardening-auditor) under AGPL-3.0-or-later. [Copied source](../../third_party/community/linux-cis-hardening-auditor/) · [Author and license ledger](../../THIRD_PARTY.md).

**Question:** In a fabricated Debian-style configuration, which SSH and password-policy checks change when unsafe settings are replaced with more restrictive proposals?

## Recorded result

The imported Bash scanner was executed with `--test-root`, `--categories 5`, `--format json` and `--quiet` on two synthetic roots. It did **not** inspect a real host or deploy changes.

| Result for 23 selected controls | Before | After |
| --- | ---: | ---: |
| PASS | 2 | 19 |
| FAIL | 18 | 1 |
| SKIP | 3 | 3 |
| WARN | 0 | 0 |
| Scanner-reported scored percentage | 10% | 95% |

**17 controls changed from FAIL to PASS.** Relevant examples:

| Control | Weak fixture | Proposed hardened fixture |
| --- | --- | --- |
| 5.2.2 SSH access restriction | No allow/deny directive | `AllowUsers lab-analyst` |
| 5.2.6 Authentication attempts | `MaxAuthTries 8` | `MaxAuthTries 4` |
| 5.2.8 Root SSH login | `PermitRootLogin yes` | `PermitRootLogin no` |
| 5.2.11 Cipher selection | Includes `aes128-cbc` | Modern AEAD cipher list |
| 5.2.12 / 5.2.13 | Weak MAC and key exchange included | Weak variants removed |
| 5.3.1 / 5.5.1 | Password-quality / lockout PAM rules absent | `pam_pwquality` and `pam_faillock` entries |
| 5.4.1–5.4.3 | 99999 max / 0 min / 0 warning days | 365 max / 1 min / 7 warning days |

**The remaining failure is 5.1.1** (cron daemon not enabled/present in the fixture). Checks 5.1.2–5.1.4 were **SKIP**, since cron configuration paths are absent. These are intentional scope limits, not “fixed” controls.

## Reproduce the evidence

From the collection root, with Bash, GNU utilities and Python 3 available:

```bash
python3 projects/15-linux-cis-synthetic-hardening/verify_lab.py
```

The verifier executes the **unchanged imported scanner**, confines its inputs to the two committed fixture roots, removes only non-deterministic `timestamp` and `hostname` fields from the returned JSON, and checks that the resulting reports exactly match the saved artifacts. It also checks the 17 state transitions, selected control IDs and remaining failure. No pip installation, network or privileged host access is needed.

- [Before fixture](fixtures/before/etc/ssh/sshd_config) · [After fixture](fixtures/after/etc/ssh/sshd_config)
- [Before JSON](reports/before.json) · [After JSON](reports/after.json)
- [Verification runner](verify_lab.py)
- Source files were read from collection commit [`4ac88d5912d4`](https://github.com/IXI-2773/Cybersecurity-Projects/tree/4ac88d5912d4ab87c780f0d466e53c8ad5e139f0); all 17 imported Bash files used for the execution matched their Git blob identities.

Normalized report SHA-256 values:
- `reports/before.json`: `101533d77f7dd3e1192c0619fb9959bb9c52ee65b4069997e8013b1823097d22`
- `reports/after.json`: `b619cca6b2f67e6e3df4f34a1afb6e374a3b42198bb69cb58ec60ce6384f6c16`

## What this demonstrates—and does not

- Demonstrates how to set up a controlled SSH/PAM hardening scenario, use a credited scanner consistently, compare its actual emitted results and retain reviewer-reproducible evidence.
- The upstream auditor labels the report “CIS Debian Linux 12 Benchmark v1.1.0”; this exercise covers **only its 23 section-5 checks**, not the full CIS benchmark, a validated benchmark implementation or certification.
- Two checks (5.2.1 and 5.2.3) report PASS in test mode even though SSH file permissions cannot be verified and no host keys were provided. They must **not** be read as genuine permission or key-security assurance.
- The test root includes illustrative PAM entries, not a functional operating-system authentication stack. The scanner checks text patterns; it does not prove SSH/PAM service behavior, secure algorithms, account safety, or effective enforcement.
- The scores are `PASS / (PASS + FAIL)` within this selected synthetic set, excluding SKIPs. A 95% figure is **not a real-host compliance score**.
- No real credentials, host logs, network targets, organization data, production systems or live remediations are involved. This lab was prepared and executed in an assistant-supported workspace; the owner should reproduce it before describing individual hands-on operation in an interview.

### Review decision

In this synthetic context, the proposed settings address 17 scanner-detected review findings. The cron-related failure and all unverified checks remain open. A real deployment would require permission, change control, compatibility testing, service-level validation and rollback.
