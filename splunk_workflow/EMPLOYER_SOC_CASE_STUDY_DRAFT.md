# SOC case study: Authentication burst detection and scheduled alert

> **Portfolio lab — synthetic data only.** This is a controlled, authorized Splunk Enterprise exercise, not a real breach, production SOC incident, or proof of real-world detection accuracy. The project was developed and validated with AI assistance. Screenshots and an owner-recorded walkthrough have **not** yet been completed.

**Project owner:** Don Lopez-Moya  
**Focus:** Detection engineering · Splunk SPL · SIEM validation · SOC investigation  
**Evidence status:** Indexed detection and one native scheduled-alert confirmation **passed** on November 8, 2026. Temporary schedule subsequently disabled.  
**Reference:** [Source-bound live confirmation record](https://github.com/IXI-2773/Cybersecurity-Projects/blob/c375b0403f493431e37f85a0176559d6534eab8e/splunk_workflow/LIVE_CONFIRMATION_2026-11-08.md) (published on `main` via [project PR #11](https://github.com/IXI-2773/Cybersecurity-Projects/pull/11); link pins merge commit `c375b04`).

## The 30-second story

I maintain a synthetic SOC lab that tests whether suspicious authentication sequences are detected **after actual indexing**, rather than only in an in-memory search. The correlation looks for at least five failed logins for one account and source IP within an inclusive 10-minute window, followed by a successful login. I validated the original 64-event test matrix, checked that negative cases did not produce extra findings, then used a separate six-event current-time replay to confirm that a **real scheduled Splunk search** generated a tracked alert. The workflow preserved the exact scheduled search result before the temporary alert was disabled.

The outcome is evidence of an operational lab workflow—not a determination that anyone was attacked.

## Detection objective and design

**Investigation lead:** A burst of failed logins immediately followed by a success may justify a credential-access review. It may also be explained by an authorized user recovering a password or automation using a stale secret.

**Correlation contract:**

1. Partition by both `username` and `source_ip`; do not combine activity from separate users or IPs.
2. Count at least five preceding failures in a **600-second inclusive window**.
3. Require a subsequent success for that same account/source pair.
4. Treat an intervening success as a reset, even if the previous failures were below threshold.
5. Preserve source UTC timestamps and field identity through indexing before evaluating the detector.

The [indexed detection SPL](searches/07_indexed_auth_detection.spl) implements the investigation logic. The [scheduled-alert SPL](searches/08_alert_preview_indexed.spl) additionally limits qualifying successes to the recent five-minute window. Both operate on purpose-built synthetic telemetry, not real employee accounts.

## Confirmed technical result

| Evidence | Verified lab observation |
| --- | --- |
| Input | 64 original synthetic authentication events plus six unique replay events |
| Indexed dataset | **70 source-equal rows**, with UTC event time checked against the input |
| Original correlation matrix | **5 of 5 expected findings**, with no extra findings from the supplied negative scenarios |
| Scheduled demonstration | **One native scheduled-search result** and **one tracked fired-alert entry** |
| Alert condition | True; the completed scheduled job returned **one matching result row** |
| Replay identity | `a7e1724930524217`, synthetic user `portfolio_replay_a7e1724930524217` |
| Replay source | `192.0.2.250`, host `SYNTHETIC-ALERT-REPLAY` |
| Cleanup | Temporary schedule disabled and unscheduled after evidence capture; no email, webhook, script, or other external action enabled |

The five original findings cover the **threshold**, **post-success reset**, **inclusive ten-minute boundary**, and **two interleaved-user** cases. The negative tests cover below-threshold activity, intervening-success reset, expired timing, another user, and another source IP. “No extra findings” refers to these **supplied synthetic fixtures**, not a measured production false-positive rate.

### Representative original findings

| Scenario | Synthetic account | Documentation source IP | Success time (UTC) |
| --- | --- | --- | --- |
| Threshold | `user_threshold` | `192.0.2.10` | 2026-10-05 09:05 |
| Post-success burst | `user_reset` | `192.0.2.13` | 2026-10-05 10:39 |
| Inclusive boundary | `user_boundary` | `203.0.113.10` | 2026-10-05 13:10 |
| Interleaved user A | `user_alpha` | `203.0.113.20` | 2026-10-05 13:40 |
| Interleaved user B | `user_beta` | `203.0.113.21` | 2026-10-05 13:41 |

## SOC investigation: One scheduled replay alert

**Case ID:** `LAB-AUTH-REPLAY-a7e1724930524217`  
**Classification:** Simulated authentication anomaly / investigation lead  
**Illustrative triage priority:** Medium; not an actual production severity assignment  
**Disposition:** `SYNTHETIC_DETECTION_CONFIRMED — NO REAL INCIDENT`

**Observed sequence:** Five fabricated failed authentications were followed by one fabricated successful authentication for the same replay user and IP. The earliest failure was exactly 600 seconds before the success. The temporary saved search ran on a one-minute schedule with a 20-minute lookback and a recent-success filter. Splunk retained a native fired-alert record and an associated completed-job result containing the exact replay identity.

**Triage reasoning:** The sequence is consistent with a password-guessing *lead* but cannot establish attacker intent or compromised credentials. Positive evidence is limited to the lab input and Splunk's observed alert behavior. The test corpus demonstrates that account/source mixing and certain benign-looking sequences are excluded by the rule; it does not resolve real-world context.

**Benign alternatives to examine on a real authorized investigation:** Password manager retrying an outdated credential, forgotten-password attempts, service-account misconfiguration, user self-recovery, shared network egress, and approved help-desk changes.

**Next evidence a real analyst would request:** MFA outcomes, successful session details, device and identity-provider records, previous account baselines, source-IP ownership and reputation, endpoint/EDR telemetry, geo/ASN context, privileged actions, and confirmation from the user or service owner.

**Proposed response boundary:** Preserve relevant records and open a triage ticket. Escalate or contain only if corroborated facts and organizational procedure justify it. **No account was locked, host isolated, or external notification sent in this exercise.**

## What was actually exercised

1. Compared the canonical fixture with indexed results, including individual source fields and UTC timestamps.
2. Ran the detection against indexed events and checked its original five positive cases and supplied negatives.
3. Added **only** a unique six-event replay to the isolated lab index; the canonical fixture was not uploaded again.
4. Observed one completed native scheduled search and tracked fired-alert record.
5. Captured the exact scheduled-job result and alert record **before** the temporary schedule was disabled.
6. Disabled and unscheduled the temporary alert to avoid repeat firings. Retained sensitive native responses locally outside version control.

**Evidence quality and limitations:** The confirmation workflow reported `INDEXED_AND_FIRED_ALERT_EVIDENCE_PASS`. The public [confirmation note](https://github.com/IXI-2773/Cybersecurity-Projects/blob/c375b0403f493431e37f85a0176559d6534eab8e/splunk_workflow/LIVE_CONFIRMATION_2026-11-08.md) identifies the run, source/artifact hashes, and privacy boundary. The verifier's separate HTTPS/token entrypoint was **not** exercised in this live attempt; native operations used an existing authenticated local Splunk CLI context whose hostname-verification setting was unchanged. The result is not independent attestation, a dashboard-rendering test, or evidence of scheduler suppression behavior. An earlier missing scheduled artifact has an **unresolved cause**; the corrected capture order succeeded but does not establish that root cause.

## Employer-view screenshots to capture when Splunk is available

These are **placeholders**, not existing captures. Use genuine screenshots with sensitive values concealed; keep timestamps, scenario names, and result counts visible where feasible.

1. **[PENDING] Indexed 70-event search:** Search bar/query, time range, and visible count.
2. **[PENDING] Five original detections:** One results table showing scenario, user, source IP, and success timestamp.
3. **[PENDING] Scheduled search / fired-alert record:** Saved search name, scheduler origin, one fired entry; mask session/token information.
4. **[PENDING] Single replay result:** Matching replay identity, success event, and one-result confirmation.

Do not imply the temporary alert is still enabled, and do not reconstruct a screenshot from text.

## 3–5 minute interview walkthrough outline

- **0:00–0:40 — Problem:** “I wanted a realistic SIEM demonstration that didn't stop at matching a CSV in memory.” Explain the five-failures-then-success hypothesis and why it is a lead, not a verdict.
- **0:40–1:35 — Engineering:** Show the indexed SPL and the 600-second inclusive window, user/IP isolation, and success reset.
- **1:35–2:25 — Validation:** Show the 64-event matrix and five expected findings; explain one negative scenario that prevents a false match.
- **2:25–3:25 — Operational proof:** Show real scheduled-alert evidence from the isolated six-event replay, one completed job result, and capture-before-disable handling.
- **3:25–4:15 — Investigation and next steps:** Explain plausible benign causes, what evidence would warrant escalation, and why the lab made no real remediation changes.
- **4:15–5:00 — Honest scope:** State that the data were synthetic, the exercise was AI-assisted, and the result does not establish production performance.

## Publication checklist

- [x] Live confirmation note retained on the project repository’s `main` branch (PR #11).
- [x] One concise investigation narrative with explicit alternative hypotheses and response boundary.
- [ ] Genuine redacted Splunk screenshots captured and reviewed.
- [ ] Owner personally walks through SPL, one positive, one negative, and the alert evidence.
- [x] Draft and project index linked in the published portfolio source (portfolio PR #38 merged); GitHub Pages propagation not independently checked.

**Related exercise:** [LAB-AUTH-001](../projects/01-authentication-detection/SOC_CASE_REPORT.md) describes a **different 16-event fabricated case** and retains its own historical verification boundary. It must not be mistaken for this 70-event live Splunk confirmation.
