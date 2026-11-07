# Stage D — Controlled Alerting and Tuning (Synthetic Lab)

**Status: NOT EXECUTED in Splunk.** A disabled saved-search definition and SPL preview exist, but **no alert has been enabled or triggered** by this project.

## The disabled alert

The Splunk app ships [`savedsearches.conf`](../splunk_app/don_lopez_soc/default/savedsearches.conf) with `disabled=1` and `enableSched=0`. It reads only `index=lab_auth sourcetype="portfolio:auth"` and has **no email, script, or webhook actions**. Do not turn it on for an external or production index.

The preview query [`08_alert_preview_indexed.spl`](searches/08_alert_preview_indexed.spl) tests for a success matching five prior failed logins within 600 seconds, returning only success events from the last **five** minutes. The search should read a **20-minute event-time window** if later scheduled, allowing a full ten-minute lookback. This is a small-fixture example and retains Splunk's bounded `list()` behavior.

## Demonstrate the detection and triage safely today

1. For an immediate, no-alert test, run [`09_alert_preview_synthetic.spl`](searches/09_alert_preview_synthetic.spl) inside the installed demo app; **expect five synthetic findings** (static October 5 data).
2. For indexed events, run [`08_alert_preview_indexed.spl`](searches/08_alert_preview_indexed.spl) after indexing, and use a time window that actually includes the event timestamps; **historical October 5 events do not count as recent events today**, so a zero recent-result is expected.
3. Inspect **Save As → Alert** configuration if authorized, using a separate *synthetic-only* index. For any scheduling demonstration, use a five-minute schedule and a twenty-minute search lookback, trigger on **number of results greater than zero**, consider suppression by `username,source_ip` for 30 minutes, and choose only approved built-in actions. Splunk provides schedule and throttle controls. Do **not** enable an automatic response or external notification.
4. Use the [execution evidence workflow](EXECUTION.md) to generate a **new authorized current-time test fixture**. Its six events preserve the inclusive 600-second boundary and use a unique synthetic identity. The original historical CSV cannot satisfy today's last-five-minute filter. The generator is implemented, but no such current-time fixture was indexed in this development session.
5. Before claiming the alert worked, preserve the actual Splunk alert configuration, search SID, one triggered-alert record, its finding fields and post-trigger deduplication behavior.

### Suggested analyst triage

Verify the identity and source of each alert, inspect MFA and session events, compare the account's usual activity and record alternative explanations. Suppression should not hide a new asset/identity or a separate higher-confidence detection.

**Scope:** Synthetic rule-configuration exercise only; no actual account lockout, host quarantine, intrusion or incident escalation is demonstrated.
