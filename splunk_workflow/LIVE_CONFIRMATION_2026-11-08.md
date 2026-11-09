# Live Splunk confirmation — 2026-11-08

Status: `INDEXED_AND_FIRED_ALERT_EVIDENCE_PASS`.

This was one bounded, authorized synthetic lab confirmation, not a production incident.
Collector source commit: `1a5178466c5057940cee251407fa7307e08ae176`.
Replay run ID: `a7e1724930524217`.

## Verified results

- 64 canonical events plus six fresh replay events: exactly 70 indexed rows, with native UTC timestamps matching their sources.
- All five expected canonical findings matched; the fixture's negative scenarios produced no extra findings.
- One native tracked-alert instance and its exact replay finding were captured before schedule cleanup.
- The same job's native scheduler log confirms scheduled execution, success, one result, and a true alert condition.
- The temporary schedule was disabled and read back as unscheduled; external actions remained off.

## Retained private evidence

The source-bound runtime files remain in the ignored local evidence directory `local_splunk_run_20261108_003`; no credentials or raw local logs are committed.

| Artifact | SHA-256 |
| --- | --- |
| confirmation.json | 11bdee7320d43fa23384e9199cb6a8f005e6dc6b9189395477c30cf75a5fbdbb |
| verification.json | 6d71bc8ff1791c90e86e0d71bc6538c938e6275f5c0d3a1b4ee19c4bc7e6ba80 |
| fired_alert.json | 861add96770ef1bab1963a8e2b0cf9759c83460a51bc05b2f82958c75e79eab9 |
| fired_findings.csv | 8e78fcdc9c80da7206c55cf49a4432072254cdab0d4abf8c8bf31e13f42b4c59 |

## Limits

Execution used the native, already-authenticated local Splunk CLI adapter. CLI hostname validation was disabled in the existing configuration; it was not changed. The original bearer-token, TLS-verifying entrypoint was not executed. This is not independent attestation, suppression-policy validation, production efficacy, or proof of a real compromise. The cause of the earlier missing retained artifact is still unproven. Screenshots and the employer-facing investigation narrative are not completed by this run.
