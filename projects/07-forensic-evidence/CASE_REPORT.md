# LAB-DFIR-001 — Forensic Evidence Examination

## Question

Do the supplied lab-created artifacts support a download-to-scheduled-task sequence?

## Integrity and handling

- Acquired package SHA-256: `409bd208bf9a794f61e72176cc19c713cb81abb29e7b0006612075fed2c64cba`
- Working-copy SHA-256: `409bd208bf9a794f61e72176cc19c713cb81abb29e7b0006612075fed2c64cba`
- Three artifacts were inventoried after the hash check.
- The examiner copied the verified package to a temporary working location and did not extract from or write to the original.
- A mismatched package hash or unsafe archive path stops examination before artifact parsing.

## Observations

1. `browser_history.csv` records a lab portal sign-in at 18:02 UTC.
2. The same artifact records a remote-support download URL at 18:07 UTC.
3. `scheduled_tasks.xml` records creation of `SupportUpdate` at 18:09 UTC.
4. The task command references the same `remote-support.exe` filename shown in the earlier URL.

## Findings

| Finding | Evidence | Interpretation |
| --- | --- | --- |
| `FORENSIC_DOWNLOAD_SEQUENCE` | `browser_history.csv`, 18:07 UTC | A download record precedes task creation by two minutes. |
| `FORENSIC_PERSISTENCE_REFERENCE` | `scheduled_tasks.xml`, 18:09 UTC | The task command references the downloaded filename. |

## Assessment

The supplied artifacts support a download-to-scheduled-task sequence in this bounded fixture. They do not establish that the executable ran, that it was malicious, or that a particular person intended the activity.

## Scope

This is independently created portfolio evidence, not a recovered E3 assignment. It represents no real person, device, organization, or incident. Paraben E3 classroom use is a separate, owner-confirmed experience.

## Method foundation

The high-level workflow—preserve integrity, minimize handling of the original, plan the analysis, cite artifacts, and report bounded findings—was informed by Chuck Easttom's *Digital Forensics, Investigation, and Response, Fourth Edition*. No textbook exercise or passage is reproduced.
