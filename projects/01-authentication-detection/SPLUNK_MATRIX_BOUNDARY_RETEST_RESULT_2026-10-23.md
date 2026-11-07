# Stage B2 — Boundary-Corrected Splunk Matrix: Screenshot Review

**Date received/reviewed:** October 23, 2026  
**Environment:** Operator-provided Splunk Statistics screenshot; earlier full-screen evidence showed Splunk Enterprise free-trial user interface.  
**Data:** Same frozen **64 fabricated authentication events** across **nine scenarios**.  
**Observed:** **5/5 rows match the unchanged independent expected findings**.  
**Qualification:** `STAGE_B2_RESULT_SCREENSHOT_MATCH_5_OF_5` — the user says this followed the [corrected in-memory SPL](SPLUNK_MATRIX_BOUNDARY_RETEST.spl).

## Results visible in the screenshot

| Timestamp (UTC) | Username | Source IP | Scenario | Failures | Fixture events | Scenario count |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 2026-10-05T09:05:00Z | `user_threshold` | `192.0.2.10` | `threshold` | 5 | 64 | 9 |
| 2026-10-05T10:39:00Z | `user_reset` | `192.0.2.13` | `post_success_burst` | 5 | 64 | 9 |
| 2026-10-05T13:10:00Z | `user_boundary` | `203.0.113.10` | `ten_minute_boundary` | 5 | 64 | 9 |
| 2026-10-05T13:40:00Z | `user_alpha` | `203.0.113.20` | `interleaved_users` | 5 | 64 | 9 |
| 2026-10-05T13:41:00Z | `user_beta` | `203.0.113.21` | `interleaved_users` | 5 | 64 | 9 |

**Exact match:** 5 of 5 independently frozen expected rows; no unexpected row in the pictured Statistics table. The two formerly missing ten-minute boundary detections now appear.

## What this evidence supports

- The screenshot shows the expected **five-row synthetic 64-event Splunk search result**.
- The result is consistent with the explicit-inclusive timestamp correction, after the original [three-of-five failure](SPLUNK_MATRIX_FIRST_RUN_2026-10-23.md).
- The example demonstrates using SPL in a real application, confronting a boundary-case mismatch and verifying a corrected result *at the table-output level*.

## Evidence and scope limits

The image provided in chat is **a cropped Statistics table**. It does **not show the search query, job SID, Splunk version, search execution controls, or independent results export**. The image is reviewed in the conversation but **not committed as a public screenshot**. Attribution of these rows to the corrected query relies on the user's surrounding test context, not independently authenticated search-job provenance.

This is **not** indexed-CSV validation, proof of production-ready SPL or any security incident. The corrective `list()` solution is suited to the bounded 64-row demonstration and subject to Splunk's list/streaming limits; avoid declaring it suitable for unlimited production workloads.

**Final portfolio disposition:** `SYNTHETIC_SPLUNK_MATRIX_SCREENSHOT_MATCH_5_OF_5`. Further ingestion or export work is **optional** and not necessary to present this accurately as a reproducible synthetic search and debugging demonstration. No fabricated results or real-world incident claims.
