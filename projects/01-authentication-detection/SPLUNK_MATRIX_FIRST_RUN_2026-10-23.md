# Splunk Stage B — First 64-Event In-Memory Execution

**Date:** October 23, 2026  
**Classification:** Operator-supplied genuine Splunk Enterprise screenshot; fabricated data  
**Result:** **3/5 expected detections returned — validation NOT PASSED**

## Visible evidence

The Search & Reporting screenshot shows the [unmodified original full-matrix query](SPLUNK_MATRIX_IN_MEMORY.spl), a green completed search, **All time**, **Statistics (3)**, and these three rows:

| UTC timestamp | Username | Source IP | Scenario | Failure count | Fixture events | Scenarios |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 2026-10-05T09:05:00Z | user_threshold | 192.0.2.10 | threshold | 5 | 64 | 9 |
| 2026-10-05T10:39:00Z | user_reset | 192.0.2.13 | post_success_burst | 5 | 64 | 9 |
| 2026-10-05T13:41:00Z | user_beta | 203.0.113.21 | interleaved_users | 5 | 64 | 9 |

**Missing compared with unchanged independent oracle:** `user_boundary` at 13:10 and `user_alpha` at 13:40, both with five failures whose earliest failure is exactly ten minutes before success.

## Finding and next control

The common missing-case condition suggests an **exclusive left edge** in this particular Splunk `streamstats time_window=10m` evaluation. The Python reference explicitly includes the ten-minute boundary. This interpretation remains a diagnosis until an independently executed comparison confirms a boundary-aware replacement.

A revised, **not yet executed** [explicit inclusive-window retest](SPLUNK_MATRIX_BOUNDARY_RETEST.spl) is prepared with the [technical design and limitations](SPLUNK_MATRIX_BOUNDARY_RETEST.md).

## Provenance limitations

The screenshot is supplied and visually examined in the conversation; it is **not preserved as a public image in this repository**. Search SID, exact Splunk version, query export, and authenticated raw/diagnostic output are unavailable. The screenshot verifies an application result but not its back-end job provenance.

**Disposition at first run:** `REAL_SPLUNK_MATRIX_PARITY_FAIL_3_OF_5`. The original search remained incorrect. **Later update:** [the boundary-corrected Stage B2 result screenshot shows 5/5 expected rows](SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md). This preserves the original failure as a regression example without rewriting history.
