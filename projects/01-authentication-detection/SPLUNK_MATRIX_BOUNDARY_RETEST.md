# Stage B2 — Splunk Boundary-Corrected Retest (Screenshot-Reviewed 5/5)

**Owner:** Don Lopez · **Fixture:** Same frozen 64 synthetic events, nine scenarios, five expected matches

**Update, October 23, 2026:** [The operator-provided results screenshot matches all five expected rows](SPLUNK_MATRIX_BOUNDARY_RETEST_RESULT_2026-10-23.md). The cropped screenshot does not show the SPL query or SID, so this is a screenshot-reviewed result, not independently authenticated job provenance.  
**Reason:** On October 23, 2026, the original Stage B `streamstats time_window=10m` query actually returned **3 findings instead of 5** in Splunk Enterprise.

## Real first-run observation

| Case | Original Splunk result | Frozen expectation |
| --- | --- | --- |
| `threshold`, 09:05 UTC | 5 failures, present | Present |
| `post_success_burst`, 10:39 UTC | 5 failures, present | Present |
| `ten_minute_boundary`, 13:10 UTC | **Missing** | Present |
| `interleaved_users / user_alpha`, 13:40 UTC | **Missing** | Present |
| `interleaved_users / user_beta`, 13:41 UTC | 5 failures, present | Present |

The screenshot shows `fixture_event_count=64`, `fixture_scenario_count=9` on all three returned rows; it shows no Splunk error. The image was received in conversation and reviewed but is **not included as a public repository image**.

## Root-cause hypothesis

Both missing results depend on counting a failure **exactly 600 seconds before the success event**. The Python oracle treats the time window as *inclusive*, whereas the original `streamstats time_window=10m` result behaves as though that earliest event is outside the window. This is a **strongly supported boundary-behavior diagnosis**, not yet a completed Splunk command-level proof; the retest below will challenge it.

The frozen [64-row source](validation_events.csv) and [five expected detections](expected_findings.json) remain **unchanged**. Do not change the expected count to three just to pass.

## Corrected candidate approach

[`SPLUNK_MATRIX_BOUNDARY_RETEST.spl`](SPLUNK_MATRIX_BOUNDARY_RETEST.spl) retains the exact 64 synthetic events and the same success-based streak IDs but replaces the `time_window` aggregate with **explicit epoch arithmetic**:

1. `streamstats current=f list(failure_epoch)` collects only earlier failures for each account/IP/success streak.
2. `mvmap` calculates each failure's age in seconds relative to a candidate success.
3. `mvfilter` explicitly accepts ages **0 through 600 seconds inclusive**.
4. `mvcount` counts qualifying failures and the unchanged threshold remains **at least five**.

This is a **bounded validation technique** for the 64-event corpus, **not a production-ready high-volume alert**. Splunk documents that `list()` returns at most **100 values**, while streaming statistics also have configurable memory/window limits. Scaling this approach to production requires a separate detection design and capacity testing.

## Reproduce the successful result without any upload

1. Open [the corrected SPL](SPLUNK_MATRIX_BOUNDARY_RETEST.spl) in GitHub, click **Raw**, copy all the text.
2. In Splunk **Search & Reporting**, choose **All time** and run the query.
3. In **Statistics**, check that the result has **five rows**, each with `fixture_event_count=64`, `fixture_scenario_count=9`, and `failure_count_in_window=5`.
4. Capture an authentic screenshot showing all five rows and any search diagnostics. If Splunk reports an error or still produces three findings, retain the result for further repair.

Expected and visible in the submitted Statistics screenshot: `user_threshold` 09:05, `user_reset` 10:39, `user_boundary` 13:10, `user_alpha` 13:40, and `user_beta` 13:41 (all UTC on October 5, 2026).

## Evidence classification

- Stage A seven-event search: **SCREENSHOT-REVIEWED PASS**.
- Stage B original full-matrix search: **OBSERVED 3/5 — PARITY FAIL**.
- Stage B2 explicit-boundary candidate: **5/5 RESULT SCREENSHOT-REVIEWED**; actual SPL job and SID not visible in cropped image.
- Stage C indexed CSV ingestion/export comparison: **NOT YET VERIFIED**.

There was **no real intrusion**. This is an observed discrepancy in a fabricated detector-validation exercise.

## Technical references

- [Splunk streamstats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/streamstats)
- [Splunk multivalue eval functions](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-reference/evaluation-functions/multivalue-eval-functions)
- [Splunk `list()` limits](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-reference/statistical-and-charting-functions/multivalue-and-array-functions)
