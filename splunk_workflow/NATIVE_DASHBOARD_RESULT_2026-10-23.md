# Native Splunk Dashboard — Screenshot-Reviewed Result

**Date reviewed:** October 23, 2026  
**Application:** Splunk Enterprise / Search & Reporting  
**Dashboard title:** `Don Lopez — SOC Authentication Investigation`  
**Classification:** `ONE_PANEL_NATIVE_DASHBOARD_VERIFIED_BY_SCREENSHOT`

## Actual result shown by the operator

The screenshot shows the Splunk Enterprise interface, working Search & Reporting navigation, the dashboard title and a saved populated table. All **5 of 5 frozen expected synthetic findings** appear:

| Timestamp (UTC) | Username | Source IP | Scenario | Failures | Fixture count | Scenarios |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 2026-10-05T09:05:00Z | `user_threshold` | `192.0.2.10` | `threshold` | 5 | 64 | 9 |
| 2026-10-05T10:39:00Z | `user_reset` | `192.0.2.13` | `post_success_burst` | 5 | 64 | 9 |
| 2026-10-05T13:10:00Z | `user_boundary` | `203.0.113.10` | `ten_minute_boundary` | 5 | 64 | 9 |
| 2026-10-05T13:40:00Z | `user_alpha` | `203.0.113.20` | `interleaved_users` | 5 | 64 | 9 |
| 2026-10-05T13:41:00Z | `user_beta` | `203.0.113.21` | `interleaved_users` | 5 | 64 | 9 |

These include the two exact ten-minute boundary findings absent from the original 3/5 query, consistent with the [corrected synthetic SPL](../projects/01-authentication-detection/SPLUNK_MATRIX_BOUNDARY_RETEST.spl).

## What is and is not established

**Established by screenshot:** A native one-panel Splunk dashboard was saved, opened successfully in Search & Reporting, and displayed a table matching all five artificial findings. This bypasses the installed custom application's prior 404.

**Publication:** A [cropped and resized derivative of the actual operator-provided screenshot](../assets/evidence/splunk-native-dashboard-results.png) is now publicly archived. The original full-resolution capture remains in the project conversation. This derivative is a real screen capture, **not an AI-generated or recreated Splunk interface**.

**Not established:** The source query and search SID are not visible in the cropped screenshot. The separate six-panel Classic XML dashboard has not been shown rendering. Likewise, there is no verified indexed CSV ingest, scheduled alert firing, real attack, production telemetry, or SOC deployment.

**Disposition:** `ONE_PANEL_NATIVE_DASHBOARD_VERIFIED_BY_SCREENSHOT`. It is credible synthetic Splunk application evidence with bounded proof. Further work is optional.
