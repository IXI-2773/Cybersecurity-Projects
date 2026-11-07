# Splunk 404 Workaround — Native Dashboard (No App Installation)

**Use this instead of upgrading the custom `don_lopez_soc` app.** The user has already executed searches successfully in **Splunk Enterprise Search & Reporting**. An app routing problem should not block portfolio progress.

## Fastest route: one validated results panel

1. Open Splunk **Search & Reporting**, where the corrected 64-event authentication search has already worked.
2. Open the previously successful [corrected 64-event search](../projects/01-authentication-detection/SPLUNK_MATRIX_BOUNDARY_RETEST.spl) (or use its saved query), select **All time** and run it.
3. Open **Statistics**, then click **Save As → Dashboard Panel**.
4. Select **New Dashboard**; name it **Don Lopez — SOC Authentication Investigation**. If prompted for framework, select **Classic / Simple XML**.
5. Save the results as a **table**. The dashboard belongs to the normal **Search & Reporting** app. **No custom app package, restart, indexed data, or API is needed.**

**Observed October 23, 2026:** The native Search & Reporting dashboard titled **Don Lopez — SOC Authentication Investigation** opened and showed all five synthetic detection rows in an operator screenshot. [Result review and limitations](NATIVE_DASHBOARD_RESULT_2026-10-23.md). The image itself is not in the public repository.

## One-paste route: complete six-panel classic dashboard

[Download or copy the raw standalone dashboard XML](NO_APP_DASHBOARD.xml). It contains the complete fabricated 64-event corpus directly in an inline `makeresults` base search plus six post-process panels. It does **not** call `inputlookup`, `index=lab_auth` or `don_lopez_soc`.

1. Open **Search & Reporting → Dashboards → Create New Dashboard** (or navigate to Dashboards and choose Create New Dashboard).
2. Name it **Don Lopez | SOC Authentication — No-App Lab**. Choose **Classic Dashboards / Simple XML** (not Dashboard Studio), with **Private** permissions initially, then create.
3. Click **Edit → Source** (or **Edit Source**, depending on version); replace the dashboard's XML with the full contents of [`NO_APP_DASHBOARD.xml`](NO_APP_DASHBOARD.xml). Save.
4. Reload from the **Dashboards** list in Search & Reporting—not the previously broken custom app URL. All data are generated in memory.
5. Look for **64 total events**, **nine scenario families**, and **five synthetic candidates**. The timeline, source-IP table and full event table are additional panels. These are expected, **not yet observed for this new dashboard**.

If Splunk does not offer Classic Simple XML, use the **Fastest route** above instead. A Dashboard Studio source editor accepts **JSON**, not this XML.

### Why this avoids the 404

Splunk dashboards belong to an app context. The broken custom app's menu and dashboard registration are bypassed by saving the dashboard in the **working Search & Reporting context**. No custom app install, upgraded package, lookup permission, or standalone web server is required.

### Technical design and limitations

- The inline base search generates exactly the [64 frozen CSV records](../projects/01-authentication-detection/validation_events.csv) and retains `_time`, identity, source and event-type fields using a final `table` command.
- Splunk supports Classic Simple XML shared base/post-process searches with `<search id="source_events">` and `<search base="source_events">`. One base search supplies all six panels.
- Detection uses the same **0–600 second inclusive** bounded calculation that was consistent with five rows in the user-provided Splunk Statistics screenshot.
- The Splunk `list()` aggregation is capped; this fixture-sized example is not a production-scale correlation rule.
- The dashboard is entirely synthetic. It demonstrates investigation flow, not actual enterprise telemetry, malware identification or incident response.

### If the UI still fails

First test the one-panel Save As workflow, which avoids XML entirely. If that works but pasting XML fails, capture the source editor error. If even a saved panel fails to open under Search & Reporting, investigate **view permissions and Dashboard menu access** in that standard app, rather than reinstalling `don_lopez_soc`.

**Status:** **One-panel native dashboard screenshot-reviewed PASS (5/5)**. The separate **six-panel Classic XML** has not been shown running; it remains prepared only.
