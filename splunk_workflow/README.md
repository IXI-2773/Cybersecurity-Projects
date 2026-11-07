# Splunk End-to-End SOC Authentication Lab

![Portfolio project](../assets/badges/portfolio-project.svg)

**Owner:** Don Lopez · **Source:** 64 synthetic authentication rows, nine scenarios, five expected correlation matches.

**Status:** Application/dashboard/alert package **PREPARED — installation, true CSV ingestion, dashboard rendering, and alert triggering are NOT YET VERIFIED in your Splunk Enterprise trial.** The separate original seven-event smoke search passed and the corrected 64-row in-memory SPL returned a screenshot with five expected rows; those do not validate this packaged app or indexed behavior.

## What is ready to use

The [execution evidence workflow](EXECUTION.md) now prepares a current-time six-event replay and verifies indexed events, native fired-alert job results and an analyst handoff through authenticated REST. The new verifier has offline protocol tests; **it has not run against a live Splunk instance**. Existing upload and temporary-alert configuration steps remain operator actions.

| Component | Artifact | Deployment state |
| --- | --- | --- |
| Self-contained demo | [Splunk app source](../splunk_app/don_lopez_soc/) + lookup `portfolio_auth_validation.csv` | Prepared; independent of index and ingest |
| SOC dashboard — demo | `auth_triage_demo` Simple XML page | Not run in your instance |
| SOC dashboard — indexed | `auth_triage_indexed` Simple XML page | Requires actual authorized CSV ingestion |
| Nine focused searches | [SPL search files](searches/) | Not yet run as this package |
| Saved alert | Disabled `Portfolio SOC Auth Candidate - Indexed (DISABLED)` | Disabled; no automatic action |
| Installation package | Original portfolio CI artifact `don-lopez-splunk-soc-app`, or local `scripts/build_splunk_app.py` output | Source/build verification only |

## Preferred workaround if the installed app opens a 404

**Stop upgrading the custom app.** Instead follow [No-App Dashboard Guide](NO_APP_GUIDE.md). The reliable path is to run the **already successful 64-event SPL in Search & Reporting**, then use **Save As → Dashboard Panel**. This creates a real native Splunk dashboard without `don_lopez_soc` app routing, file uploads, indexes or installation.

For all six panels in one paste, use [self-contained Classic Simple XML](NO_APP_DASHBOARD.xml), which embeds the 64 fabricated events and runs in your normal Search & Reporting app. No custom lookup or installed app is involved.

**Execution status:** The native one-panel Search & Reporting dashboard now has a [real operator screenshot showing 5/5 synthetic findings](NATIVE_DASHBOARD_RESULT_2026-10-23.md). The six-panel Classic XML and custom-app dashboards remain unverified.

## Resolving a Splunk 404 after installation

On October 23, 2026, an operator submitted a Splunk Enterprise **404 Not Found** screenshot after attempting the earlier v1.0.0 package. The screenshot did not show the request URL or app-install status. Thus, it is **not possible to prove the exact root cause** from that image. The following are defensible troubleshooting actions.

The **v1.0.1 repair package** now:
- removes navigation entries (`search`, `reports`) that had no view definitions in this custom application;
- marks the bundled `auth_triage_demo` dashboard as the **only default landing view**;
- adds `metadata/default.meta` granting app-scoped read access to its dashboard and synthetic lookup;
- checks every navigation entry corresponds to an actual packaged XML view, and increments version/build.

**Direct URL to try first (for local Splunk Enterprise):**

```text
http://localhost:8000/en-US/app/don_lopez_soc/auth_triage_demo
```

If the direct link works, the old app menu or cached navigation was likely the problem. If it still shows 404:

1. **Settings → Apps → Manage Apps**: confirm `don_lopez_soc` exists, is enabled, and shows version **1.0.1** after update. If it is absent, the package did not install.
2. From the [original portfolio Actions](https://github.com/IXI-2773/Cybersecurity_Portfolio/actions), download `don-lopez-splunk-soc-app` from a **successful run containing app version 1.0.1**, extract the `.spl` archive, and install with **Upgrade app** checked **only when updating this same `don_lopez_soc` app**. Never replace an unrelated app.
3. After install/upgrade, follow Splunk's restart prompt. If Splunk has not refreshed its new views, an authorized administrator can use **Settings → Server controls → Restart Splunk** (this temporarily interrupts the local trial). After it starts, sign in again and hard-refresh the browser. A Splunk documentation example also uses `http://localhost:8000/debug/refresh` to refresh app navigation; use only on your own local instance.
4. **Settings → User Interface → Views**, choose the Don Lopez app, and verify `auth_triage_demo` and `auth_triage_indexed` exist and have view permissions. Do not create or modify production app roles.
5. If the view exists but is inaccessible, check **Settings → User Interface → Navigation Menus** in the same app. Its XML must point to `auth_triage_demo` (default) and `auth_triage_indexed`, not missing `search` or `reports`.
6. If the direct URL still 404s, preserve the **browser address-bar URL** and the selected app/version rather than guessing. Do not share tokens, passwords, or internal logs.

**No dashboard runtime success is claimed.** Source/package checks and static XML tests cannot prove a deployed view loads.

## Fastest path: deploy the demo dashboard without an index

1. In [GitHub Actions](https://github.com/IXI-2773/Cybersecurity_Portfolio/actions), open a **successful Validate public portfolio** run. Under Artifacts download `don-lopez-splunk-soc-app` and extract its ZIP wrapper.
2. Find the `don_lopez_soc.spl` file (version **1.0.1**). In Splunk Enterprise as an authorized administrator, open **Apps → Manage Apps → Install app from file**, select the `.spl` archive, and follow any restart instructions. Review the package source first; it contains only CSV, dashboard XML, and a **disabled** saved search. Do not upload secrets.
3. Open **Don Lopez | SOC Authentication Lab** → **SOC Authentication | Bundled Synthetic Demo**. This reads the app's lookup with `inputlookup`, not indexed events.
4. Expected: 64 events, nine scenario labels, two counts/charts/tables, and five candidate detections under the inclusive 600-second rule. Take actual Splunk screenshots **only after viewing these results**.
5. If the dashboard shows a missing lookup warning, verify installation and app context. Do not claim a successful dashboard until observed.

## Next: genuine CSV indexing and investigation

Follow [the ingestion guide](INGESTION.md), which uses the original fixture in a **separate isolated test index** with CSV field extraction, UTC timestamp verification, no duplicates, and explicit checks. The indexed dashboard will remain empty until ingestion works.

## Controlled alert demonstration

Follow [the alert runbook](ALERTING.md). The bundled alert is *disabled* and does not email, send webhooks, run scripts, or isolate hosts. The alert preview can be tested manually; **historical 2026-10-05 data will not trigger a live last-five-minutes alert on today's date**. Creating a controlled alert with current fabricated events is a separate authorized operation and has not been performed.

## Limits

- No real identity provider, user credentials, or operational telemetry.
- The bounded demonstration detector uses `streamstats list()` and explicit inclusive time arithmetic; Splunk's multivalue list cap makes it **unsuitable as a general high-volume production correlation rule** without redesign.
- Dashboard XML is syntactically checked in CI but still requires actual Splunk renderer/runtime verification.
- Neither a passing code test nor installation alone establishes an actual incident, live alert, or production effectiveness.

See [verification checklist](VALIDATION_CHECKLIST.md).
