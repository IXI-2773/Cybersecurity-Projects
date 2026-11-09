# Splunk End-to-End SOC Authentication Lab

![Portfolio project](../assets/badges/portfolio-project.svg)

**Owner:** Don Lopez · **Source:** 64 original synthetic authentication rows, nine scenarios, five expected correlation matches; a separate current-time replay adds six synthetic rows.

**Packaged-app status:** Custom-app installation, its dashboard rendering, and its bundled saved-alert execution remain **UNVERIFIED**. The older seven-event smoke search and 64-row in-memory screenshot exercise are separate from package validation.

**Separate live confirmation — November 8, 2026:** An authorized standalone synthetic lab indexed exactly **70 source-equal events** (64 original plus six fresh), matched all **five** original expected findings without extras from the supplied negative fixtures, and retained **one native tracked scheduled alert** and its exact job result before disabling the temporary schedule. See the [source-bound confirmation](LIVE_CONFIRMATION_2026-11-08.md) and [employer-facing investigation draft](EMPLOYER_SOC_CASE_STUDY_DRAFT.md). This is not a real incident or proof of the packaged app's runtime.

## What is ready to use

The [execution evidence workflow](EXECUTION.md) prepares a six-event replay and checks indexed rows, the actual fired-alert job and an analyst handoff. Its **HTTPS bearer-token verifier was not the entrypoint used for the November live result**: that run used an existing authenticated local Splunk CLI context, with hostname validation disabled in its unchanged configuration. The separate token-based path retains offline protocol tests. Uploading and configuring a temporary alert remain manual authorized lab steps.

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

## Indexed CSV investigation

Follow [the ingestion guide](INGESTION.md) for a separate isolated index, CSV field extraction and UTC timestamp checks. The November 8 standalone run confirmed 70 correctly indexed synthetic events. **The packaged indexed dashboard itself still lacks observed runtime rendering**; verified indexing does not establish its UI behavior.

## Controlled alert demonstration

Follow [the alert runbook](ALERTING.md). The bundled alert is *disabled* and does not email, send webhooks, run scripts, or isolate hosts. Historical 2026-10-05 data cannot trigger a current five-minute alert. A **separate temporary native alert** was successfully confirmed using six current-time fabricated events on November 8; its exact job and tracked fired-alert record were retained before the schedule was disabled. No external actions were enabled. See the [bounded result](LIVE_CONFIRMATION_2026-11-08.md).

## Limits

- No real identity provider, user credentials, or operational telemetry.
- The bounded demonstration detector uses `streamstats list()` and explicit inclusive time arithmetic; Splunk's multivalue list cap makes it **unsuitable as a general high-volume production correlation rule** without redesign.
- Dashboard XML is syntactically checked in CI but still requires actual Splunk renderer/runtime verification.
- Neither a passing code test nor installation alone establishes an actual incident, live alert, or production effectiveness.

See [verification checklist](VALIDATION_CHECKLIST.md).
