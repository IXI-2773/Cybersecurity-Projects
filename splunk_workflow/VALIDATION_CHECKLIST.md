# Splunk Evidence Admission Checklist

Only change status based on genuine Splunk screenshots, exports or verified job metadata.

The [execution verifier](EXECUTION.md) can prepare a fresh replay, collect authenticated search/job evidence, compare indexed UTC/row parity and an actual fired-alert result, and generate a handoff. Its offline tests are implemented; **live execution remains pending**. A generated replay or passing protocol test does not advance any execution milestone below.

| Milestone | Prepared artifacts | Execution evidence | Allowed claim |
| --- | --- | --- | --- |
| Previous 7-event SPL smoke | Query | Screenshot-reviewed 1/1 | Small synthetic SPL smoke passed |
| Previous 64-event SPL matrix | Query and five-row oracle | Initial screenshot 3/5; cropped corrected results 5/5 | Bounded screenshot consistency; job provenance unverified |
| Source-derived website trend charts and hypothetical alert | [Synthetic preview](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/splunk-synthetic-preview.html) | Generated from 64 fabricated records (not a Splunk screenshot) | Clearly labeled visual aid only, **not** alert triggering or SIEM monitoring |
| Native Search & Reporting dashboard table | [No-app guide](NO_APP_GUIDE.md) | [Operator screenshot review: 5/5](NATIVE_DASHBOARD_RESULT_2026-10-23.md) | One panel rendered successfully; query and SID not visible |
| Standalone six-panel Classic XML dashboard | [No-app XML](NO_APP_DASHBOARD.xml) | **Not yet executed** | Prepared only |
| Bundled CSV lookup dashboard | Splunk app, CSV, Simple XML | **Not yet executed** | App source prepared; not demo runtime success |
| Indexed CSV investigation | Upload guide, dashboard and SPL | **Not yet executed** | Prepared only |
| Alert configuration | Disabled saved search, preview, guide | **Not yet executed** | Disabled definition prepared only |
| Actual scheduled trigger / throttle | Guide | **Not yet executed** | No trigger claim |

**Release rules:** Never fabricate screenshots, real incident timelines, job identifiers, triggered alert logs or ingestion results. Treat browser-rendered portfolio charts as presentation, not proof Splunk ran.

## Operational completion criteria (optional)

- Lookup demonstration: 64 records, nine scenarios, five findings visible in a real Splunk dashboard.
- Indexed data: 64 raw events, correct fields/UTC times, five original oracle findings from indexed search, documented index and source metadata.
- Alert: harmless synthetic-only trigger, specified schedule, observable triggered-alert event, suppression behavior and no unauthorized external actions.

## Native fallback — 404 bypass

[No-App Dashboard Guide](NO_APP_GUIDE.md) and [single-source Classic XML](NO_APP_DASHBOARD.xml) are prepared as the preferred alternative to installing a custom Splunk application. They require no index, lookup or package upgrade. The prior Statistics screenshot and a [new actual native dashboard screenshot](NATIVE_DASHBOARD_RESULT_2026-10-23.md) now confirm the **one-panel** results table. The six-panel XML remains unverified.

## App navigation regression — observed 404

A Splunk Enterprise 404 image was provided after the first v1.0.0 package, but the URL was not visible. The **1.0.1** package removes unresolved navigation targets, adds app/view/lookup metadata, and increments the build. A native Search & Reporting dashboard is screenshot-verified. The original custom-app 404 is bypassed, **not independently proven repaired**. See [404 diagnostics](README.md#resolving-a-splunk-404-after-installation).
