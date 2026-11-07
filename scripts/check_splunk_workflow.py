"""Inspect unexecuted Splunk app artifacts against the canonical auth fixture.

Static tests only. They do not test actual Splunk ingestion, dashboard UI,
alert firing, or arbitrary production log correctness.
"""
from __future__ import annotations

import configparser
import csv
from io import StringIO
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "splunk_app/don_lopez_soc"
WORK = ROOT / "splunk_workflow"
SOURCE = ROOT / "projects/01-authentication-detection"


def require(ok: bool, msg: str):
    if not ok:
        raise AssertionError(msg)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main():
    source = read(SOURCE / "validation_events.csv")
    copied = read(APP / "lookups/portfolio_auth_validation.csv")
    require(copied == source, "Packaged lookup diverges from 64-event validation fixture")
    rows = list(csv.DictReader(StringIO(source)))
    require(len(rows) == 64 and len({r["scenario"] for r in rows}) == 9,
            "Auth fixture count/scenarios unexpectedly changed")
    conf = configparser.ConfigParser(interpolation=None)
    conf.read_string(read(APP / "default/savedsearches.conf"))
    require(len(conf.sections()) == 1, "Unexpected alert definitions")
    alert = conf[conf.sections()[0]]
    require(alert.get("disabled") == "1" and alert.get("enablesched") == "0",
            "No automatic alert action or scheduling is permitted")
    require(alert.get("counttype") == "number of events"
            and alert.get("relation") == "greater than"
            and alert.get("quantity") == "0",
            "Alert threshold must be number of events greater than zero")
    require(alert.get("action.email") == "0" and alert.get("action.script") == "0",
            "External alert actions must be off")
    require(alert.get("dispatch.earliest_time") == "-20m",
            "Alert lookback requires a 20-minute source window")
    require('index=lab_auth sourcetype="portfolio:auth"' in alert["search"],
            "Alert may only use isolated synthetic lab index")
    require("relative_time(now(),\"-5m\")" in alert["search"],
            "Alert must filter candidate successes to last five minutes")

    search_files = sorted((WORK / "searches").glob("*.spl"))
    require(len(search_files) == 9, "Expected nine documented SPL searches")
    for p in search_files:
        content = read(p)
        require("index=*" not in content and "| delete" not in content,
                f"Unsafe broad search or destructive command in {p.name}")

    demo = APP / "default/data/ui/views/auth_triage_demo.xml"
    indexed = APP / "default/data/ui/views/auth_triage_indexed.xml"
    for path, selector in (
        (demo, "| inputlookup portfolio_auth_validation.csv"),
        (indexed, 'index=lab_auth sourcetype="portfolio:auth"'),
    ):
        root = ET.fromstring(read(path))
        require(root.tag == "dashboard", "Classic dashboard root must be dashboard")
        panels = root.findall(".//panel")
        queries = [q.text or "" for q in root.findall(".//search/query")]
        require(len(panels) == 6 and len(queries) == 6,
                f"{path.name}: expected six analysis panels")
        require(all(q.lstrip().startswith(selector) for q in queries),
                f"{path.name}: wrong data source in dashboard search")
        require(all(x.find("earliest") is not None for x in root.findall(".//search")),
                f"{path.name}: expected explicit historical search coverage")
        detections = [q for q in queries if "prior_failure_times" in q]
        require(len(detections) == 1, "Dashboard must contain exactly one detection table")
        require("age_seconds<=600" in detections[0] and "list(failure_epoch)" in detections[0],
                "Dashboard must use inclusive-boundary rule from corrected matrix")
        require("time_window=10m" not in detections[0],
                "Observed boundary-bug query must not ship in dashboard")

    # Verify no-app dashboard uses exactly the same synthetic CSV,
    # and no app installation, lookup, or index is necessary.
    standalone = read(WORK / "NO_APP_DASHBOARD.xml")
    root_no_app = ET.fromstring(standalone)
    require(root_no_app.tag == "dashboard", "Standalone dashboard XML invalid")
    base_nodes = root_no_app.findall("./search")
    require(len(base_nodes) == 1 and base_nodes[0].get("id") == "source_events",
            "Exactly one inline fixture search is required")
    base_query = base_nodes[0].findtext("query") or ""
    marker = 'fixture_rows="'
    require(marker in base_query, "Missing inline fixture data")
    actual_payload = base_query.split(marker, 1)[1].split('"', 1)[0]
    fields = ("timestamp", "username", "source_ip", "host", "event_type", "scenario")
    expected_payload = ";".join("|".join(row[key] for key in fields) for row in rows)
    require(actual_payload == expected_payload,
            "Inline fixture does not match canonical 64-event source")
    require("| table _time timestamp username source_ip host event_type scenario" in base_query,
            "Base search must retain required fields as a table")
    require(base_nodes[0].findtext("earliest") == "0",
            "Base search must permit historical test timestamps")
    panels = root_no_app.findall(".//panel")
    searches = root_no_app.findall(".//panel//search")
    require(len(panels) == 6 and len(searches) == 6,
            "Expected six standalone dashboard panels")
    require(all(s.get("base") == "source_events" for s in searches),
            "Every panel must use the same inline base search")
    queries = [s.findtext("query") or "" for s in searches]
    detections = [q for q in queries if "prior_failure_times" in q]
    require(len(detections) == 1 and "age_seconds<=600" in detections[0],
            "Standalone detector must count the inclusive 600-second boundary")
    require(not any("inputlookup" in q or "index=lab_auth" in q for q in queries)
            and "inputlookup" not in base_query and "index=lab_auth" not in base_query,
            "No-app dashboard must not depend on lookup or index")
    guide = read(WORK / "NO_APP_GUIDE.md")
    require("Save As" in guide and "Search & Reporting" in guide,
            "Guide must document native Dashboard Panel path")
    nav = ET.fromstring(read(APP / "default/data/ui/nav/default.xml"))
    names = [x.get("name") for x in nav.findall("view")]
    require(names == ["auth_triage_demo", "auth_triage_indexed"],
            "Navigation must not reference nonexistent built-in app views")
    require(nav.find("view").get("default") == "true",
            "First valid installed dashboard must be the app home")
    require(not nav.attrib.get("search_view"),
            "Do not redirect search view to a page unavailable in this custom app")
    for name in names:
        require((APP / ("default/data/ui/views/" + name + ".xml")).is_file(),
                f"App navigation references non-packaged view: {name}")
    meta_file = read(APP / "metadata/default.meta")
    require("[views]" in meta_file and "[lookups]" in meta_file
            and "access = read : [ * ], write : [ admin ]" in meta_file,
            "Package must include explicit public-safe view/lookup permissions")
    app_config = configparser.ConfigParser(interpolation=None)
    app_config.read_string(read(APP / "default/app.conf"))
    require(app_config["launcher"]["version"] == "1.0.1"
            and app_config["install"]["build"] == "2",
            "App version/build must change for updated navigation release")
    for filename in ("07_indexed_auth_detection.spl", "06_lookup_auth_detection.spl"):
        q = read(WORK / "searches" / filename)
        require("age_seconds<=600" in q and "time_window=10m" not in q,
                f"{filename}: wrong boundary predicate")

    print("PASS: 64-row lookup custody, nine searches, two 6-panel XML dashboards, disabled alert")
    print("LIMIT: source/package check; does NOT claim real Splunk runtime execution")


if __name__ == "__main__":
    main()
