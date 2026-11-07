"""Render existing offline firewall-review findings without changing their meaning."""

import csv
from html import escape
from io import StringIO


CSV_FIELDS = ("policy", "rule_count", "rule_id", "severity", "code", "detail",
              "prior_rule_ids", "overlap_example", "scope")
JSON_SCOPE = "Illustrative JSON policy; rule order and real reachability not evaluated"


def _prior_ids(finding):
    return "; ".join(finding.get("covering_rule_ids")
                     or finding.get("overlapping_rule_ids") or [])


def _overlap_example(finding):
    example = finding.get("overlap_example")
    if not example:
        return ""
    service = example["protocol"]
    if example["port"] is not None:
        service += f"/{example['port']}"
    return f"{example['source']} → {example['destination']} ({service})"


def _safe_csv_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def render_csv(report):
    """Emit one spreadsheet-safe row per review finding, with report context."""
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for finding in report["findings"]:
        values = {
            "policy": report["policy"],
            "rule_count": report["rule_count"],
            "rule_id": finding["rule_id"],
            "severity": finding["severity"],
            "code": finding["code"],
            "detail": finding["detail"],
            "prior_rule_ids": _prior_ids(finding),
            "overlap_example": _overlap_example(finding),
            "scope": report.get("scope", JSON_SCOPE),
        }
        writer.writerow({key: _safe_csv_cell(value) for key, value in values.items()})
    return output.getvalue()


def render_html(report):
    """Produce a standalone, escaped HTML report suitable for offline viewing."""
    h = lambda value: escape(str(value), quote=True)
    rows = []
    for finding in report["findings"]:
        severity = finding["severity"]
        severity_class = {"CRITICAL": "critical", "HIGH": "high", "INFO": "info"}.get(
            severity, "other")
        prior = _prior_ids(finding) or "—"
        evidence = _overlap_example(finding) or "—"
        rows.append(
            f'<tr><td><span class="badge {severity_class}">{h(severity)}</span></td>'
            f'<td class="mono">{h(finding["rule_id"] or "—")}</td>'
            f'<td class="mono">{h(finding["code"])}</td>'
            f'<td>{h(finding["detail"])}</td>'
            f'<td class="mono">{h(prior)}</td><td class="mono">{h(evidence)}</td></tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="6">No modeled findings; this is not a security certification.</td></tr>')
    return "\n".join([
        "<!doctype html>",
        '<html lang="en">',
        '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>Firewall Policy Review</title>',
        "<style>",
        ":root{color-scheme:light}body{margin:0;background:#f3f6fb;color:#15263e;font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}",
        "main{max-width:1180px;margin:40px auto;padding:0 24px}header{background:#132b49;color:#fff;border-radius:12px;padding:28px 32px}",
        "h1{font-size:28px;margin:3px 0 8px}.kicker{color:#a5d4ef;letter-spacing:.12em;font-size:12px;text-transform:uppercase}",
        "header p{margin:0;color:#d7e5f2}.summary{display:flex;gap:14px;margin:18px 0}",
        ".metric{background:#fff;border:1px solid #dce5f0;border-radius:10px;padding:13px 18px;min-width:130px}",
        ".metric strong{font-size:24px;display:block}.metric span{font-size:12px;color:#51667f}",
        "section{background:#fff;border:1px solid #dce5f0;border-radius:10px;overflow-x:auto}",
        "table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:13px 12px;border-bottom:1px solid #e9edf3;vertical-align:top}",
        "th{background:#eaf0f7;color:#294563;font-size:12px;text-transform:uppercase;letter-spacing:.035em}",
        "td{overflow-wrap:anywhere}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}",
        ".badge{border-radius:5px;padding:4px 8px;font-weight:700;font-size:11px}.critical{background:#fce4e4;color:#921d1d}",
        ".high{background:#fff0d9;color:#824700}.info{background:#e2f1fe;color:#1e547f}",
        ".notice{margin:18px 0 8px;color:#495f78}footer{color:#5f7185;font-size:12px;margin:22px 0 40px}",
        "</style></head>",
        "<body><main>",
        '<header><div class="kicker">Offline defensive configuration review</div>',
        f'<h1>Firewall Policy Review</h1><p>Policy: {h(report["policy"])}</p></header>',
        '<div class="summary">',
        f'<div class="metric"><strong>{h(report["rule_count"])}</strong><span>Rules reviewed</span></div>',
        f'<div class="metric"><strong>{len(report["findings"])}</strong><span>Review findings</span></div>',
        '</div><section><table><thead><tr><th>Priority</th><th>Rule</th><th>Finding</th>',
        '<th>Review guidance</th><th>Earlier rules</th><th>Overlap example</th></tr></thead><tbody>',
        *rows,
        '</tbody></table></section>',
        f'<p class="notice"><strong>Scope:</strong> {h(report.get("scope", JSON_SCOPE))}</p>',
        '<footer>Offline static review candidates only; not a confirmed vulnerability, '
        'live exposure measurement, or recommendation to remove rules automatically.</footer>',
        '</main></body></html>',
        "",
    ])
