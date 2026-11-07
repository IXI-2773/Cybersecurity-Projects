"""Offline CSV/JSON triage. No network, command execution or response actions.

Run from a clone of this repository; process patterns reuse process_triage.py.
Exit 0: complete scoped processing; 2: partial, rejected rows retained; 1: fatal.
"""
from collections import defaultdict
import argparse
import csv
from datetime import datetime, timezone
import hashlib
from html import escape
import io
from ipaddress import ip_address
import itertools
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PROCESS_SOURCE = HERE.parent / '02-windows-process-triage/process_triage.py'
ALIASES = {
    'timestamp': ('timestamp', 'time', 'TimeCreated'),
    'username': ('username', 'user', 'User'),
    'host': ('host', 'computer', 'Computer'),
    'source_ip': ('source_ip', 'src_ip', 'IpAddress'),
    'event_type': ('event_type', 'action'),
    'event_uid': ('event_uid', 'record_uid'),
}
MAX_BYTES, MAX_ROWS, MAX_FILES = 5 * 1024 * 1024, 5000, 8


def digest(data):
    return hashlib.sha256(data).hexdigest()


def packed(row):
    return json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON object key')
        result[key] = value
    return result


def load(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Input exceeds 5 MiB limit')
    text = raw.decode('utf-8-sig')
    if path.suffix.lower() == '.json':
        def bad_constant(value):
            raise ValueError('Non-finite JSON number')
        rows = json.loads(text, object_pairs_hook=unique_object, parse_constant=bad_constant)
        if not isinstance(rows, list):
            raise ValueError('JSON root must be an array of event objects')
    elif path.suffix.lower() == '.csv':
        reader = csv.DictReader(io.StringIO(text, newline=''), strict=True)
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise ValueError('CSV requires unique, nonempty column names')
        if any(not key for key in reader.fieldnames):
            raise ValueError('Empty CSV header')
        rows = list(itertools.islice(reader, MAX_ROWS + 1))
    else:
        raise ValueError('Only .csv and .json exports are supported')
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError('Input must contain 1..5000 data records')
    return raw, rows


def field(row, key, required=True):
    values = []
    for alias in ALIASES.get(key, (key,)):
        value = row.get(alias)
        if value is None or value == '':
            continue
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError('Invalid text field: ' + key)
        if value.strip():
            values.append(value.strip())
    if len(set(values)) > 1:
        raise ValueError('Conflicting aliases: ' + key)
    if required and not values:
        raise ValueError('Missing required field: ' + key)
    return values[0] if values else ''


def normalize(row):
    if not isinstance(row, dict) or None in row:
        raise ValueError('Expected an object with a valid CSV field count')
    if any(value is None for value in row.values()):
        raise ValueError('Null value or missing CSV field')
    timestamp = field(row, 'timestamp')
    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    if 'T' not in timestamp or dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError('Timestamp must include an explicit timezone')
    dt = dt.astimezone(timezone.utc)
    kind = field(row, 'event_type', False)
    if not kind and str(row.get('event_id', '')) == '4688':
        kind = 'process_start'
    if kind not in {'login_failure', 'login_success', 'process_start'}:
        raise ValueError('Unsupported event_type')
    result = {'timestamp': dt.isoformat().replace('+00:00', 'Z'),
              'username': field(row, 'username'), 'host': field(row, 'host').casefold(),
              'event_type': kind, 'event_uid': field(row, 'event_uid', False)}
    address = field(row, 'source_ip', kind != 'process_start')
    parsed = ip_address(address) if address else None
    result['source_ip'] = str(getattr(parsed, 'ipv4_mapped', None) or parsed) if parsed else ''
    if kind == 'process_start':
        result.update(image=field(row, 'image'), command_line=field(row, 'command_line'),
                      parent_image=field(row, 'parent_image', False))
        pid = row.get('process_id', '')
        if pid == '':
            result['process_id'] = None
        elif isinstance(pid, bool) or not str(pid).isdigit() or int(pid) < 1:
            raise ValueError('process_id must be a positive integer when provided')
        else:
            result['process_id'] = int(pid)
    return result


def review(events):
    sys.path.insert(0, str(PROCESS_SOURCE.parent))
    from process_triage import inspect_event
    findings, groups = [], defaultdict(list)
    for row in events:
        if row['event_type'] == 'process_start':
            for match in inspect_event(row):
                findings.append({'rule_id': match['rule_id'], 'timestamp': row['timestamp'],
                                 'username': row['username'], 'host': row['host'],
                                 'reason': match['matched_behavior'], 'source_refs': row['source_refs'],
                                 'next_step': 'Validate command content, parent process and authorization; encoding alone does not establish malicious intent.'})
        else:
            groups[(row['username'], row['host'], row['source_ip'])].append(row)
    for key, rows in sorted(groups.items()):
        history = []
        ordered = sorted(rows, key=lambda r: datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00')))
        for timestamp, bucket in itertools.groupby(ordered, key=lambda r: r['timestamp']):
            bucket = list(bucket)
            now = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            history = [r for r in history if (now - datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00'))).total_seconds() <= 600]
            successes = [r for r in bucket if r['event_type'] == 'login_success']
            if successes:
                if len(history) >= 5:
                    findings.append({'rule_id': 'AUTH_FAILURES_THEN_SUCCESS', 'timestamp': timestamp,
                                     'username': key[0], 'host': key[1], 'source_ip': key[2],
                                     'reason': f'{len(history)} earlier failures within inclusive 600 seconds, then success on the same user/host/IP.',
                                     'source_refs': [ref for r in history + successes for ref in r['source_refs']],
                                     'next_step': 'Confirm account ownership, MFA context and approved activity before assigning incident severity.'})
                history = []  # Every success resets history; tied failures have unknown order.
            else:
                history.extend(bucket)
    return sorted(findings, key=lambda f: (datetime.fromisoformat(f['timestamp'].replace('Z', '+00:00')), f['rule_id'], f['source_refs'][0]))


def analyze(paths):
    if not 1 <= len(paths) <= MAX_FILES:
        raise ValueError('Provide 1..8 input exports')
    inputs, records, pending, events, notes = [], [], defaultdict(list), [], []
    rejected_ids = set()
    for file_no, supplied in enumerate(paths, 1):
        path = Path(supplied)
        raw, rows = load(path)
        source_id = f'S{file_no:02d}'
        inputs.append({'id': source_id, 'name': path.name, 'format': path.suffix.lower()[1:], 'sha256': digest(raw), 'rows': len(rows)})
        for index, row in enumerate(rows, 1):
            ref = f'{source_id}:R{index:06d}'
            preserved = ({'csv_fields': {k: v for k, v in row.items() if k is not None},
                          'extra_values': row[None]} if isinstance(row, dict) and None in row else row)
            record = {'id': ref, 'input_id': source_id, 'data_record': index,
                      'parsed_record_sha256': digest(packed(preserved).encode()), 'raw': preserved, 'status': 'accepted'}
            records.append(record)
            try:
                item = normalize(row)
            except (ValueError, TypeError, OverflowError) as exc:
                record.update(status='rejected', reason=str(exc))
                # An invalid copy must not leave a matching identified event trusted.
                if isinstance(row, dict):
                    try:
                        rejected_ids.add((field(row, 'host').casefold(), field(row, 'event_uid')))
                    except ValueError:
                        pass  # Identity is unavailable or ambiguous; keep the row rejected.
                continue
            item['source_refs'] = [ref]
            if item['event_uid']:
                pending[(item['host'], item['event_uid'])].append((item, record))
            else:
                events.append(item)
    for identity, group in pending.items():
        values = {packed({k: v for k, v in item.items() if k != 'source_refs'}) for item, _ in group}
        if len(values) != 1 or identity in rejected_ids:
            for _, record in group:
                record.update(status='rejected', reason='Conflicting or invalid copy of event_uid within host; all identifiable matching IDs quarantined')
            continue
        primary = group[0][0]
        for item, record in group[1:]:
            primary['source_refs'].extend(item['source_refs'])
            record.update(status='duplicate', duplicate_of=primary['source_refs'][0])
        events.append(primary)
    events.sort(key=lambda row: (datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')), row['source_refs'][0]))
    if any(not r['event_uid'] for r in events):
        notes.append('Rows without event_uid remain distinct; identical-looking records are not assumed to be duplicates.')
    notes.append('Same-time failures and successes do not establish order: tied failures are excluded and every success resets the earlier failure history.')
    rejected = sum(r['status'] == 'rejected' for r in records)
    findings = review(events)
    return {'schema': 'portfolio.soc-triage.v1', 'status': 'PARTIAL' if rejected else 'COMPLETE',
            'scope': 'Offline exported-log processing; review candidates, not confirmed incidents. No endpoint collection, network calls or response actions.',
            'source_sha256': {'triage.py': digest(Path(__file__).read_bytes()), 'process_triage.py': digest(PROCESS_SOURCE.read_bytes())},
            'summary': {'input_rows': len(records), 'accepted_events': len(events),
                        'duplicate_rows': sum(r['status'] == 'duplicate' for r in records),
                        'rejected_rows': rejected, 'review_candidates': len(findings)},
            'inputs': inputs, 'notes': notes, 'findings': findings,
            'timeline': events, 'source_records': records}


def render_html(report):
    e = escape
    def refs(values):
        return ' '.join(f'<a href="#{ref}">{ref}</a>' for ref in values)
    findings = ''.join(f'<li><h3>{e(r["rule_id"])}</h3><p>{e(r["timestamp"])} / {e(r["username"])} / {e(r["host"])}</p><p>{e(r["reason"])}</p><p><strong>Follow-up:</strong> {e(r["next_step"])}</p><p>{refs(r["source_refs"])}</p></li>' for r in report['findings'])
    timeline = ''.join(f'<li><strong>{e(r["timestamp"])}</strong><p>{e(r["event_type"])} / {e(r["username"])} / {e(r["host"])}</p>{refs(r["source_refs"])}</li>' for r in report['timeline'])
    records = ''.join(f'<details id="{r["id"]}"><summary>{r["id"]} / {r["status"]}</summary><p>{e(r.get("reason", r.get("duplicate_of", "Accepted source record")))}</p><pre>{e(json.dumps(r["raw"],indent=2,ensure_ascii=True))}</pre><p>Parsed-record SHA-256: {r["parsed_record_sha256"]}</p></details>' for r in report['source_records'])
    sources = ''.join(f'<li>{e(r["id"])} / {e(r["name"])} / {r["rows"]} data records<pre>{r["sha256"]}</pre></li>' for r in report['inputs'])
    counts = ' / '.join(f'{key.replace("_", " ")}: {value}' for key, value in report['summary'].items())
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Executed exported-log triage report with source records, rejected inputs and analyst follow-up."><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>SOC triage handoff</title><style>body{{font:16px/1.65 system-ui,sans-serif;color:#213533;max-width:860px;margin:40px auto;padding:0 22px}}h1,h2,h3{{line-height:1.25;overflow-wrap:anywhere}}a{{color:#286b60}}section{{margin-top:36px}}li+li,details{{margin-top:18px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef3f0;padding:16px}}.status{{padding:20px;border-left:4px solid #93651d;background:#fff8e9}}summary{{cursor:pointer}}p{{overflow-wrap:anywhere}}</style></head><body><a class="skip-link" href="#main">Skip to content</a><main id="main">
<h1>SOC triage handoff</h1><p class="status"><strong>{report['status']} / analyst review required</strong><br>{e(counts)}</p><p>{e(report['scope'])}</p><p>Rejected records remain below. A zero-candidate result does not establish that the input is complete or safe.</p>
<nav aria-label="Report sections"><a href="#findings">Candidates</a> / <a href="#timeline">Timeline</a> / <a href="#sources">Sources</a> / <a href="#records">Input records</a></nav>
<section id="findings"><h2>Review candidates</h2><ol>{findings}</ol></section><section id="timeline"><h2>Normalized UTC timeline</h2><ol>{timeline}</ol></section><section id="sources"><h2>Source files and scope</h2><ul>{sources}</ul>{''.join('<p>'+e(n)+'</p>' for n in report['notes'])}<p>Record references count CSV data records after the header or JSON array positions, starting at one. Record hashes cover canonical parsed JSON; file hashes cover exact input bytes. Only declared host/event_uid pairs are coalesced. Shared IDs must be stable and unique within a host across the supplied exports.</p></section><section id="records"><h2>Preserved input records</h2>{records}</section></main></body></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path)
    parser.add_argument('--output-dir', required=True, type=Path, help='A new directory; existing output is never overwritten')
    args = parser.parse_args()
    try:
        report = analyze(args.inputs)
        html = render_html(report)
        args.output_dir.mkdir(parents=True, exist_ok=False)
        (args.output_dir / 'case.json').write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
        (args.output_dir / 'report.html').write_text(html, encoding='utf-8')
    except (ValueError, OSError, csv.Error, UnicodeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    print(report['status'] + ': ' + ', '.join(f'{k}={v}' for k,v in report['summary'].items()))
    print('Wrote case.json and report.html; findings require analyst review.')
    return 2 if report['status'] == 'PARTIAL' else 0


if __name__ == '__main__':
    sys.exit(main())
