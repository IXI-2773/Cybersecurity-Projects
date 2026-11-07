"""Prepare a fresh synthetic replay and verify existing native Splunk evidence.

Creates search jobs and reads their results plus an existing fired-alert record.
Does not ingest data, install apps, enable alerts, or send notifications.
Requires Python 3.10+. Offline tests are not evidence that Splunk executed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'projects/01-authentication-detection'
sys.path.insert(0, str(SOURCE))
from qualify_exports import RAW_FIELDS, qualify
from run_live_splunk_smoke import NoRedirect, validate_base_url

LIMIT = 256 * 1024
FINDING_FIELDS = ('timestamp', 'username', 'source_ip', 'host', 'scenario', 'failure_count_in_window')


def epoch(value):
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def csv_write(path, rows, fields):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def replay_rows(anchor, run_id):
    if not re.fullmatch(r'[a-f0-9]{16}', run_id):
        raise ValueError('Invalid replay identifier')
    end = datetime.fromtimestamp(epoch(anchor), timezone.utc)
    return [dict(timestamp=(end + timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                 username='portfolio_replay_' + run_id, source_ip='192.0.2.250',
                 host='SYNTHETIC-ALERT-REPLAY', event_type='login_success' if offset == 0 else 'login_failure',
                 scenario='portfolio_alert_replay_' + run_id)
            for offset in (-600, -540, -480, -420, -360, 0)]


def prepare(folder, *, at=None, run_id=None):
    anchor = at or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    run_id = run_id or uuid.uuid4().hex[:16]
    rows = replay_rows(anchor, run_id)
    folder.mkdir(parents=True, exist_ok=False)
    canonical = (SOURCE / 'validation_events.csv').read_bytes()
    (folder / 'canonical.csv').write_bytes(canonical)
    csv_write(folder / 'replay.csv', rows, RAW_FIELDS)
    manifest = dict(schema='portfolio.splunk-replay.v1', synthetic=True, anchor_utc=anchor,
                    run_id=run_id, canonical_sha256=digest(canonical),
                    replay_sha256=digest((folder / 'replay.csv').read_bytes()))
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def safe_identifier(value, pattern):
    if not re.fullmatch(pattern, value):
        raise ValueError('Invalid lab index, namespace, alert name or search identifier')
    return value


def normalized_query(query):
    if not isinstance(query, str) or not query.strip():
        raise ValueError('Original search query is unavailable')
    return ' '.join(re.sub(r'^search\s+', '', query.strip()).split())


class SplunkAPI:
    def __init__(self, base_url, token, *, opener=None):
        self.base = validate_base_url(base_url)
        if not token.strip() or '\r' in token or '\n' in token:
            raise ValueError('A scoped Splunk API token is required')
        self.token = token.strip()
        self.opener = opener or urllib.request.build_opener(NoRedirect)

    def request(self, path, *, data=None, params=None):
        query = urllib.parse.urlencode({'output_mode': 'json', **(params or {})})
        body = None if data is None else urllib.parse.urlencode({'output_mode': 'json', **data}).encode()
        req = urllib.request.Request(self.base + path + '?' + query, data=body,
                                     headers={'Authorization': 'Bearer ' + self.token,
                                              'Content-Type': 'application/x-www-form-urlencoded',
                                              'Accept': 'application/json'},
                                     method='GET' if data is None else 'POST')
        try:
            with self.opener.open(req, timeout=10) as response:
                raw = response.read(LIMIT + 1)
        except urllib.error.HTTPError as exc:
            raise ValueError(f'Splunk REST request failed: HTTP {exc.code}') from None
        except urllib.error.URLError:
            raise ValueError('TLS-verified Splunk connection unavailable') from None
        if len(raw) > LIMIT:
            raise ValueError('Splunk response exceeds the bounded lab limit')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ValueError('Splunk returned an invalid JSON response') from None
        if not isinstance(value, dict):
            raise ValueError('Splunk JSON response must be an object')
        return value

    def results(self, sid, *, expected_query=None, owner=None, app=None):
        safe_identifier(sid, r'[A-Za-z0-9_.:-]{1,250}')
        path = '/services/search/jobs/' + urllib.parse.quote(sid, safe='')
        for _ in range(16):
            data = self.request(path)
            entries = data.get('entry', [])
            if len(entries) != 1 or entries[0].get('name') != sid:
                raise ValueError('Missing or mismatched search job metadata')
            metadata = entries[0].get('content', {})
            if metadata.get('isFailed') not in (None, False, 0, '0') or metadata.get('isFinalized') not in (None, False, 0, '0'):
                raise ValueError('Failed or finalized search job cannot qualify')
            state = metadata.get('dispatchState')
            if state == 'DONE':
                break
            if state not in ('QUEUED', 'PARSING', 'RUNNING', 'FINALIZING'):
                raise ValueError('Search job did not complete successfully')
            time.sleep(1)
        else:
            raise ValueError('Search job exceeded the bounded wait')
        original = metadata.get('request', {}).get('search')
        if expected_query is not None and normalized_query(original) != normalized_query(expected_query):
            raise ValueError('Original job query does not match the indexed lab query')
        if owner is not None or app is not None:
            acl = entries[0].get('acl') or metadata.get('eai:acl', {})
            if not isinstance(acl, dict) or acl.get('owner') != owner or acl.get('app') != app:
                raise ValueError('Fired job namespace does not match the requested alert')
        result = self.request('/services/search/v2/jobs/' + urllib.parse.quote(sid, safe='') + '/results', params={'count': 101})
        rows = result.get('results')
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError('Invalid search result rows')
        if len(rows) > 100 or int(metadata.get('resultCount', -1)) != len(rows):
            raise ValueError('Search result count is truncated or inconsistent')
        return dict(rows=rows, sid=sid, observed_query_sha256=digest(original.encode()) if isinstance(original, str) else None)

    def search(self, query):
        created = self.request('/services/search/jobs', data={'search': query, 'earliest_time': '0',
                               'latest_time': 'now', 'max_time': '30'})
        sid = created.get('sid', '')
        return dict(**self.results(sid, expected_query=query), query_sha256=digest(query.encode()))

    def fired(self, owner, app, name):
        parts = [urllib.parse.quote(x, safe='') for x in (owner, app, name)]
        entries = self.request('/servicesNS/' + parts[0] + '/' + parts[1] + '/alerts/fired_alerts/' + parts[2]).get('entry')
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError('Invalid or oversized fired-alert evidence')
        return entries


def tuples(rows, fields):
    if any(any(not isinstance(row.get(field), (str, int, float)) for field in fields) for row in rows):
        raise ValueError('Missing or multivalued lab result fields')
    return Counter(tuple(str(row[field]).strip() for field in fields) for row in rows)


def reset_evidence(folder, status='NOT_VERIFIED'):
    if not folder.is_dir():
        raise ValueError('Prepare an evidence directory first')
    report = dict(schema='portfolio.splunk-execution-evidence.v1', status=status,
                  independently_attested=False, suppression_verified=False,
                  scheduled_execution_verified=False)
    (folder / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (folder / 'handoff.md').write_text(f'# Analyst handoff\n\n{status} — no completed evidence check for this attempt.\n', encoding='utf-8')
    return report


def verify(folder, client, *, index, owner, app, alert_name):
    report = reset_evidence(folder)
    safe_identifier(index, r'lab_auth(?:_[a-z0-9]+)*')
    for value in (owner, app):
        safe_identifier(value, r'[A-Za-z0-9_.@-]{1,128}')
    safe_identifier(alert_name, r'[A-Za-z0-9 _().-]{1,128}')
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema') != 'portfolio.splunk-replay.v1' or manifest.get('synthetic') is not True:
        raise ValueError('Invalid replay manifest')
    replay = replay_rows(manifest['anchor_utc'], manifest['run_id'])
    if manifest['canonical_sha256'] != digest((SOURCE / 'validation_events.csv').read_bytes()) or (folder / 'canonical.csv').read_bytes() != (SOURCE / 'validation_events.csv').read_bytes():
        raise ValueError('Canonical fixture integrity mismatch')
    if manifest['replay_sha256'] != digest((folder / 'replay.csv').read_bytes()):
        raise ValueError('Replay artifact integrity mismatch')
    with (folder / 'replay.csv').open(newline='', encoding='utf-8') as f:
        if tuples(list(csv.DictReader(f)), RAW_FIELDS) != tuples(replay, RAW_FIELDS):
            raise ValueError('Replay artifact does not match its manifest')
    base = f'index={index} sourcetype="portfolio:auth"'
    raw_job = client.search('search ' + base + ' | eval indexed_epoch=_time | table _time indexed_epoch ' + ' '.join(RAW_FIELDS))
    raw = raw_job['rows']
    if len(raw) != 70:
        raise ValueError('Expected exactly 70 indexed events: 64 canonical and six replay rows')
    for row in raw:
        try:
            observed = float(row['indexed_epoch'])
            valid_time = math.isfinite(observed) and abs(observed - epoch(row['timestamp'])) < .001
        except (KeyError, ValueError, TypeError):
            valid_time = False
        if not valid_time:
            raise ValueError('Native indexed time does not match the UTC source timestamp')
    scenario = replay[0]['scenario']
    observed_replay = [row for row in raw if row.get('scenario') == scenario]
    canonical = [row for row in raw if row.get('scenario') != scenario]
    if tuples(observed_replay, RAW_FIELDS) != tuples(replay, RAW_FIELDS):
        raise ValueError('Indexed replay rows differ from the prepared fixture')
    csv_write(folder / 'indexed_canonical.csv', canonical, RAW_FIELDS)
    query = (HERE / 'searches/07_indexed_auth_detection.spl').read_text(encoding='utf-8')
    first, remaining = query.split('\n', 1)
    if first != 'index=lab_auth sourcetype="portfolio:auth"':
        raise ValueError('Indexed query source contract changed')
    query = 'search ' + base + f' | where scenario!="{scenario}"\n' + remaining
    finding_job = client.search(query)
    findings = finding_job['rows']
    csv_write(folder / 'indexed_findings.csv', findings, FINDING_FIELDS)
    parity = qualify(folder / 'indexed_canonical.csv', folder / 'indexed_findings.csv')
    if parity['status'] != 'CSV_PARITY_PASS':
        raise ValueError('Canonical raw-event or finding parity failed')
    expected = json.loads((SOURCE / 'expected_findings.json').read_text())['expected_findings']
    for finding in findings:
        source = [row for row in canonical if row.get('event_type') == 'login_success' and all(str(row.get(k)) == str(finding.get(k)) for k in ('timestamp', 'username', 'source_ip', 'host', 'scenario'))]
        if len(source) != 1 or not any(all(str(row.get(k)) == str(finding.get(k)) for k in row) for row in expected):
            raise ValueError('Finding source binding failed')
    candidates = []
    anchor = epoch(manifest['anchor_utc'])
    for entry in client.fired(owner, app, alert_name):
        content = entry.get('content', {})
        try:
            trigger = float(content.get('trigger_time', -1))
        except (ValueError, TypeError):
            continue
        if content.get('savedsearch_name') == alert_name and anchor <= trigger <= anchor + 300 and not content.get('actions'):
            candidates.append(content)
    if not candidates:
        raise ValueError('No matching native fired alert for this replay; a preview is insufficient')
    fired = max(candidates, key=lambda row: float(row['trigger_time']))
    alert_query = (HERE / 'searches/08_alert_preview_indexed.spl').read_text(encoding='utf-8')
    alert_first, alert_remaining = alert_query.split('\n', 1)
    if alert_first != 'index=lab_auth sourcetype="portfolio:auth"':
        raise ValueError('Indexed alert query source contract changed')
    alert_query = 'search ' + base + '\n' + alert_remaining
    alert_job = client.results(fired.get('sid', ''), expected_query=alert_query, owner=owner, app=app)
    alert_rows = alert_job['rows']
    expected_alert = [{**replay[-1], 'failure_count_in_window': 5}]
    if tuples(alert_rows, FINDING_FIELDS) != tuples(expected_alert, FINDING_FIELDS):
        raise ValueError('Fired search job does not contain this exact replay finding')
    csv_write(folder / 'fired_findings.csv', alert_rows, FINDING_FIELDS)
    report.update(status='INDEXED_AND_FIRED_ALERT_EVIDENCE_PASS', observed_at_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),
                  canonical_events=64, replay_events=6, canonical_findings=5, indexed_time_checked=True,
                  raw_job_sid=raw_job['sid'], finding_job_sid=finding_job['sid'], fired_job_sid=fired['sid'],
                  query_sha256={'raw': raw_job['query_sha256'], 'findings': finding_job['query_sha256'], 'fired_observed': alert_job['observed_query_sha256']},
                  fired_namespace={'owner': owner, 'app': app},
                  artifact_sha256={name: digest((folder / name).read_bytes()) for name in ('manifest.json', 'canonical.csv', 'replay.csv', 'indexed_canonical.csv', 'indexed_findings.csv', 'fired_findings.csv')},
                  note='Authenticated response checks only; not independent attestation, production efficacy, scheduler or suppression validation.')
    (folder / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    handoff = '# Analyst handoff — synthetic authentication lab\n\n' + f'Run: `{manifest["run_id"]}` · Replay success: {manifest["anchor_utc"]}\n\n'
    handoff += 'Observed: 64 canonical indexed events, six replay events, five canonical findings and one matching native fired-alert job. Native indexed UTC timestamps matched the source.\n\n'
    handoff += f'Jobs: raw `{raw_job["sid"]}`; findings `{finding_job["sid"]}`; fired `{fired["sid"]}`. Source/export hashes are retained in verification.json.\n\n'
    handoff += 'Legitimate user recovery can produce failures followed by success. These inputs are synthetic; compromise is not established. For actual triage, obtain MFA/session, endpoint and account-owner context.\n\n'
    handoff += 'Disposition: controlled lab evidence checked; no containment or external escalation. Next owner: lab operator, who should disable the temporary schedule and review configuration/screenshots. Scheduler origin, suppression behavior, dashboard rendering and production efficacy remain unverified.\n'
    (folder / 'handoff.md').write_text(handoff, encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('--output', type=Path, required=True)
    check.add_argument('--index', default='lab_auth')
    check.add_argument('--owner', required=True)
    check.add_argument('--app', default='search')
    check.add_argument('--alert-name', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            manifest = prepare(args.output)
            print('Prepared 64 canonical and six current-time replay rows; no Splunk execution. Replay UTC:', manifest['anchor_utc'])
            return 0
        reset_evidence(args.output)
        url, token = os.getenv('SPLUNK_MGMT_URL', ''), os.getenv('SPLUNK_API_TOKEN', '')
        if not url or not token:
            reset_evidence(args.output, 'BLOCKED_NO_CONNECTION')
            raise ValueError('Set SPLUNK_MGMT_URL and SPLUNK_API_TOKEN locally; never place the token in a command or commit')
        report = verify(args.output, SplunkAPI(url, token), index=args.index, owner=args.owner, app=args.app, alert_name=args.alert_name)
        print(report['status'])
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('Splunk workflow NOT_VERIFIED: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
