"""Behavior and failure-path checks for the exported-log assistant."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def event(uid='a', timestamp='2026-10-26T10:00:00Z', kind='login_failure', **changes):
    return dict(event_uid=uid, timestamp=timestamp, event_type=kind,
                username='analyst', host='host1', source_ip='192.0.2.10', **changes)


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((HERE / 'triage.py').exists(), 'The executable triage assistant is not implemented')
        spec = importlib.util.spec_from_file_location('triage', HERE / 'triage.py')
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def analyze(self, rows):
        path = self.folder / 'events.json'
        path.write_text(json.dumps(rows))
        return self.tool.analyze([path])

    def sequence(self, seconds=600):
        return [event(str(i), f'2026-10-26T10:0{i}:00Z') for i in range(5)] + [
            event('success', f'2026-10-26T10:10:{seconds-600:02d}Z', 'login_success')]

    def test_inclusive_boundary_has_exact_source_references(self):
        r = self.analyze(self.sequence())
        self.assertEqual(len(r['findings']), 1)
        self.assertEqual(r['findings'][0]['source_refs'], [f'S01:R{i:06d}' for i in range(1,7)])

    def test_601_seconds_does_not_match(self):
        self.assertEqual(self.analyze(self.sequence(601))['findings'], [])

    def test_duplicate_uid_cannot_inflate_threshold(self):
        rows = self.sequence(); rows[4] = rows[3].copy()
        r = self.analyze(rows)
        self.assertEqual(r['summary']['duplicate_rows'], 1)
        self.assertEqual(r['findings'], [])

    def test_conflicting_uid_quarantines_both_rows(self):
        r = self.analyze([event(), event(timestamp='2026-10-26T10:01:00Z')])
        self.assertEqual(r['summary']['rejected_rows'], 2)
        self.assertEqual(r['timeline'], [])

    def test_malformed_copy_quarantines_identifiable_valid_uid(self):
        r=self.analyze([event(),event(timestamp='not-a-time')])
        self.assertEqual(r['summary']['rejected_rows'],2)
        self.assertEqual(r['timeline'],[])

    def test_malformed_uid_copy_cannot_contribute_to_finding(self):
        rows=self.sequence();rows.append(event('4', 'not-a-time'))
        self.assertEqual(self.analyze(rows)['findings'],[])

    def test_host_isolation(self):
        rows = self.sequence(); rows[-1]['host'] = 'other-host'
        self.assertEqual(self.analyze(rows)['findings'], [])

    def test_success_resets_the_failure_history(self):
        rows = self.sequence(); rows.insert(4, event('reset', '2026-10-26T10:03:30Z', 'login_success'))
        self.assertEqual(self.analyze(rows)['findings'], [])

    def test_same_timestamp_failure_does_not_establish_order(self):
        rows = self.sequence(); rows[4]['timestamp'] = rows[-1]['timestamp']
        self.assertEqual(self.analyze(rows)['findings'], [])

    def test_explicit_offset_normalizes_to_utc(self):
        r = self.analyze([event(timestamp='2026-10-26T12:00:00+02:00')])
        self.assertEqual(r['timeline'][0]['timestamp'], '2026-10-26T10:00:00Z')

    def test_timezone_free_timestamp_is_quarantined(self):
        r = self.analyze([event(timestamp='2026-10-26T10:00:00')])
        self.assertEqual(r['status'], 'PARTIAL')
        self.assertEqual(r['summary']['rejected_rows'], 1)

    def test_conflicting_field_alias_is_rejected(self):
        self.assertEqual(self.analyze([event(user='different')])['summary']['rejected_rows'], 1)

    def test_without_event_uid_identical_records_are_retained(self):
        row=event();row.pop('event_uid')
        r=self.analyze([row,row.copy()])
        self.assertEqual(r['summary']['accepted_events'], 2)
        self.assertIn('event_uid', ' '.join(r['notes']))

    def test_process_patterns_reuse_existing_inspector(self):
        row=event(kind='process_start', image='powershell.exe', command_line='powershell -enc LAB_ONLY')
        self.assertEqual(self.analyze([row])['findings'][0]['rule_id'], 'PS_ENCODED_COMMAND')

    def test_benign_process_does_not_match(self):
        row=event(kind='process_start', image='powershell.exe', command_line='powershell -File diagnostic.ps1')
        self.assertEqual(self.analyze([row])['findings'], [])

    def test_report_escapes_untrusted_html(self):
        row=event();row['username']='<script>alert(1)</script>'
        html=self.tool.render_html(self.analyze([row]))
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_json_duplicate_keys_are_fatal(self):
        path=self.folder/'bad.json';path.write_text('[{"host":"a","host":"b"}]')
        with self.assertRaises(ValueError):self.tool.analyze([path])

    def test_duplicate_csv_headers_are_fatal(self):
        path=self.folder/'bad.csv';path.write_text('timestamp,host,host\nx,a,b\n')
        with self.assertRaises(ValueError):self.tool.analyze([path])

    def test_partial_cli_returns_two_and_writes_reviewable_report(self):
        path=self.folder/'events.json';path.write_text(json.dumps([event(),event('bad', 'not-a-time')]))
        out=self.folder/'report'
        r=subprocess.run([sys.executable,str(HERE/'triage.py'),str(path),'--output-dir',str(out)],capture_output=True,text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(json.loads((out/'case.json').read_text())['summary']['rejected_rows'], 1)
        self.assertTrue((out/'report.html').exists())

    def test_existing_output_is_not_overwritten(self):
        path=self.folder/'events.json';path.write_text(json.dumps([event()]))
        out=self.folder/'report';out.mkdir();sentinel=out/'case.json';sentinel.write_text('preserve')
        r=subprocess.run([sys.executable,str(HERE/'triage.py'),str(path),'--output-dir',str(out)],capture_output=True,text=True)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_existing_64_event_fixture_retains_expected_five_users(self):
        r=self.tool.analyze([HERE.parent/'01-authentication-detection/validation_events.csv'])
        self.assertEqual(len(r['findings']), 5)
        self.assertEqual({f['username'] for f in r['findings']}, {'user_threshold','user_reset','user_boundary','user_alpha','user_beta'})

    def test_future_fractional_failures_are_not_before_whole_second_success(self):
        rows=[event(str(i), f'2026-10-26T10:00:00.00000{i+1}Z') for i in range(5)]
        rows.append(event('success','2026-10-26T10:00:00Z','login_success'))
        self.assertEqual(self.analyze(rows)['findings'], [])

    def test_extra_csv_column_is_quarantined_and_retained(self):
        path=self.folder/'bad.csv'
        path.write_text('timestamp,username,host,event_type,source_ip\n2026-10-26T10:00:00Z,a,h,login_failure,192.0.2.1,extra\n')
        report=self.tool.analyze([path])
        self.assertEqual(report['summary']['rejected_rows'],1)
        self.assertIn('extra', json.dumps(report['source_records'][0]['raw']))


if __name__=='__main__':unittest.main()
