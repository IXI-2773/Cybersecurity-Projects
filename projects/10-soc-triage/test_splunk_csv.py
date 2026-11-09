"""Focused authentication-export contract checks; no live service or mocks."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fixtures/splunk_csv_v1'


class ExportContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('triage', HERE / 'triage.py')
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def row(self, **changes):
        return dict(_time='2026-11-08T10:00:00Z', username='lab_user',
                    host='SYNTHETIC-01', source_ip='192.0.2.1',
                    event_type='login_failure', event_uid='', **changes)

    def analyze_csv(self, rows):
        path = self.folder / 'events.csv'
        with path.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return self.tool.analyze([path])

    def test_valid_export_normalizes_time_and_preserves_candidate_sources(self):
        report = self.tool.analyze([FIXTURES / 'valid.csv'])
        self.assertEqual(report['summary'], dict(input_rows=8, accepted_events=8,
                         duplicate_rows=0, rejected_rows=0, review_candidates=1))
        self.assertEqual(report['status'], 'COMPLETE')
        self.assertEqual(report['findings'][0]['source_refs'],
                         [f'S01:R{i:06d}' for i in range(1, 7)])
        self.assertEqual(report['timeline'][0]['timestamp'], '2026-11-08T10:00:00Z')
        self.assertEqual(report['source_records'][0]['raw']['_time'],
                         '2026-11-08T12:00:00+02:00')
        self.assertEqual(report['inputs'][0]['sha256'],
                         'b76966b8cdef9dfc0e14e26f18a16384815d8797c2973dfc22df70c391265514')
        self.assertEqual(len(report['source_records']), 8)

    def test_malformed_export_keeps_reasons_and_extra_values(self):
        report = self.tool.analyze([FIXTURES / 'malformed.csv'])
        self.assertEqual(report['summary'], dict(input_rows=6, accepted_events=0,
                         duplicate_rows=0, rejected_rows=6, review_candidates=0))
        self.assertIn('explicit timezone', report['source_records'][1]['reason'])
        self.assertIn('Unsupported event_type', report['source_records'][4]['reason'])
        self.assertEqual(report['source_records'][5]['raw']['extra_values'], ['unexpected'])
        self.assertEqual(report['source_records'][5]['id'], 'S01:R000006')

    def test_invalid_identified_copy_quarantines_valid_match(self):
        report = self.tool.analyze([FIXTURES / 'valid.csv', FIXTURES / 'malformed.csv'])
        self.assertEqual(report['summary'], dict(input_rows=14, accepted_events=7,
                         duplicate_rows=0, rejected_rows=7, review_candidates=0))
        self.assertEqual(report['status'], 'PARTIAL')
        self.assertEqual(report['source_records'][0]['status'], 'rejected')
        self.assertEqual(report['source_records'][8]['status'], 'rejected')
        self.assertEqual(len(report['source_records']), 14)

    def test_timestamp_aliases_compare_strings_before_parsing(self):
        row = self.row(timestamp='2026-11-08T10:00:00Z')
        self.assertEqual(self.analyze_csv([row])['summary']['accepted_events'], 1)
        for other in ('2026-11-08T11:00:00Z', '2026-11-08T12:00:00+02:00'):
            with self.subTest(other=other):
                row['timestamp'] = other
                report = self.analyze_csv([row])
                self.assertEqual(report['summary']['rejected_rows'], 1)
                self.assertIn('Conflicting aliases: timestamp', report['source_records'][0]['reason'])

    def test_requires_timezone_and_rejects_epoch_text(self):
        row = self.row()
        row['_time'] = '2026-11-08T10:00:00'
        with self.assertRaisesRegex(ValueError, 'explicit timezone'):
            self.tool.normalize(row)
        row['_time'] = '1794132000'
        with self.assertRaisesRegex(ValueError, 'Invalid isoformat'):
            self.tool.normalize(row)

    def test_fractional_timestamp_is_preserved(self):
        row = self.row()
        row['_time'] = '2026-11-08T12:00:00.123456+02:00'
        report = self.analyze_csv([row])
        self.assertEqual(report['summary']['accepted_events'], 1)
        self.assertEqual(report['timeline'][0]['timestamp'], '2026-11-08T10:00:00.123456Z')

    def test_blank_or_absent_uid_does_not_coalesce_records(self):
        for absent in (False, True):
            with self.subTest(absent=absent):
                row = self.row()
                if absent:
                    del row['event_uid']
                report = self.analyze_csv([row, row.copy()])
                self.assertEqual(report['summary']['accepted_events'], 2)
                self.assertEqual(report['summary']['duplicate_rows'], 0)
                self.assertEqual(len(report['source_records']), 2)

    def test_unknown_fields_are_retained_and_html_escaped(self):
        report = self.analyze_csv([self.row(note='<script>untrusted</script>')])
        self.assertEqual(report['summary']['accepted_events'], 1)
        self.assertEqual(report['source_records'][0]['raw']['note'], '<script>untrusted</script>')
        html = self.tool.render_html(report)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;untrusted&lt;/script&gt;', html)

    def test_shared_json_process_alias_rejects_conflicting_time(self):
        row = self.row(timestamp='2026-11-08T10:00:00Z', image='notepad.exe',
                       command_line='notepad.exe')
        row['event_type'] = 'process_start'
        path = self.folder / 'events.json'
        path.write_text(json.dumps([row]), encoding='utf-8')
        self.assertEqual(self.tool.analyze([path])['summary']['accepted_events'], 1)
        row['_time'] = '2026-11-08T11:00:00Z'
        path.write_text(json.dumps([row]), encoding='utf-8')
        report = self.tool.analyze([path])
        self.assertEqual(report['summary']['rejected_rows'], 1)
        self.assertIn('Conflicting aliases: timestamp', report['source_records'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
