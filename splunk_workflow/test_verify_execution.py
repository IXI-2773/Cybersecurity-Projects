"""Offline protocol and evidence checks; these tests do not execute Splunk."""
import copy
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    import verify_execution as workflow
except ModuleNotFoundError:
    workflow = None


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(workflow, "Splunk execution verifier is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'run'
        self.manifest = workflow.prepare(self.folder, at='2026-10-26T12:00:00Z', run_id='1234567890abcdef')
        with (self.folder / 'canonical.csv').open(newline='') as f:
            self.canonical = list(csv.DictReader(f))
        with (self.folder / 'replay.csv').open(newline='') as f:
            self.replay = list(csv.DictReader(f))
        for row in self.canonical + self.replay:
            row['_time'] = str(workflow.epoch(row['timestamp']))
            row['indexed_epoch'] = row['_time']
        expected = json.loads((workflow.SOURCE / 'expected_findings.json').read_text())['expected_findings']
        self.findings = []
        for row in expected:
            source = next(x for x in self.canonical if x['timestamp'] == row['timestamp'] and x['username'] == row['username'])
            self.findings.append(dict(row, host=source['host']))
        self.alert_row = {**self.replay[-1], 'failure_count_in_window': '5'}

    def client(self, *, raw=None, findings=None, alert_rows=None, fired=True):
        parent = self
        class FakeAPI:
            def search(self, query):
                rows = (raw if raw is not None else parent.canonical + parent.replay) if '| table _time ' in query else (findings if findings is not None else parent.findings)
                return {'sid': 'test_job', 'query_sha256': 'a' * 64, 'rows': copy.deepcopy(rows)}
            def fired(self, owner, app, name):
                return ([{'name': 'test_alert_instance', 'content': {'savedsearch_name': name, 'sid': 'scheduler_test_job', 'trigger_time': workflow.epoch(parent.manifest['anchor_utc']) + 30}}] if fired else [])
            def results(self, sid, **binding):
                parent.assertIn('index=lab_auth ', binding['expected_query'])
                parent.assertEqual((binding['owner'], binding['app']), ('admin', 'search'))
                return {'rows': copy.deepcopy(alert_rows if alert_rows is not None else [parent.alert_row]), 'observed_query_sha256': 'b' * 64}
        return FakeAPI()

    def run_check(self, client=None, **kwargs):
        return workflow.verify(self.folder, client or self.client(), index='lab_auth', owner='admin', app='search', alert_name='Portfolio Replay', **kwargs)

    def test_prepare_keeps_canonical_bytes_and_builds_exact_boundary(self):
        self.assertEqual((self.folder / 'canonical.csv').read_bytes(), (workflow.SOURCE / 'validation_events.csv').read_bytes())
        self.assertEqual(len(self.replay), 6)
        self.assertEqual(workflow.epoch(self.replay[-1]['timestamp']) - workflow.epoch(self.replay[0]['timestamp']), 600)
        self.assertEqual([r['event_type'] for r in self.replay], ['login_failure'] * 5 + ['login_success'])

    def test_preparation_never_overwrites_existing_evidence(self):
        with self.assertRaises(FileExistsError):
            workflow.prepare(self.folder)

    def test_complete_protocol_has_fired_job_and_handoff_but_no_independent_attestation(self):
        report = self.run_check()
        self.assertEqual(report['status'], 'INDEXED_AND_FIRED_ALERT_EVIDENCE_PASS')
        self.assertEqual(report['canonical_findings'], 5)
        self.assertEqual(report['fired_job_sid'], 'scheduler_test_job')
        self.assertFalse(report['independently_attested'])
        self.assertFalse(report['suppression_verified'])
        self.assertIn('Legitimate user recovery', (self.folder / 'handoff.md').read_text())

    def test_duplicate_ingestion_is_rejected(self):
        with self.assertRaisesRegex(ValueError, '70'):
            self.run_check(self.client(raw=self.canonical + self.replay + [self.canonical[0]]))

    def test_wrong_indexed_time_is_not_hidden_by_query_time_repair(self):
        raw = copy.deepcopy(self.canonical + self.replay)
        raw[0]['indexed_epoch'] = str(float(raw[0]['indexed_epoch']) + 3600)
        with self.assertRaisesRegex(ValueError, 'indexed time'):
            self.run_check(self.client(raw=raw))

    def test_changed_canonical_finding_fails(self):
        with self.assertRaisesRegex(ValueError, 'parity'):
            self.run_check(self.client(findings=self.findings[:-1]))

    def test_wrong_finding_host_does_not_pass_partial_field_comparison(self):
        rows = copy.deepcopy(self.findings)
        rows[0]['host'] = 'wrong-host'
        with self.assertRaisesRegex(ValueError, 'source binding'):
            self.run_check(self.client(findings=rows))

    def test_missing_fired_alert_cannot_be_replaced_by_a_preview(self):
        with self.assertRaisesRegex(ValueError, 'fired alert'):
            self.run_check(self.client(fired=False))

    def test_fired_job_must_contain_this_exact_replay_finding(self):
        with self.assertRaisesRegex(ValueError, 'replay finding'):
            self.run_check(self.client(alert_rows=self.findings[:1]))

    def test_modified_replay_artifact_fails_before_network(self):
        with (self.folder / 'replay.csv').open('a') as f:
            f.write('tampered\n')
        with self.assertRaisesRegex(ValueError, '(?i)replay'):
            self.run_check()

    def test_non_lab_index_and_search_injection_rejected(self):
        for index in ('main', 'lab_auth | rest /services/server/info'):
            with self.subTest(index=index), self.assertRaises(ValueError):
                workflow.verify(self.folder, self.client(), index=index, owner='admin', app='search', alert_name='Portfolio Replay')

    def test_failed_recheck_replaces_success_report_and_handoff(self):
        self.run_check()
        with self.assertRaises(ValueError):
            self.run_check(self.client(fired=False))
        self.assertEqual(json.loads((self.folder / 'verification.json').read_text())['status'], 'NOT_VERIFIED')
        self.assertIn('NOT_VERIFIED', (self.folder / 'handoff.md').read_text())

    def test_invalid_connection_cannot_leave_a_stale_success_report(self):
        self.run_check()
        argv = ['verify_execution.py', 'verify', '--output', str(self.folder), '--owner', 'admin', '--alert-name', 'Portfolio Replay']
        with patch('sys.argv', argv), patch.dict('os.environ', {'SPLUNK_MGMT_URL': 'http://invalid.example', 'SPLUNK_API_TOKEN': 'test-token'}), patch('sys.stderr', io.StringIO()):
            self.assertEqual(workflow.main(), 2)
        self.assertEqual(json.loads((self.folder / 'verification.json').read_text())['status'], 'NOT_VERIFIED')


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(workflow, 'Splunk execution verifier is not implemented')

    def test_untrusted_origin_rejected_before_token_use(self):
        with self.assertRaises(ValueError):
            workflow.SplunkAPI('http://example.invalid:8089', 'secret')

    def test_failed_or_finalized_job_never_yields_completed_results(self):
        for content in ({'dispatchState': 'FAILED'}, {'dispatchState': 'DONE', 'isFinalized': True}):
            api = workflow.SplunkAPI('https://example.invalid:8089', 'test-token')
            api.request = lambda path, **kw: {'entry': [{'name': 'job-1', 'content': content}]}
            with self.subTest(content=content), self.assertRaises(ValueError):
                api.results('job-1')

    def test_actual_job_paths_are_bounded_and_token_does_not_enter_report(self):
        requests = []
        replies = [
            {'sid': 'job-1'},
            {'entry': [{'name': 'job-1', 'content': {'dispatchState': 'DONE', 'isFailed': False, 'isFinalized': False, 'resultCount': '1', 'request': {'search': 'search index=lab_auth | head 1'}}}]},
            {'results': [{'timestamp': 'example'}]},
        ]
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *_): self.close()
        class Opener:
            def open(self, req, timeout):
                requests.append(req)
                return Response(json.dumps(replies.pop(0)).encode())
        api = workflow.SplunkAPI('https://example.invalid:8089', 'test-token', opener=Opener())
        report = api.search('search index=lab_auth | head 1')
        self.assertEqual(requests[0].get_method(), 'POST')
        self.assertIn('/services/search/jobs', requests[0].full_url)
        self.assertIn('/services/search/v2/jobs/job-1/results', requests[-1].full_url)
        self.assertTrue(all(req.get_method() == 'GET' for req in requests[1:]))
        self.assertNotIn('test-token', json.dumps(report))

    def test_matching_rows_cannot_hide_a_generating_or_wrong_index_alert_job(self):
        for query in ('| makeresults | eval failure_count_in_window=5', 'search index=main | head 1'):
            api = workflow.SplunkAPI('https://example.invalid:8089', 'test-token')
            api.request = lambda path, **kw: {'entry': [{'name': 'job-1', 'acl': {'owner': 'admin', 'app': 'search'}, 'content': {'dispatchState': 'DONE', 'resultCount': '1', 'request': {'search': query}}}]}
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, 'query'):
                api.results('job-1', expected_query='search index=lab_auth | head 1', owner='admin', app='search')

    def test_matching_alert_query_cannot_hide_wrong_namespace(self):
        api = workflow.SplunkAPI('https://example.invalid:8089', 'test-token')
        api.request = lambda path, **kw: {'entry': [{'name': 'job-1', 'acl': {'owner': 'other', 'app': 'search'}, 'content': {'dispatchState': 'DONE', 'resultCount': '1', 'request': {'search': 'search index=lab_auth | head 1'}}}]}
        with self.assertRaisesRegex(ValueError, 'namespace'):
            api.results('job-1', expected_query='search index=lab_auth | head 1', owner='admin', app='search')


if __name__ == '__main__':
    unittest.main()
