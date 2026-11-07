"""Execute the actual CLI and retain or verify deterministic public demo output."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder) / 'output'
        result = subprocess.run([sys.executable, str(HERE/'triage.py'),
                                 str(HERE/'fixtures/authentication.csv'), str(HERE/'fixtures/processes.json'),
                                 '--output-dir', str(out)], capture_output=True, text=True, timeout=20)
        if result.returncode != 2:
            raise ValueError('Expected partial exit 2 from deliberate malformed rows: ' + result.stderr)
        data = json.loads((out/'case.json').read_text())
        expected = {'input_rows':20, 'accepted_events':13, 'duplicate_rows':1,
                    'rejected_rows':6, 'review_candidates':3}
        if data['summary'] != expected:
            raise ValueError('Demo count mismatch: ' + str(data['summary']))
        if {r['rule_id'] for r in data['findings']} != {'AUTH_FAILURES_THEN_SUCCESS','PS_ENCODED_COMMAND','CERTUTIL_URLCACHE_FETCH'}:
            raise ValueError('Unexpected candidate rule IDs')
        known = {r['id'] for r in data['source_records']}
        if any(not set(r['source_refs']) <= known for r in data['findings']+data['timeline']):
            raise ValueError('Unresolved source reference')
        files = {name: (out/name).read_bytes() for name in ('case.json','report.html')}
        files['execution.txt'] = result.stdout.encode()
        dest = HERE/'artifacts'
        if args.check:
            for name, content in files.items():
                if (dest/name).read_bytes() != content:
                    raise ValueError('Retained demo differs from actual CLI execution: ' + name)
        else:
            dest.mkdir(exist_ok=True)
            for name, content in files.items():
                (dest/name).write_bytes(content)
        print(result.stdout, end='')
        print('PASS: executed demo matches frozen counts, candidate IDs and source references' + ('; retained outputs match' if args.check else ''))


if __name__=='__main__':
    main()
