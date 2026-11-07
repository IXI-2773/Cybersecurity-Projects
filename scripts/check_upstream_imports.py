"""Verify unchanged upstream bytes and the two retained, bounded tool examples."""
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    manifest = ROOT / 'third_party/imports.json'
    imports = json.loads(manifest.read_text())['imports']
    count = 0
    require({item['name'] for item in imports} == {'ssh-audit', 'detect-secrets'}, 'Unexpected imports')
    for item in imports:
        folder = (ROOT / item['root']).resolve()
        require(folder.is_relative_to(ROOT / 'third_party'), 'Import root escapes third_party')
        require(any(row['path'] == 'LICENSE' for row in item['files']), 'Import missing license')
        expected = set()
        for row in item['files']:
            path = (folder / row['path']).resolve()
            require(path.is_relative_to(folder), 'Imported path escapes its root')
            require(digest(path) == row['sha256'], f'Changed upstream source: {path.relative_to(ROOT)}')
            expected.add(path)
            if path.suffix == '.py':
                ast.parse(path.read_text(), filename=str(path.relative_to(ROOT)))
            count += 1
        actual = {p.resolve() for p in folder.rglob('*') if p.is_file()
                  and '__pycache__' not in p.parts and p.suffix != '.pyc'}
        require(actual == expected, f'Unexpected/missing imported paths: {item["name"]}')
    for name in ('11-ssh-algorithm-review', '12-secret-detection'):
        artifacts = ROOT / 'projects' / name / 'artifacts'
        receipt = json.loads((artifacts / 'receipt.json').read_text())
        require(receipt['harness_sha256'] == digest(ROOT / 'scripts/imported_tool_demo.py'), 'Stale demo source')
        require(receipt['imports_sha256'] == digest(manifest), 'Stale imported-tool snapshot')
        for path, sha in receipt['inputs'].items():
            target = (ROOT / path).resolve()
            require(target.is_relative_to(ROOT), 'Input path escapes repository')
            require(digest(target) == sha, f'Stale demo input: {path}')
        for path, sha in receipt['outputs'].items():
            target = (artifacts / path).resolve()
            require(target.is_relative_to(artifacts), 'Output path escapes artifacts')
            require(digest(target) == sha, f'Stale retained output: {path}')
    artifacts = ROOT / 'projects/11-ssh-algorithm-review/artifacts'
    text = (artifacts / 'lookup.txt').read_text()
    require(re.search(r'^\(kex\)\s+diffie-hellman-group1-sha1\s+-- \[fail\]', text, re.M), 'Missing flagged SSH control')
    require(re.search(r'^\(kex\)\s+mlkem768x25519-sha256\s+-- \[info\]', text, re.M), 'Missing SSH comparison control')
    artifacts = ROOT / 'projects/12-secret-detection/artifacts'
    before = json.loads((artifacts / 'before.json').read_text())
    after = json.loads((artifacts / 'after.json').read_text())
    findings = [(Path(path).name, row['type']) for path, rows in before['results'].items() for row in rows]
    require(findings == [('positive.txt', 'Private Key')] and not after['results'], 'Incorrect secret-demo controls')
    require(all(not any('verification_policies' in f['path'] for f in data['filters_used'])
                for data in (before, after)), 'Secret verification was enabled')
    print(f'PASS: {count} unchanged upstream files, licenses, Python syntax and both retained examples')
    print('Scope: offline SSH lookup and synthetic secret-detection controls; no live-server or production verdict')


if __name__ == '__main__':
    main()
