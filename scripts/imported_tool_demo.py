"""Run one bounded upstream-tool demonstration; never scan a user-supplied target."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = {'ssh': '11-ssh-algorithm-review', 'secrets': '12-secret-detection'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(command, cwd, destination, allowed, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=30)
    if result.returncode not in allowed:
        raise RuntimeError(f'Tool failed ({result.returncode}): {result.stderr or result.stdout}')
    data = json.loads(result.stdout)
    destination.write_text(result.stdout)
    return data, result.returncode


def secret_demo(project, out):
    env = os.environ.copy()
    env['PYTHONPATH'] = str(ROOT / 'third_party/detect-secrets')
    # The fixture has a recognizable header but no private key or credential.
    with tempfile.TemporaryDirectory(prefix='secret-demo-') as work:
        work = Path(work)
        for path in (project / 'fixtures').iterdir():
            shutil.copyfile(path, work / path.name)
        command = [sys.executable, '-m', 'detect_secrets', '--cores', '1', 'scan',
                   '--all-files', '--no-verify', '.']
        before, first_exit = invoke(command, work, out / 'before.json', {0}, env)
        findings = [(Path(name).name, finding['type'])
                    for name, rows in before['results'].items() for finding in rows]
        if findings != [('positive.txt', 'Private Key')]:
            raise RuntimeError(f'Unexpected fixture findings: {findings}')
        (work / 'positive.txt').write_text('The demonstration header was removed.\n')
        after, second_exit = invoke(command, work, out / 'after.json', {0}, env)
        if after['results']:
            raise RuntimeError('The corrected fixture still produced findings')
        for result in (before, after):
            if any('verification_policies' in row['path'] for row in result['filters_used']):
                raise RuntimeError('Network verification was not disabled')
    return {'before_findings': 1, 'after_findings': 0,
            'benign_findings': 0, 'allowlisted_findings': 0,
            'network_verification': False, 'tool_exit_codes': [first_exit, second_exit],
            'dependencies': {name: importlib.metadata.version(name) for name in ('requests', 'PyYAML')}}


def ssh_demo(project, out):
    case = json.loads((project / 'fixtures/algorithms.json').read_text())
    names = [case['comparison_algorithm'], case['flagged_algorithm']]
    command = [sys.executable, str(ROOT / 'third_party/ssh-audit/ssh-audit.py'),
               '--lookup', ','.join(names), '--no-colors']
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15)
    if result.returncode not in {0, 2, 3}:
        raise RuntimeError(f'Algorithm lookup failed: {result.stderr or result.stdout}')
    (out / 'lookup.txt').write_text(result.stdout)
    levels = {}
    for name in names:
        match = re.search(r'^\(kex\)\s+' + re.escape(name) + r'\s+-- \[(info|warn|fail)\]',
                          result.stdout, flags=re.M)
        if not match:
            raise RuntimeError(f'Missing algorithm classification: {name}')
        levels[name] = match.group(1)
    if levels[case['flagged_algorithm']] != 'fail' or levels[case['comparison_algorithm']] != 'info':
        raise RuntimeError(f'Unexpected algorithm classifications: {levels}')
    return {'method': 'offline upstream algorithm database lookup',
            'network_used': False, 'classifications': levels, 'tool_exit_code': result.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', choices=PROJECTS)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    project = ROOT / 'projects' / PROJECTS[args.tool]
    observed = secret_demo(project, out) if args.tool == 'secrets' else ssh_demo(project, out)
    receipt = {
        'tool': args.tool, 'executed_at': datetime.now(timezone.utc).isoformat(),
        'python': platform.python_version(), 'platform': platform.platform(),
        'harness_sha256': digest(Path(__file__)),
        'imports_sha256': digest(ROOT / 'third_party/imports.json'),
        'inputs': {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted((project / 'fixtures').iterdir())},
        'outputs': {p.name: digest(p) for p in sorted(out.iterdir())},
        'observed': observed,
    }
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(observed, indent=2))


if __name__ == '__main__':
    main()
