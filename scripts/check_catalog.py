"""Check local Markdown destinations and Python syntax without running lab suites."""
import ast
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
failures = []
links = 0
sources = 0

for path in sorted(ROOT.rglob('*.md')):
    if '.git' in path.parts:
        continue
    text = re.sub(r'```.*?```', '', path.read_text(), flags=re.S)
    for value in re.findall(r'!?\[[^\]\n]*\]\(([^\s)]+)\)', text):
        url = urlsplit(value)
        if url.scheme or url.netloc or not url.path:
            continue
        target = (path.parent / unquote(url.path)).resolve()
        if not target.is_relative_to(ROOT) or not target.exists():
            failures.append(f'{path.relative_to(ROOT)}: missing or escaping destination: {value}')
        links += 1

for path in sorted(ROOT.rglob('*.py')):
    if '.git' in path.parts:
        continue
    try:
        ast.parse(path.read_text(), filename=str(path.relative_to(ROOT)))
    except SyntaxError as exc:
        failures.append(str(exc))
    sources += 1

if failures:
    raise SystemExit('\n'.join(failures))
print(f'PASS: {links} local Markdown destinations; {sources} Python sources parse')
