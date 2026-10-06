#!/usr/bin/env python3
"""Check public wiki links, page metadata, source IDs and publication boundaries."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
errors = []
source_ids = {x['id'] for x in json.loads((ROOT/'raw/public/sources.json').read_text())}
index = (ROOT/'wiki/index.md').read_text()
pages = list((ROOT/'wiki').rglob('*.md'))
for p in pages:
    text = p.read_text()
    if p.name not in ('index.md', 'log.md') or p.parent != ROOT/'wiki':
        for key in ('id', 'kind', 'visibility', 'status', 'updated', 'sources'):
            if not re.search(rf'^{key}:', text, re.M):
                errors.append(f'{p.relative_to(ROOT)}: missing {key}')
        m = re.search(r'^sources: (.+)$', text, re.M)
        if m:
            for source in json.loads(m.group(1)):
                if source not in source_ids:
                    errors.append(f'{p.relative_to(ROOT)}: unknown source {source}')
    if p != ROOT/'wiki/index.md' and str(p.relative_to(ROOT/'wiki')) not in index:
        errors.append(f'{p.relative_to(ROOT)}: absent from index')

for p in list(ROOT.glob('*.md')) + pages + list((ROOT/'raw').rglob('*.md')):
    text = p.read_text()
    for target in re.findall(r'\]\(([^)]+)\)', text):
        if re.match(r'^[a-z]+:', target) or target.startswith('#'):
            continue
        dest = (p.parent / unquote(target.split('#')[0])).resolve()
        if not dest.is_relative_to(ROOT) or 'private' in dest.relative_to(ROOT).parts:
            errors.append(f'{p.relative_to(ROOT)}: nonpublic link {target}')
        elif not dest.exists():
            errors.append(f'{p.relative_to(ROOT)}: broken link {target}')

manifest=json.loads((ROOT/'raw/public/manifest.json').read_text())
for item in manifest['files']:
    p=ROOT/'raw/public'/item['path']
    if hashlib.sha256(p.read_bytes()).hexdigest() != item['sha256']:
        errors.append(f'{p.relative_to(ROOT)}: immutable snapshot modified')

# These checks are conservative tripwires, not a complete secret detector.
for p in pages + list((ROOT/'raw/public').rglob('*.json')):
    text=p.read_text()
    for pattern in (r'https?://[^\s)]*slack\.com/', r'kaist\.gov-dooray\.com',
                    r'docs\.google\.com/', r'10-202[456]-\d{7}',
                    r'C-202[456]-\d{6}', r'gh[pousr]_[A-Za-z0-9]{20,}',
                    r'PRIVATE KEY-----', r'\b010-\d{4}-\d{4}\b'):
        if re.search(pattern,text,re.I):
            errors.append(f'{p.relative_to(ROOT)}: restricted data pattern')

if (ROOT/'.git').exists():
    tracked = subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
    for name in filter(None,tracked):
        p=Path(name)
        if p.parts[0]=='private' or p.suffix.lower() in {'.pdf','.xlsx','.hwp','.hwpx','.png','.jpg','.zip'} or p.name.startswith('.env'):
            errors.append(f'{name}: forbidden tracked file')

if errors:
    print('\n'.join(errors))
    sys.exit(1)
print(f'OK: {len(pages)} wiki pages; links, index, source IDs, snapshot hash and public boundary checked')
