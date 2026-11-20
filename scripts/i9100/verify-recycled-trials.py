#!/usr/bin/env python3
"""Verify actual Windows recycle payload bytes and retained storage dependencies."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def windows_path(value):
    if not re.fullmatch(r'D:\\\$Recycle\.Bin\\S-1-5-21-[0-9-]+[\\/]+\$[IR][A-Za-z0-9.]+', value, re.IGNORECASE):
        raise ValueError('Receipt is not an exact D-drive Windows recycle file')
    return Path('/mnt/d') / value[3:].replace('\\', '/')


def main():
    if os.name != 'posix':
        raise RuntimeError('Verify bulk bytes inside the WSL CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice', '-c2', '-n7',
                            sys.executable, '-B', *sys.argv], dict(os.environ, I9100_CPU_CAPPED='1'))
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    plan = a.plan.resolve()
    receipt = a.receipt.resolve()
    output = a.output.resolve()
    for file in (plan, receipt, output):
        if not file.is_relative_to(ROOT / 'research/archive'):
            raise ValueError('Use retained project archive input/output')
    if output.exists():
        raise ValueError('Do not overwrite an earlier verification')
    prepared = json.loads(plan.read_text(encoding='utf-8-sig'))
    completed = json.loads(receipt.read_text(encoding='utf-8-sig'))
    if completed.get('state') != 'PASS' or completed['plan_sha256'] != sha(plan) or completed['permanent_delete'] is not False or completed['recycle_bin_emptied'] is not False:
        raise ValueError('Recycle action was not verified without permanent deletion')
    expected = {row['path']: row for row in prepared['files']}
    if len(expected) != prepared['file_count'] or len(completed['files']) != len(expected):
        raise ValueError('Receipt does not cover every exact planned file')
    seen = set()
    for row in completed['files']:
        key = row['path']
        if key in seen or key not in expected or row['state'] != 'verified-recyclable':
            raise ValueError('Duplicate or incomplete recycle receipt')
        seen.add(key)
        payload = windows_path(row['payload'])
        metadata = windows_path(row['metadata'])
        original = ROOT / key
        if original.exists() or payload.is_symlink() or not metadata.is_file() or not payload.is_file():
            raise ValueError('Original/recycle path does not match the action receipt')
        value = sha(payload)
        if payload.stat().st_size != row['bytes'] or value != row['sha256'] or value != expected[key]['sha256']:
            raise ValueError('Windows recycle payload differs from the original bytes: ' + key)
        if len(seen) <= 6 or len(seen) % 500 == 0:
            print('VERIFIED', len(seen), '/', len(expected), key, flush=True)
    # Final storage candidates and their role capacity must survive intact.
    pair_file = ROOT / 'uniloader-S2I9100/out/ios6-volume-pair-20261120-025359-621241/pair-manifest.json'
    pair = json.loads(pair_file.read_text())
    retained = {}
    for role in ('system', 'data'):
        item = pair[role]
        file = (ROOT / item['path']).resolve()
        if not file.is_relative_to(ROOT / 'uniloader-S2I9100/out') or file.stat().st_size != item['bytes'] or sha(file) != item['sha256']:
            raise ValueError('Final storage candidate changed during retirement')
        retained[role] = dict(path=item['path'], bytes=item['bytes'], sha256=item['sha256'])
        print('RETAINED', role, item['sha256'], flush=True)
    result = dict(schema=1, result='PASS', created_utc=datetime.now(timezone.utc).isoformat(),
                  plan_sha256=sha(plan), receipt_sha256=sha(receipt), files_verified=len(seen),
                  bytes_verified=sum(item['bytes'] for item in completed['files']),
                  original_paths_absent=True, every_recycle_payload_sha256_verified=True,
                  retained_volume_pair=retained, pair_manifest_sha256=sha(pair_file),
                  permanent_delete=False, recycle_bin_emptied=False, hardware_contacted=False)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print('PASS', len(seen), 'actual Windows recycle payloads and final volume candidates')


if __name__ == '__main__':
    main()
