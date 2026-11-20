#!/usr/bin/env python3
"""Prepare a bounded, SHA-pinned retirement list; never delete or contact hardware."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
RETIRED = (
    'uniloader-S2I9100/out/ios6-data-volume-20261120-021014-924377/DATAFS.HFS',
    'uniloader-S2I9100/out/ios6-data-volume-20261120-021545-946163/DATAFS.HFS',
    'uniloader-S2I9100/out/ios6-data-layout-probe-20261120/blank.hfs',
    'uniloader-S2I9100/out/ios6-system-volume-20261120-022721-579846/FACTORYFS.HFS',
    'uniloader-S2I9100/out/ios6-system-volume-20261120-023623-120833/FACTORYFS.HFS',
    'uniloader-S2I9100/out/one-shot/ROOTFS6-inspect.hfs',
)


def digest(path):
    before = path.stat()
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError('File changed during retirement inventory: ' + str(path))
    return h.hexdigest(), before


def main():
    if os.name != 'posix':
        raise RuntimeError('Hash this inventory in WSL inside the CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice', '-c2', '-n7',
                            sys.executable, '-B', *sys.argv], dict(os.environ, I9100_CPU_CAPPED='1'))
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    output = a.output.resolve()
    if not output.is_relative_to(ROOT / 'research/archive') or output.exists():
        raise ValueError('Use a fresh inventory in the retained project archive')
    cutoff = datetime(2026, 11, 20, 12, 20, tzinfo=timezone.utc).timestamp()
    paths = [(ROOT / name, 'Superseded HFS trial; final role images and original logs retained') for name in RETIRED]
    # Host-model intermediate objects are never Mach-O product objects. Keep
    # current-round objects and every final model executable/source/log.
    xnu = ROOT / 'xnu-S2I9100'
    for parent, dirs, files in os.walk(xnu / 'out'):
        dirs[:] = [name for name in dirs if name not in ('.git', 'node_modules', '__pycache__')
                   and not Path(parent, name).is_symlink()]
        for name in files:
            file = Path(parent, name)
            if name.startswith('host-model-') and name.endswith('.o') and file.stat().st_mtime < cutoff:
                paths.append((file, 'Old host-only intermediate; final executable and evidence retained'))
    rows = []
    for file, reason in paths:
        if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(ROOT):
            raise ValueError('Retirement target moved, missing or linked: ' + str(file))
        value, info = digest(file)
        rel = file.relative_to(ROOT).as_posix()
        rows.append(dict(path=rel, bytes=info.st_size, mtime_ns=info.st_mtime_ns, sha256=value, reason=reason))
        if rel in RETIRED:
            print('HASHED', rel, info.st_size, flush=True)
    # Do not retire a host intermediate referenced by an independent filelist
    # or script. Retained compile/run logs record its historical provenance
    # and remain available; no product/link entry may depend on these paths.
    candidate = {item['path'] for item in rows if item['path'] not in RETIRED}
    reference_pattern = re.compile(r'xnu-S2I9100/out/[^\s\"\'<>]+/host-model-[A-Za-z0-9_-]+\.(?:c|cpp)\.o')
    references = []
    for scope in (xnu / 'out', xnu / 'port-tests', ROOT / 'uniloader-S2I9100/scripts'):
        for parent, dirs, files in os.walk(scope):
            dirs[:] = [name for name in dirs if name not in ('.git', '__pycache__') and not Path(parent, name).is_symlink()]
            for name in files:
                file = Path(parent, name)
                if (not name.endswith('.filelist') and file.suffix not in ('.py', '.sh', '.ps1')) or file.stat().st_size > 1024 * 1024:
                    continue
                text = file.read_text(errors='replace').replace('\\', '/')
                for rel in reference_pattern.findall(text):
                    if rel in candidate:
                        references.append(dict(source=file.relative_to(ROOT).as_posix(), target=rel))
    if references:
        raise RuntimeError('Intermediate is referenced outside a historical log: ' + repr(references[:8]))
    output.parent.mkdir(parents=True, exist_ok=True)
    result = dict(schema=1, created_utc=datetime.now(timezone.utc).isoformat(), hardware_access=False,
                  action='Windows SendToRecycleBin only; plan does not mutate targets',
                  project='D:/Desktop/Git/ios-samsung-i9100', files=rows, file_count=len(rows),
                  total_bytes=sum(row['bytes'] for row in rows), product_dependency_conflicts=references,
                  protected=['Final FACTORYFS/DATAFS pair', 'All ARM objects and link ancestry',
                             'Current models', 'All original logs and source fixtures', 'Phone plans/packages',
                             'assets/toolchains/source patches'])
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(result='PLAN_ONLY', files=len(rows), bytes=result['total_bytes'],
                          plan_sha256=hashlib.sha256(output.read_bytes()).hexdigest(), output=str(output))))


if __name__ == '__main__':
    main()
