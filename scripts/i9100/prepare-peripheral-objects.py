#!/usr/bin/env python3
"""Regenerate the unapplied optional-object patch against the actual main builder."""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
ROOT=Path(__file__).resolve().parents[3]
REPO=ROOT/'uniloader-S2I9100'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--write-unapplied-patch',action='store_true',required=True)
    p.parse_args()
    inventory=ROOT/'xnu-S2I9100/port-tests/check_i9100_peripheral_all.py'
    groups={}
    for n in ast.parse(inventory.read_text()).body:
        if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('C_SOURCES','CPP_SOURCES'):
            groups[n.targets[0].id]=ast.literal_eval(n.value)
    names=groups['C_SOURCES']+groups['CPP_SOURCES']
    if not names or len(names)!=len(set(names)):
        raise RuntimeError('Duplicate or empty peripheral inventory')
    objects=['iokit/'+Path(name).stem+('.cpo' if name.endswith('.cpp') else '.o') for name in names]
    source=Path(__file__).with_name('prepare-automation.py')
    raw=source.read_bytes();before=raw.decode('utf-8')
    if '--offline-peripheral-objects' in before:
        raise RuntimeError('Actual builder already integrates peripherals; do not silently update it')
    parse='args = parser.parse_args()'
    rebuild="subprocess.run([sys.executable, xnu / 'tools/rebuild-i9100.py'"
    if before.count(parse)!=1 or before.count(rebuild)!=1:
        raise RuntimeError('Actual builder anchors changed')
    option="parser.add_argument('--offline-peripheral-objects', action='store_true',\n                    help='Compile opt-in peripheral objects; no peripheral hardware is enabled')\n"
    at=before.index(rebuild);line_start=before.rfind('\n',0,at)+1
    extension='if args.offline_peripheral_objects:\n    peripheral_objects = '+repr(objects)+'\n    objects.extend(name for name in peripheral_objects if name not in objects)\n'
    after=before[:line_start]+extension+before[line_start:]
    after=after.replace(parse,option+parse)
    ast.parse(after)
    patch=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/scripts/i9100/prepare-automation.py',tofile='b/scripts/i9100/prepare-automation.py'))
    if hashlib.sha256(source.read_bytes()).digest()!=hashlib.sha256(raw).digest():
        raise RuntimeError('Actual main builder changed during preparation')
    target=Path(__file__).with_name('peripheral-offline-objects-integration.patch')
    metadata=Path(__file__).with_name('peripheral-offline-objects-integration.json')
    old=json.loads(metadata.read_text())
    result=dict(old,source_sha256=hashlib.sha256(raw).hexdigest(),new_objects=objects,
                patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),applied=False,hardware_enabled=False)
    target.write_bytes(patch.encode())
    metadata.write_text(json.dumps(result,indent=2)+'\n')
    if source.read_bytes()!=raw:raise RuntimeError('Actual main builder changed; unapplied snapshot is stale')
    print('PREPARED',len(objects),'unapplied objects; actual builder unchanged',result['source_sha256'])


if __name__=='__main__':main()
