#!/usr/bin/env python3
"""Prepare removal of old derived package intermediates; no deletion or hardware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
NAMES = ('Image.raw', 'Image.lz4', 'mach_kernel')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def record(path):
    info = path.stat()
    data = path.read_bytes()
    if len(data) != info.st_size or info.st_mtime_ns != path.stat().st_mtime_ns:
        raise ValueError('Changing input: ' + str(path))
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=len(data),
                sha256=digest(data), mtime_ns=info.st_mtime_ns), data

def main():
    if os.name != 'posix':
        raise RuntimeError('Run in WSL')
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
            sys.executable, '-B', *sys.argv], dict(os.environ,I9100_CPU_CAPPED='1'))
    import lz4.block
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if not output.is_relative_to(ROOT/'research/archive') or output.exists():
        raise ValueError('Use fresh project archive output')
    rows, packages=[], []
    base=ROOT/'uniloader-S2I9100/out/automation'
    for folder in sorted(base.iterdir()):
        if not re.fullmatch(r'control-2026111[3-6]-[A-Za-z0-9-]+', folder.name):
            continue
        if folder.is_symlink() or not all((folder/name).is_file() for name in
                (*NAMES, 'zImage','mach_kernel.sys','manifest.json','loader-symbols.txt')):
            continue
        manifest_record, manifest_data=record(folder/'manifest.json')
        manifest=json.loads(manifest_data)
        zrecord,zdata=record(folder/'zImage')
        sys_record,sysdata=record(folder/'mach_kernel.sys')
        if any(item['bytes']!=manifest['artifacts'][name]['bytes'] or
               item['sha256']!=manifest['artifacts'][name]['sha256']
               for item,name in ((zrecord,'zImage'),(sys_record,'mach_kernel.sys'))):
            raise ValueError('Retained artifact differs: ' + str(folder))
        symbols={}
        for line in (folder/'loader-symbols.txt').read_text().splitlines():
            parts=line.split()
            if len(parts)==3 and re.fullmatch(r'[0-9a-fA-F]+',parts[0]):
                symbols[parts[2]]=int(parts[0],16)
        start=symbols['_kernel_start']-0x48000000
        end=symbols['_kernel_end']-0x48000000
        if not 0<=start<end<=len(zdata):
            raise ValueError('Embedded LZ4 boundaries differ')
        payloads={}
        for name in NAMES:
            item,data=record(folder/name)
            expected=manifest['artifacts'][name]
            if item['bytes']!=expected['bytes'] or item['sha256']!=expected['sha256']:
                raise ValueError('Derived artifact differs: '+str(folder/name))
            payloads[name]=(item,data)
        if payloads['Image.lz4'][1]!=zdata[start:end]:
            raise ValueError('LZ4 not recoverable from retained zImage')
        if lz4.block.decompress(zdata[start:end],
                uncompressed_size=len(payloads['Image.raw'][1]))!=payloads['Image.raw'][1]:
            raise ValueError('Raw image not recoverable from retained zImage')
        if payloads['mach_kernel'][1]!=sysdata:
            raise ValueError('Kernel copies differ')
        retained=dict(zImage=zrecord,kernel=sys_record,manifest=manifest_record,
                      symbols=record(folder/'loader-symbols.txt')[0])
        for name in NAMES:
            item=payloads[name][0]
            item['reason']='Old derived file; retained verified zImage and mach_kernel.sys reproduce exact bytes'
            item['recovery']=dict(zImage=zrecord['path'],kernel=sys_record['path'],
                blob_start=start,blob_end=end,raw_bytes=len(payloads['Image.raw'][1]))
            rows.append(item)
        packages.append(dict(package=folder.relative_to(ROOT).as_posix(),
                             retained=retained))
    # Runtime scripts and link lists must not depend on the retired paths.
    candidates={item['path'] for item in rows}
    expressions=re.compile('|'.join(re.escape(p) for p in candidates))
    conflicts=[]
    for scope in ('xnu-S2I9100/tools','xnu-S2I9100/port-tests',
                  'uniloader-S2I9100/scripts','xnu-S2I9100/out'):
        for parent, dirs, files in os.walk(ROOT/scope):
            dirs[:]=[d for d in dirs if d not in ('.git','__pycache__')
                     and not Path(parent,d).is_symlink()]
            for name in files:
                file=Path(parent,name)
                if file.suffix not in ('.py','.sh','.ps1','.filelist') or file.stat().st_size>1024*1024:
                    continue
                text=file.read_text(errors='replace').replace('\\','/')
                for match in expressions.finditer(text):
                    conflicts.append(dict(source=file.relative_to(ROOT).as_posix(),
                                          target=match[0]))
    if conflicts:
        raise ValueError('Active dependency on old derived artifact: '+repr(conflicts[:5]))
    plan=dict(schema=2,created_utc=datetime.now(timezone.utc).isoformat(),
              hardware_access=False,action='Windows SendToRecycleBin only',
              files=rows,file_count=len(rows),total_bytes=sum(x['bytes'] for x in rows),
              packages=packages,product_dependency_conflicts=conflicts,
              protected=['All zImage/tar/plans and consumption receipts','All ARM objects',
                         'All logs, symbols and current packages','Final HFSX pair','Sources and patches'])
    output.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(result='PLAN_ONLY',files=len(rows),packages=len(packages),
          bytes=plan['total_bytes'],plan_sha256=digest(output.read_bytes()))))

if __name__=='__main__':
    main()
