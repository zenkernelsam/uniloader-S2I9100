#!/usr/bin/env python3
"""Read original dyld environment accessors and UIKit classic initialization."""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
import argparse,importlib.util,json,mmap,struct
from pathlib import Path
here=Path(__file__).resolve().parent;root=here.parents[2]
s=importlib.util.spec_from_file_location('startup_cache',here/'symbolize-ios6-stacks.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
sys.path.insert(0,str(root/'assets/py-native-hid'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if not out.is_relative_to(root/'research') or out.exists():p.error('Fresh project research directory required')
    out.mkdir(parents=True);rows=[];lines=[]
    with (root/'assets/ios6-extract/dyld_cache6_armv7').open('rb') as f:
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as d:
            c=m.Cache(d);md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
            for base,name in c.images:
                if name.rsplit('/',1)[-1] not in ('libdyld.dylib','libsystem_c.dylib'):continue
                uuid=None;at=c.offset(base)+28;count=struct.unpack_from('<I',d,c.offset(base)+16)[0]
                for _ in range(count):
                    cmd,size=struct.unpack_from('<2I',d,at)
                    if cmd==27:uuid=d[at+8:at+24].hex()
                    at+=size
                for va,symbol in c.image_symbols(base)[1]:
                    if symbol not in ('__NSGetEnviron','__NSGetArgc','__NSGetArgv','_environ','__environ','_getenv'):continue
                    raw=d[c.offset(va,96):c.offset(va,96)+96]
                    row=dict(image=name,image_base=hex(base),uuid=uuid,symbol=symbol,address=hex(va),bytes=raw.hex());rows.append(row)
                    lines.append(f'{name} UUID={uuid} {symbol} {va:08x}')
                    if symbol not in ('_environ','__environ'):
                        for ins in md.disasm(raw,va):lines.append(f'{ins.address:08x} {ins.bytes.hex():12s} {ins.mnemonic:10s} {ins.op_str}')
    (out/'startup-symbols.json').write_text(json.dumps(dict(images=rows),indent=2)+'\n')
    (out/'native.txt').write_text('\n'.join(lines)+'\n')
    print('\n'.join(lines),flush=True)
if __name__=='__main__':main()
