#!/usr/bin/env python3
"""Read original Bluetooth cache symbols and transport hints without a device."""
import argparse
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import re
import struct
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
ROOT=Path(__file__).resolve().parents[3]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'research') or out.exists():p.error('Fresh project research output required')
    out.mkdir(parents=True);spec=importlib.util.spec_from_file_location('bt_cache',Path(__file__).with_name('symbolize-ios6-stacks.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    source=ROOT/'assets/ios6-extract/dyld_cache6_armv7';images=[]
    with source.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        cache=module.Cache(data)
        for base,name in cache.images:
            if not any(part in name for part in ('MobileBluetooth','BluetoothManager','CoreBluetooth')):continue
            row=dict(path=name,base=f'{base:08x}',strings=[],symbols=[],imports=[])
            at=cache.offset(base);pos=at+28
            for _ in range(cache.unpack('<I',at+16)[0]):
                cmd,size=cache.unpack('<II',pos)
                if cmd==27:row['uuid']=data[pos+8:pos+24].hex()
                if cmd==1:
                    for n in range(cache.unpack('<I',pos+48)[0]):
                        section=pos+56+n*68;label=bytes(data[section:section+16]).rstrip(b'\0')
                        va,length=cache.unpack('<II',section+32)
                        if label==b'__cstring':
                            start=cache.offset(va,length);raw=bytes(data[start:start+length]);cursor=0
                            for item in raw.split(b'\0'):
                                text=item.decode('utf-8','replace')
                                if re.search(r'IOBluetooth|IOService|HCI|Transport|UART|/dev/|BTServer|IOConnect|com\.apple\.bluetooth',text,re.I):
                                    row['strings'].append(dict(address=f'{va+cursor:08x}',value=text))
                                cursor+=len(item)+1
                if cmd==2:
                    so,count,st,strings=cache.unpack('<4I',pos+8)
                    if count>1000000:raise RuntimeError('Unbounded symbol table')
                    for n in range(count):
                        index,typ,_,_,value=cache.unpack('<IBBHI',so+n*12)
                        if index>=strings:continue
                        symbol=cache.string(st+index,st+strings)
                        if typ&0x0e==0 and re.search(r'IOConnect|IOService|IORegistry|IOObject|mach_msg|bootstrap|socket|xpc_',symbol):
                            row['imports'].append(symbol)
                pos+=size
            row['symbols']=[dict(address=f'{v:08x}',name=s) for v,s in cache.image_symbols(base)[1]
                            if re.search(r'HCI|Transport|UART|Controller|BluetoothIsAvailable|BluetoothGetState',s)]
            images.append(row)
    report=dict(source=str(source.relative_to(ROOT)),hardware_tested=False,images=images,
        scope='Original framework evidence only. Actual BTServer and IOUserClient/IOSerial contracts require separate binary/provider analysis; symbol strings do not prove a compatible service.')
    (out/'catalog.json').write_text(json.dumps(report,indent=2)+'\n')
    print('EVIDENCE',out)
    for row in images:print(row['path'],row.get('uuid'),'strings',len(row['strings']),'HCI symbols',len(row['symbols']))


if __name__=='__main__':main()
