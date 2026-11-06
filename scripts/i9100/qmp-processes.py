#!/usr/bin/env python3
"""Read a stopped ARMv7 kernel's live proc list through its actual page tables."""
import argparse
import json
from pathlib import Path
import re
import socket
import struct
import subprocess

p=argparse.ArgumentParser()
p.add_argument('--socket-file',type=Path,required=True)
p.add_argument('--kernel',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
symbols={}
for row in subprocess.check_output(['llvm-nm-14',str(a.kernel)],text=True).splitlines():
    parts=row.split()
    if len(parts)==3 and parts[2] in ('_allproc','_initproc','_kernel_pmap_store'):
        symbols[parts[2]]=int(parts[0],16)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5)
s.connect(a.socket_file.read_text().strip());f=s.makefile('rwb',buffering=0)
json.loads(f.readline())
def call(cmd,args=None):
    req={'execute':cmd}
    if args is not None:req['arguments']=args
    f.write((json.dumps(req)+'\n').encode())
    while True:
        reply=json.loads(f.readline())
        if 'error' in reply:raise RuntimeError(reply)
        if 'return' in reply:return reply['return']
def hmp(cmd):return call('human-monitor-command',{'command-line':cmd})
call('qmp_capabilities');running=call('query-status')['running']
if running:call('stop')
try:
    def physical(pa,n=1):
        data=hmp('xp /%uwx 0x%x'%(n,pa))
        values=[int(v,16) for v in re.findall(r'0x([0-9a-fA-F]{8})\b',data)]
        if len(values)!=n:raise ValueError(data)
        return values
    ttb=physical(symbols['_kernel_pmap_store']-0x40000000)[0]
    assert ttb&0x3fff==0
    tables={}
    def word(pa):
        if pa not in tables:tables[pa]=physical(pa)[0]
        return tables[pa]
    def translate(va):
        l1=word(ttb+(va>>20)*4)
        if l1&3==2:return (l1&0xfff00000)|(va&0xfffff)
        if l1&3==1:
            l2=word((l1&0xfffffc00)+((va>>12)&255)*4)
            if l2&3 in (2,3):return (l2&0xfffff000)|(va&0xfff)
            if l2&3==1:return (l2&0xffff0000)|(va&0xffff)
        raise ValueError('Unmapped '+hex(va))
    def read(va,n):
        out=bytearray()
        while n:
            count=min(n,4096-(va&4095))
            assert count%4==0
            values=physical(translate(va),count//4)
            out+=struct.pack('<%uI'%len(values),*values)
            n-=count;va+=count
        return out
    def u32(va):return struct.unpack('<I',read(va,4))[0]
    init=u32(symbols['_initproc']);raw=read(init,1024)
    assert struct.unpack_from('<I',raw,8)[0]==1
    comm=raw.find(b'launchd\0')
    if comm<0:raise ValueError('Could not identify initproc command field')
    head=u32(symbols['_allproc']);seen=set();rows=[]
    while head:
        assert head not in seen and len(seen)<256;seen.add(head)
        data=read(head,(comm+20+3)&~3)
        pid=struct.unpack_from('<I',data,8)[0]
        name=data[comm:comm+17].split(b'\0')[0].decode('ascii')
        assert pid<100000 and all(32<=ord(c)<127 for c in name)
        rows.append({'pid':pid,'name':name,'proc':hex(head)})
        head=struct.unpack_from('<I',data)[0]
    result={'kernel_pmap_ttb':hex(ttb),'command_offset':hex(comm),
        'processes':sorted(rows,key=lambda r:r['pid'])}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
finally:
    if running:call('cont')
    s.close()
