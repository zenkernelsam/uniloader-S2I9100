#!/usr/bin/env python3
"""Identify an audited live PID on one verified handle; no process actions.

The proc list is a bounded, sequential observation, not a stopped snapshot.
Recheck the selected PID/name/address through the existing native command.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import struct
HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def main():
    boot=module('proc_boot','capture-boot-snapshot.py');o=boot.o
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--pid',type=int,required=True);a=p.parse_args()
    o.require(0<a.pid<100000,'PID out of bounds')
    out=o.confined(a.output,boot.f.REPO/'out');o.require(not out.exists(),'Fresh proc evidence required')
    symbols=boot.m.Symbols(o.confined(a.kernel,boot.f.REPO/'out'))
    profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory());o.require(device and o.normalize_location(device['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','DONE','STOP','CLOSED'):print(json.dumps(row),flush=True)
            try:
                with boot.open_session(device,symbols.tag,out,record,180) as session:
                    kernel=boot.m.Kernel(session,symbols)
                    init=kernel.u32(symbols['_initproc']);raw=kernel.read(init,1024)
                    o.require(struct.unpack_from('<I',raw,8)[0]==1,'Unexpected initproc PID layout')
                    offset=raw.find(b'launchd\0');o.require(offset>=0 and offset+17<=len(raw),'Missing init command field')
                    head=kernel.u32(symbols['_allproc']);seen=set();rows=[];selected=None
                    while head and len(seen)<128:
                        o.require(0x80000000<=head<0xf0000000 and head not in seen,'Unsafe or cyclic proc pointer')
                        seen.add(head);data=kernel.read(head,(offset+20+3)&~3)
                        pid=struct.unpack_from('<I',data,8)[0]
                        name=data[offset:offset+17].split(b'\0')[0].decode('ascii')
                        o.require(pid<100000 and all(32<=ord(c)<127 for c in name),'Invalid proc identity')
                        row=dict(pid=pid,name=name,proc=head);rows.append(row)
                        if pid==a.pid:selected=row;break
                        head=struct.unpack_from('<I',data)[0]
                    result=dict(tag=symbols.tag,requested_pid=a.pid,command_offset=offset,rows=rows,selected=selected,
                                sequential=True,native_identity_verified=False)
                    (out/'results.json').write_text(json.dumps(result,indent=2))
                    if selected:
                        o.require(re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',selected['name']),'Name outside diagnostic scope')
                        _,answer=session.command('threads '+selected['name']);(out/'selected-threads.txt').write_bytes(answer)
                        identity=re.search(rb'proc\s+(\d+)\s+.*?p=0x([0-9a-fA-F]+)',answer)
                        o.require(identity and int(identity[1])==a.pid and int(identity[2],16)==selected['proc'],'PID changed or wrong inferred name field; no retry')
                        result['native_identity_verified']=True
                        print('VERIFIED PID',a.pid,selected['name'],hex(selected['proc']),flush=True)
                    (out/'results.json').write_text(json.dumps(result,indent=2))
                record('DONE',found=selected is not None)
            except BaseException as error:record('STOP',error=str(error),retry=False);raise
if __name__=='__main__':main()
