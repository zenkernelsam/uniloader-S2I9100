#!/usr/bin/env python3
"""Retain a live SpringBoard Mach request and both associated port queues."""
import argparse
from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
f=module('display_forensic','forensic-session.py')
m=module('display_memory','live-memory.py')
o=module('display_odin','odin-loop.py')

def queue(kernel,address,out,label):
    data=kernel.read(address,0x8c)
    (out/(label+'-port.bin')).write_bytes(data)
    w=struct.unpack('<35I',data)
    result=dict(object=hex(address),bits=hex(w[0]),references=w[1],
                message_count=w[17],limit=w[18],receiver_name=hex(w[20]),
                receiver_space=hex(w[22]),kobject=hex(w[23]),pset_count=w[31],messages=[])
    if 0x80000000<=w[22]<0xf0000000:
        result['receiver_task']=hex(kernel.u32(w[22]+0x34))
    current=w[16];seen=set()
    while current and current not in seen and len(seen)<min(w[17],8):
        seen.add(current)
        kmsg=struct.unpack('<6I',kernel.read(current,24))
        header=kmsg[5]
        raw=kernel.read(header,24)
        fields=struct.unpack('<5Ii',raw)
        length=min(max(fields[1],24),512)
        raw=kernel.read(header,length)
        (out/f'{label}-message-{len(result["messages"])}.bin').write_bytes(raw)
        result['messages'].append(dict(kmsg=hex(current),header=hex(header),bits=hex(fields[0]),
                     size=fields[1],remote=hex(fields[2]),local=hex(fields[3]),id=fields[5]))
        current=kmsg[0]
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();symbols=m.Symbols(a.kernel);out=o.confined(a.output,f.REPO/'out')
    o.require(not out.exists(),'Fresh output directory required')
    profile=json.loads((f.REPO/'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location'])==profile['location'],'No approved live CDC')
        out.mkdir(parents=True);transport=None
        with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','STOP','DONE'):print(json.dumps(row),flush=True)
            try:
                transport=f.WinTransport(device['port'],record)
                s=f.Session(transport,symbols.tag,record,capture,timeout=20);s.handshake()
                kernel=m.Kernel(s,symbols)
                _,data=s.command('threads SpringBoard');(out/'threads.txt').write_bytes(data)
                text=data.decode();match=re.search(r'proc\s+(\d+)\s+SpringBoard.*?thr=(0x[0-9a-f]+)',text,re.S)
                o.require(match is not None,'No live SpringBoard thread')
                pid=int(match[1]);thread=int(match[2],16)
                task=kernel.u32(thread+0x3a0);uss=kernel.u32(thread+0x22c)
                regs=struct.unpack('<17I',kernel.read(uss,68))
                o.require(regs[12]==0xffffffe1,'Saved context is not mach_msg; preserve it and inspect another state')
                user=kernel.user_pmap(kernel.u32(kernel.u32(task+0x18)+0x2c))
                raw=user.read(regs[0],48);(out/'user-message.bin').write_bytes(raw)
                h=struct.unpack_from('<5Ii',raw)
                _,ports=s.command('ports SpringBoard');(out/'ports.txt').write_bytes(ports)
                current_pid=re.search(r'proc\s+(\d+)\s+SpringBoard',ports.decode())
                o.require(current_pid and int(current_pid[1])==pid,'SpringBoard respawned during snapshot')
                names={int(n,16):int(v,16) for n,v in re.findall(r'pn=([0-9a-f]+).*?obj=(0x[0-9a-f]+)',ports.decode())}
                sending=bool(regs[1]&1) and regs[2]>=24
                valid=sending and 24<=h[1]<=regs[2]
                message=dict(direction='send-and-receive' if sending else 'receive-only',valid_send_header=valid)
                if valid:message.update(bits=hex(h[0]),size=h[1],remote_name=hex(h[2]),local_name=hex(h[3]),id=h[5])
                result=dict(tag=symbols.tag,pid=pid,task=hex(task),thread=hex(thread),
                    registers=[hex(v) for v in regs],message=message,queues={})
                targets=[('reply',regs[4])]
                if valid:targets.insert(0,('remote',h[2]))
                elif regs[7]>=0x1004:
                    # mach_msg preserves caller r6 at FP-4. The QuartzCore
                    # send/receive wrapper keeps its remote port there; treat
                    # it as a candidate and resolve only an extant send right.
                    candidate=struct.unpack('<I',user.read(regs[7]-4,4))[0]
                    result['saved_callee_r6_candidate']=hex(candidate)
                    if candidate in names:targets.insert(0,('candidate-remote',candidate))
                for label,name in targets:
                    if name in names:result['queues'][label]=queue(kernel,names[name],out,label)
                _,bb=s.command('ports backboardd');(out/'backboard-ports.txt').write_bytes(bb)
                (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps(result,indent=2),flush=True);record('DONE')
            except BaseException as exc:record('STOP',error=str(exc),retry=False);raise
            finally:
                if transport is not None:transport.close()

if __name__=='__main__':main()
