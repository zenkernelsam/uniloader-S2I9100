#!/usr/bin/env python3
"""Bind the current GS system-app port cache to its actual receive queue.

Read only. The cache is in Backboard's user map; port objects use the kernel
map. Match BUILD, PID/task/map/cache slide before combining their evidence.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('gs_boot',HERE/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

def identity(raw):
    m=re.search(rb'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)',raw)
    b.o.require(m is not None,'Process absent')
    return int(m[1]),int(m[2],16)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--context',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    symbols=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'))
    saved=json.loads(b.o.confined(a.context,b.f.REPO/'out').read_text())
    b.o.require(saved['tag']==symbols.tag,'Context BUILD differs')
    ctx=next(x for x in saved['processes'] if x['process']=='backboardd')
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        device=b.o.cdc(b.o.Host().inventory())
        b.o.require(device and device['service'].lower()=='usbser' and b.o.normalize_location(device['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','DONE','STOP'):print(json.dumps(row),flush=True)
            try:
                with b.open_session(device,symbols.tag,out,record,300) as session:
                    reply,_=session.command('panic-status')
                    if reply!='OK panic=0 seconds=00000000':
                        b.retain_current_panic(session,out,record);raise RuntimeError('Active panic retained')
                    k=b.m.Kernel(session,symbols)
                    _,raw=session.command('ports backboardd');(out/'backboard-ports-before.bin').write_bytes(raw)
                    pid,task=identity(raw)
                    b.o.require((pid,task)==(ctx['pid'],int(ctx['task'],16)),'Backboard context replaced')
                    mapva=k.u32(task+0x18);pmap=k.u32(mapva+0x2c)
                    b.o.require(mapva==int(ctx['map'],16) and pmap==int(ctx['pmap'],16),'Backboard map replaced')
                    user=k.user_pmap(pmap)
                    dyld=user.read(int(ctx['dyld_info']['address'],16),84)
                    slide=struct.unpack_from('<I',dyld,80)[0]
                    b.o.require(slide==int(ctx['dyld_info']['cache_slide'],16) and not slide&4095,'Cache slide replaced')
                    at=0x3a283e6c+slide
                    b.o.require(4096<=at<=0x3ffffffc,'GS cache outside user range')
                    name=struct.unpack('<I',user.read(at,4))[0]
                    result=dict(tag=symbols.tag,pid=pid,task=hex(task),cache_address=hex(at),gs_port_name=hex(name))
                    # Initial ports established identity before the cache
                    # read. Query again and bracket that namespace snapshot
                    # with cache reads; a reused entry can change generation.
                    _,raw=session.command('ports backboardd');(out/'gs-lookup-ports.bin').write_bytes(raw)
                    b.o.require(identity(raw)==(pid,task),'Backboard replaced at port lookup')
                    after_name=struct.unpack('<I',user.read(at,4))[0]
                    result['cache_stable_across_lookup']=name==after_name
                    result['cache_name_after_lookup']=hex(after_name)
                    line=re.search(rb'pn='+format(name,'x').encode()+rb'\b[^\r\n]*',raw) if name==after_name else None
                    result['port_line']=line[0].decode() if line else None
                    if line:
                        obj=re.search(rb'obj=(0x[0-9a-f]+)',line[0]);port=int(obj[1],16) if obj else 0
                        if 0x80000000<=port<0xf0000000:
                            data=k.read(port,140);(out/'gs-port.bin').write_bytes(data)
                            w=struct.unpack('<35I',data)
                            result['port']=dict(object=hex(port),bits=hex(w[0]),active=bool(w[0]&0x80000000),count=w[17],limit=w[18],receiver_name=hex(w[20]),receiver_space=hex(w[22]))
                            if w[0]&0x80000000 and 0x80000000<=w[22]<0xf0000000:
                                result['port']['receiver_task']=hex(k.u32(w[22]+0x34))
                    _,sb=session.command('ports SpringBoard');(out/'springboard-ports.bin').write_bytes(sb)
                    match=re.search(rb'proc\s+(\d+)\s+SpringBoard.*?task=(0x[0-9a-f]+)',sb)
                    result['springboard']=dict(pid=int(match[1]),task=match[2].decode()) if match else None
                    if result.get('port'):
                        result['matching_sb_receives']=[line.decode() for line in sb.splitlines() if result['port']['object'].encode() in line and b'rt=recv' in line]
                    _,after=session.command('ports backboardd');(out/'backboard-ports-after.bin').write_bytes(after)
                    b.o.require(identity(after)==(pid,task) and k.u32(task+0x18)==mapva and k.u32(mapva+0x2c)==pmap,'Backboard changed during capture')
                    result['cache_stable']=struct.unpack('<I',user.read(at,4))[0]==name
                    result['sequential']=True
                    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                    print(json.dumps(result,indent=2),flush=True)
                record('DONE')
            except BaseException as e:record('STOP',error=str(e),retry=False);raise

if __name__=='__main__':main()
