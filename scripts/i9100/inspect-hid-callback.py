#!/usr/bin/env python3
"""Find the original IOHIDLib plugin in bounded live BackBoard mappings.

No memory writes, no target code execution. Exact BUILD, PID/task, original
plugin vtable and native queue fields are required; VM/page reads are capped.
"""
import argparse,hashlib,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def u32(b,at=0):return struct.unpack_from('<I',b,at)[0]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--context',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--max-pages',type=int,choices=range(1,1025),default=512)
    p.add_argument('--start',type=lambda x:int(x,16),default=0x1000)
    p.add_argument('--end',type=lambda x:int(x,16),default=0x4000000)
    a=p.parse_args();f=module('callback_forensic','forensic-session.py')
    if not 4096<=a.start<a.end<=0x2f000000 or (a.start|a.end)&4095:
        p.error('Use a bounded page-aligned heap interval below user stacks')
    m=module('callback_memory','live-memory.py');o=module('callback_odin','odin-loop.py')
    symbols=m.Symbols(a.kernel);saved=json.loads(a.context.read_text())
    o.require(saved['tag']==symbols.tag,'Saved context BUILD differs')
    ctx=next(x for x in saved['processes'] if x['process']=='backboardd')
    slide=int(ctx['dyld_info']['cache_slide'],16)
    o.require(not slide&4095 and slide<0x40000000-0x3934d758,'Invalid original plugin slide')
    expected=0x3934d758+slide
    out=o.confined(a.output,f.REPO/'out');o.require(not out.exists(),'Fresh output required')
    profile=json.loads((f.REPO/'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        dev=o.cdc(o.Host().inventory())
        o.require(dev and o.normalize_location(dev['location'])==profile['location'],'Approved live CDC absent')
        out.mkdir(parents=True);transport=None
        with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                events.write(json.dumps(dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields))+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','PROGRESS','DONE','STOP'):print(phase,fields,flush=True)
            try:
                transport=f.WinTransport(dev['port'],record);s=f.Session(transport,symbols.tag,record,capture,timeout=20)
                s.handshake();k=m.Kernel(s,symbols)
                def identity(raw):
                    g=re.search(rb'proc\s+(\d+)\s+backboardd.*?task=(0x[0-9a-f]+)',raw)
                    o.require(g is not None,'Backboard absent')
                    return int(g[1]),int(g[2],16)
                _,raw=s.command('ports backboardd');(out/'before-ports.txt').write_bytes(raw)
                pid,task=identity(raw)
                o.require(pid==ctx['pid'] and task==int(ctx['task'],16),'Backboard context replaced')
                mapva=k.u32(task+0x18);pmapva=k.u32(mapva+0x2c)
                o.require(mapva==int(ctx['map'],16) and pmapva==int(ctx['pmap'],16),'Backboard map replaced')
                user=k.user_pmap(pmapva);cache={}
                def cached(va,size):
                    result=bytearray()
                    while size:
                        page=va&~4095;n=min(size,4096-(va&4095))
                        if page not in cache:
                            cache[page]=k.read(page,4096)
                            (out/f'kernel-page-{page:08x}.bin').write_bytes(cache[page])
                        result.extend(cache[page][va&4095:(va&4095)+n]);va+=n;size-=n
                    return bytes(result)
                header=cached(mapva,48);node=u32(header,16);sentinel=mapva+12
                ranges=[];seen=set();truncated=False
                for _ in range(1024):
                    if node==sentinel:break
                    o.require(node and node not in seen and 0x80000000<=node<0xffff0000 and not node&3,'VM list changed')
                    seen.add(node);entry=cached(node,48)
                    start,end=u32(entry,8),u32(entry,12);bits=u32(entry,40)
                    # The ARM map also lists commpage aliases immediately
                    # above 0x40000000. They are valid entries, but never scanned.
                    o.require(start<end<=0xffffffff,'Invalid VM entry')
                    ranges.append(dict(node=hex(node),start=start,end=end,protection=(bits>>7)&7,submap=bool(bits&2)))
                    node=u32(entry,4)
                else:truncated=True
                (out/'ranges.json').write_text(json.dumps(ranges,indent=2)+'\n')
                matches=[];scanned=0;missing=0;pages={};needle=struct.pack('<I',expected)
                # Ordinary heap/plugin allocations only; image text, dyld
                # cache and user stacks are excluded from this bounded pass.
                for region in ranges:
                    if region['submap'] or region['protection']!=3 or region['start']>=a.end or region['end']<=a.start:continue
                    for page in range(max(region['start'],a.start)&~4095,min(region['end'],a.end),4096):
                        if scanned>=a.max_pages:break
                        try:physical=user.translate(page)
                        except m.MappingError:missing+=1;continue
                        data=k.read_phys(physical,4096);pages[page]=data;scanned+=1
                        (out/f'user-page-{page:08x}.bin').write_bytes(data)
                        begin=0
                        while True:
                            at=data.find(needle,begin)
                            if at<0:break
                            begin=at+4
                            if at&3:continue
                            address=page+at
                            try:obj=user.read(address,0x9c)
                            except m.MappingError:continue
                            if u32(obj)!=expected or u32(obj,20)!=address:continue
                            queue=u32(obj,72);length=u32(obj,76)
                            if not (4096<=queue<0x40000000 and 4108<=length<=8192):continue
                            row=dict(address=hex(address),service_port=hex(u32(obj,24)),connection=hex(u32(obj,28)),
                                opened=obj[32],notification=hex(u32(obj,36)),callback=hex(u32(obj,60)),
                                target=hex(u32(obj,64)),refcon=hex(u32(obj,68)),queue=hex(queue),queue_bytes=length,
                                vtable=hex(expected),sha256=hashlib.sha256(obj).hexdigest())
                            (out/f'plugin-{address:08x}.bin').write_bytes(obj);matches.append(row)
                        if scanned%64==0:record('PROGRESS',pages=scanned,matches=len(matches))
                    if scanned>=a.max_pages:truncated=True;break
                _,after=s.command('ports backboardd');(out/'after-ports.txt').write_bytes(after)
                o.require(identity(after)==(pid,task),'Backboard replaced during scan')
                result=dict(tag=symbols.tag,pid=pid,task=hex(task),slide=hex(slide),vtable=hex(expected),
                    vm_entries=len(ranges),pages=scanned,unmaterialized=missing,capped=truncated,matches=matches,
                    interval=[hex(a.start),hex(a.end)],
                    snapshot='non-atomic read-only scan; no target execution or memory writes')
                (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
                record('DONE')
            except BaseException as e:record('STOP',error=str(e));raise
            finally:
                if transport is not None:transport.close()
if __name__=='__main__':main()
