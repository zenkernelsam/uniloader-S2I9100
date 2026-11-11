#!/usr/bin/env python3
"""Read the real mapped touch queue through matching, validated kernel objects.

No writes or synthetic input. Layout must name this exact BUILD; vtables,
queue bounds, PID and before/after queue geometry are checked.
"""
import argparse
from datetime import datetime,timezone
import hashlib,importlib.util,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def u32(data,at=0):return struct.unpack_from('<I',data,at)[0]
def pointer(value):return 0x80000000<=value<0xffff0000 and not value&3
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--layout',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();f=module('wire_forensic','forensic-session.py')
    m=module('wire_memory','live-memory.py');o=module('wire_odin','odin-loop.py')
    symbols=m.Symbols(a.kernel);layout=json.loads(a.layout.read_text())
    o.require(layout['kernel_tag']==symbols.tag,'Layout must match this exact kernel')
    out=o.confined(a.output,f.REPO/'out');o.require(not out.exists(),'Fresh output required')
    vt={k:symbols[s] for k,s in {'client':'__ZTV21IOS7LeoHIDTouchClient',
        'service':'__ZTV17IOHIDEventService','queue':'__ZTV15IOS7LeoHIDQueue',
        'set':'__ZTV5OSSet','array':'__ZTV7OSArray','map':'__ZTV11IOMemoryMap'}.items()}
    profile=json.loads((f.REPO/'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True);transport=None
        with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                events.write(json.dumps(dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields))+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','DONE','STOP'):print(phase,fields,flush=True)
            try:
                transport=f.WinTransport(device['port'],record)
                session=f.Session(transport,symbols.tag,record,capture,timeout=20)
                session.handshake();k=m.Kernel(session,symbols)
                _,raw=session.command('ports backboardd');(out/'before-ports.txt').write_bytes(raw)
                pid=int(re.search(rb'proc\s+(\d+)\s+',raw)[1])
                task=int(re.search(rb'task=(0x[0-9a-f]+)',raw)[1],16)
                user=k.user_pmap(k.u32(k.u32(task+0x18)+0x2c))
                objects=re.findall(rb'pn=([0-9a-f]+) rt=send obj=(0x[0-9a-f]+)',raw)
                results=[];seen=set()
                for name,obj in objects[:256]:
                    port=int(obj,16)
                    header=k.read(port,0x60)
                    if not (u32(header)&0x80000000) or not (u32(header)&0x3ff):continue
                    client=u32(header,0x5c)
                    if not pointer(client):continue
                    try:client_vt=k.u32(client)
                    except m.MappingError:continue
                    if client_vt!=vt['client']+8:continue
                    service=k.u32(client+layout['client_service'])
                    o.require(pointer(service) and k.u32(service)==vt['service']+8,'HID service identity changed')
                    if service in seen:continue
                    seen.add(service);s=k.read(service,layout['service_size'])
                    if s[layout['service_home']]:continue
                    o.require(s[layout['service_ios6']]==1,'Not an iOS6 touch queue')
                    q=u32(s,layout['service_queue'])
                    o.require(pointer(q) and k.u32(q)==vt['queue']+8,'Queue identity changed')
                    address=k.u32(q+layout['queue_data']);o.require(pointer(address),'Invalid queue memory')
                    before=k.read(address,12);size,head,tail=struct.unpack('<3I',before)
                    o.require(size==4096 and head<=size and tail<=size and not (head|tail)&3,'Invalid queue geometry')
                    data=k.read(address,12+size);after=k.read(address,12)
                    (out/f'queue-{name.decode()}.bin').write_bytes(data)
                    cached=s[layout['service_cached_packet']:layout['service_cached_packet']+204]
                    (out/f'cached-{name.decode()}.bin').write_bytes(cached)
                    descriptor=u32(s,96);maps=[]
                    mapset=k.u32(descriptor+12)
                    if pointer(mapset):
                        o.require(k.u32(mapset)==vt['set']+8,'Descriptor mapping set changed')
                        array=k.u32(mapset+16);o.require(pointer(array) and k.u32(array)==vt['array']+8,'Mapping array changed')
                        pointers=k.u32(array+16);count=k.u32(array+20)
                        o.require(count<=32 and pointer(pointers),'Unbounded mapping array')
                        for n in range(count):
                            mapped=k.u32(pointers+n*4)
                            o.require(pointer(mapped) and k.u32(mapped)==vt['map']+8,'Memory map identity changed')
                            info=k.read(mapped,40)
                            if u32(info,8)!=descriptor or u32(info,28)!=task:continue
                            at=u32(info,20);length=u32(info,24)
                            o.require(4096<=at<at+length<=0x40000000 and length>=len(data),'Invalid user queue mapping')
                            row=dict(object=hex(mapped),address=hex(at),length=length,
                                task=hex(u32(info,28)),map=hex(u32(info,32)),options=hex(u32(info,36)))
                            (out/f'mapping-{mapped:08x}.bin').write_bytes(info)
                            try:
                                alias=user.read(at,len(data));(out/f'user-queue-{at:08x}.bin').write_bytes(alias)
                                row.update(physical=hex(user.translate(at)),matches_kernel_bytes=alias==data,
                                    sha256=hashlib.sha256(alias).hexdigest())
                            except m.MappingError as e:
                                row.update(materialized=False,error=str(e))
                                prefix_size=min(len(data),4096-(at&4095))
                                try:
                                    prefix=user.read(at,prefix_size)
                                    (out/f'user-queue-prefix-{at:08x}.bin').write_bytes(prefix)
                                    row.update(materialized_prefix=prefix_size,
                                        prefix_matches_kernel=prefix==data[:prefix_size],
                                        physical_prefix=hex(user.translate(at)))
                                except m.MappingError as prefix_error:
                                    row['prefix_error']=str(prefix_error)
                            maps.append(row)
                    results.append(dict(port=name.decode(),client=hex(client),service=hex(service),queue=hex(q),
                        address=hex(address),size=size,head=head,tail=tail,coherent=before==after==data[:12],
                        cache_valid=s[layout['service_cache_valid']],sha256=hashlib.sha256(data).hexdigest(),
                        cached_timestamp=struct.unpack_from('<Q',cached)[0],user_mappings=maps))
                _,after=session.command('ports backboardd');(out/'after-ports.txt').write_bytes(after)
                o.require(int(re.search(rb'proc\s+(\d+)\s+',after)[1])==pid,'Backboard PID changed')
                o.require(results,'No matching touch client was found')
                result=dict(tag=symbols.tag,pid=pid,layout=layout,queues=results,snapshot='read-only; vtable/PID/geometry checked')
                (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps(result,indent=2),flush=True);record('DONE')
            except BaseException as e:record('STOP',error=str(e));raise
            finally:
                if transport is not None:transport.close()
if __name__=='__main__':main()
