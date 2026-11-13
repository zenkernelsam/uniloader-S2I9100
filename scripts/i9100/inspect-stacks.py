#!/usr/bin/env python3
"""Read saved user registers and frame chains from the live kernel page tables.

ARM member offsets are from the matching trap.o DWARF: thread.machine=0x228,
thread.task=0x3a0, machine.uss=4, task.map=0x18, vm_map.pmap=0x2c.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import struct


def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def capture_process(session,kernel,name,out,m,dyld_info=False,thread_limit=None,kernel_context=False):
    _,data=session.command('threads '+name)
    (out/(name+'-threads.txt')).write_bytes(data)
    text=data.decode()
    proc=dict(process=name,threads=[])
    identity=re.search(r'proc\s+(\d+)\s+',text)
    if identity:proc['pid']=int(identity[1])
    current=None
    for line in text.splitlines():
        if ' thr=' in line:
            fields=dict(re.findall(r'([a-z0-9]+)=(0x[0-9a-f]+|[0-9a-f]+)',line))
            current=dict(thread=int(fields['thr'],16),bsd=line.strip())
            proc['threads'].append(current)
        elif ' pc=' in line and current is not None:
            current['wait']=line.strip()
    if not proc['threads']:
        return proc
    if thread_limit is not None:
        proc['observed_thread_count'] = len(proc['threads'])
        proc['thread_limit'] = thread_limit
        proc['threads'] = proc['threads'][:thread_limit]
    task=kernel.u32(proc['threads'][0]['thread']+0x3a0)
    mapva=kernel.u32(task+0x18);pmapva=kernel.u32(mapva+0x2c)
    proc.update(task=hex(task),map=hex(mapva),pmap=hex(pmapva))
    user=kernel.user_pmap(pmapva)
    pages={}
    def user_read(va,n):
        result=bytearray()
        while n:
            page=va&~4095;offset=va&4095;take=min(n,4096-offset)
            if page not in pages:
                pages[page]=user.read(page,4096)
                (out/f'{name}-user-{page:08x}.bin').write_bytes(pages[page])
            result.extend(pages[page][offset:offset+take]);va+=take;n-=take
        return bytes(result)
    if dyld_info:
        try:
            # ARM task offsets are from the matching trap.o DWARF.
            # mach_vm_address_t/size_t are 32-bit in this build.
            address,size=struct.unpack('<2I',kernel.read(task+0x210,8))
            if not 0<address<0x40000000 or not 12<=size<=4096:
                raise m.MappingError('Invalid live dyld header range')
            raw=user_read(address,min(size,84))
            (out/(name+'-dyld-info.bin')).write_bytes(raw)
            words=struct.unpack('<'+str(len(raw)//4)+'I',raw)
            proc['dyld_info']=dict(address=hex(address),size=size,
                version=words[0],image_count=words[1],image_array=hex(words[2]),
                words=[hex(value) for value in words])
            if words[0]>=12 and len(words)>=21:
                proc['dyld_info']['cache_slide']=hex(words[20])
                print(name,'CACHE_SLIDE',hex(words[20]),flush=True)
        except (m.MappingError,struct.error) as exc:
            proc['dyld_info_error']=str(exc)
    for thread in proc['threads']:
        try:
            if kernel_context:
                kss=kernel.u32(thread['thread']+0x228)
                kregs=struct.unpack('<17I',kernel.read(kss,68))
                base=kernel.u32(thread['thread']+0x44)
                evidence=dict(address=hex(kss),stack_base=hex(base),words=[hex(v) for v in kregs],frames=[])
                thread['kernel_context']=evidence
                kfp=kregs[7];seen_kernel=set()
                while base<=kfp<=base+0x3ff8 and kfp not in seen_kernel and not kfp&3 and len(seen_kernel)<20:
                    seen_kernel.add(kfp)
                    previous,return_address=struct.unpack('<2I',kernel.read(kfp,8))
                    evidence['frames'].append(dict(fp=hex(kfp),previous=hex(previous),lr=hex(return_address)))
                    if previous<=kfp:break
                    kfp=previous
                if base<=kregs[13]<=base+0x3f00:
                    raw=kernel.read(kregs[13],256)
                    (out/f'{name}-kernel-stack-{thread["thread"]:08x}.bin').write_bytes(raw)
                    evidence['stack_words']=[hex(v) for v in struct.unpack('<64I',raw)]
            uss=kernel.u32(thread['thread']+0x22c)
            regs=struct.unpack('<17I',kernel.read(uss,68))
            thread.update(uss=hex(uss),registers={**{f'r{i}':hex(regs[i]) for i in range(13)},
                             'sp':hex(regs[13]),'lr':hex(regs[14]),'pc':hex(regs[15]),'cpsr':hex(regs[16])})
            sp=regs[13];fp=regs[7];frames=[];seen=set()
            while fp not in seen and len(frames)<14 and sp<=fp<sp+0x20000 and not fp&3:
                seen.add(fp)
                previous,lr=struct.unpack('<2I',user_read(fp,8))
                frames.append(dict(fp=hex(fp),previous=hex(previous),lr=hex(lr)))
                if previous<=fp:break
                fp=previous
            thread['frames']=frames
            stack=user_read(sp,min(256,4096-(sp&4095)))
            thread['stack_words']=[hex(x) for x in struct.unpack('<'+str(len(stack)//4)+'I',stack)]
            # For mutex/condition waits preserve the live argument's
            # user words; they are evidence, not an owner inference.
            if regs[12] in (301,305) and 0x1000<=regs[0]<0xc0000000:
                try:thread['sync_argument']=[hex(x) for x in struct.unpack('<16I',user_read(regs[0],64))]
                except m.MappingError as exc:thread['sync_argument_error']=str(exc)
            print(name,hex(thread['thread']),hex(regs[15]),'r12='+hex(regs[12]),
                  'frames='+','.join(x['lr'] for x in frames),flush=True)
        except (m.MappingError,struct.error) as exc:
            thread['error']=str(exc);print(name,hex(thread['thread']),'unavailable',str(exc),flush=True)
    return proc


def main():
    here=Path(__file__).resolve().parent
    f=module('forensic',here/'forensic-session.py')
    m=module('memory',here/'live-memory.py')
    odin=module('odin',here/'odin-loop.py')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--process',action='append',required=True)
    p.add_argument('--dyld-info',action='store_true',
                   help='Retain the live ARM dyld header and current shared-cache slide')
    p.add_argument('--kernel-context',action='store_true',help='Retain saved kernel registers and bounded own kernel frame links')
    p.add_argument('--thread-limit',type=int,choices=range(1,65),
                   help='Read only the first N raw snapshot threads; retain the observed total')
    a=p.parse_args();symbols=m.Symbols(a.kernel)
    for name in a.process:f.validate_command('threads '+name)
    out=a.output.resolve()
    if not out.is_relative_to(f.REPO/'out') or out.exists():p.error('Fresh directory in repository out required')
    with odin.host_lock():
        device=odin.cdc(odin.Host().inventory())
        if device is None:raise RuntimeError('No live CDC device')
        profile=json.loads((f.REPO/'out/automation/inventory-20261108-recovery-download.json').read_text(encoding='utf-8'))
        if odin.normalize_location(device['location'])!=profile['location']:raise RuntimeError('Wrong USB topology')
        out.mkdir(parents=True);transport=None
        with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','STOP','DONE'):print(json.dumps(row),flush=True)
            try:
                transport=f.WinTransport(device['port'],record)
                session=f.Session(transport,symbols.tag,record,capture,timeout=20)
                session.handshake();kernel=m.Kernel(session,symbols)
                results=[]
                for name in a.process:
                    proc=capture_process(session,kernel,name,out,m,a.dyld_info,a.thread_limit,a.kernel_context)
                    results.append(proc)
                    (out/'stacks.json').write_text(json.dumps(dict(tag=symbols.tag,processes=results),indent=2)+'\n')
                record('DONE',processes=len(results))
            except BaseException as exc:
                record('STOP',error=str(exc),retry=False);raise
            finally:
                if transport is not None:transport.close()


if __name__=='__main__':main()
