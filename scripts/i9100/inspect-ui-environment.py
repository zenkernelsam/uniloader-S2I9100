#!/usr/bin/env python3
"""Read original iOS6 process startup environment on one verified handle.

The original __NSGetEnviron instructions determine its storage address. Only
CLASSIC and standard path/library settings are retained; other values are
omitted. No target writes, serial retries, UI actions or process actions.
"""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('env_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)

def capture(session,kernel,symbols,name,reference,out):
    def require(ok,message):b.o.require(ok,message)
    def identity(raw):
        found=re.search(rb'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)',raw)
        require(found is not None,'Process missing');return int(found[1]),int(found[2],16)
    _,raw=session.command('ports '+name);(out/(name+'-ports-before.txt')).write_bytes(raw)
    pid,task=identity(raw);mapva=kernel.u32(task+0x18);pmap=kernel.u32(mapva+0x2c);user=kernel.user_pmap(pmap)
    ptr,size=struct.unpack('<2I',kernel.read(task+0x210,8))
    require(4096<=ptr<=0x3fffffac and size>=84,'Invalid current dyld info')
    info=struct.unpack('<21I',user.read(ptr,84));slide=info[20]
    require(12<=info[0]<=15 and not slide&4095 and slide<=0x0375b000,'Invalid original cache slide')
    accessor=next(x for x in reference['images'] if x['symbol']=='__NSGetEnviron')
    expected=bytes.fromhex(accessor['bytes'])[:16];address=int(accessor['address'],16)+slide
    require(expected==bytes.fromhex('49f60060c0f2b61078448068704700bf'),'Unknown original environment accessor')
    require(user.read(address,16)==expected,'Original environment accessor changed')
    image=int(accessor['image_base'],16)+slide;mh=struct.unpack('<7I',user.read(image,28))
    require(mh[0]==0xfeedface and mh[1]==12 and mh[4]<=128 and 24<=mh[5]<=16384,'Unknown libc image')
    at=image+28;end=at+mh[5];uuid=None
    for _ in range(mh[4]):
        require(at<=end-8,'Truncated image commands');cmd,length=struct.unpack('<2I',user.read(at,8))
        require(8<=length<=end-at,'Unbounded image command')
        if cmd==27:
            require(length==24,'Unknown UUID command');uuid=user.read(at+8,16).hex()
        at+=length
    require(uuid==accessor['uuid'],'Original libc UUID changed')
    # movw #0x9e00; movt #0x1b6; add r0,pc; ldr r0,[r0,#8].
    storage=(int(accessor['address'],16)+12+0x01b69e00+8)+slide
    pointer=kernel_env=struct.unpack('<I',user.read(storage,4))[0]
    require(4096<=pointer<=0x3ffffffc and not pointer&3,'Invalid environ storage pointer')
    vector=struct.unpack('<I',user.read(pointer,4))[0]
    require(4096<=vector<=0x3ffffffc and not vector&3,'Invalid environment vector')
    safe={'CLASSIC','HOME','PATH','TMPDIR','IPHONE_SHARED_RESOURCES_DIRECTORY','DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH'}
    rows=[];terminated=False
    def string(v):
        require(4096<=v<0x40000000,'Invalid environment string pointer');parts=bytearray()
        while len(parts)<1024:
            n=min(64,4096-(v&4095),1024-len(parts));chunk=user.read(v,n)
            zero=chunk.find(b'\0')
            if zero>=0:return bytes(parts+chunk[:zero]).decode('utf-8','strict')
            parts+=chunk;v+=n
        raise ValueError('Environment string exceeds diagnostic bound')
    for index in range(256):
        v=struct.unpack('<I',user.read(vector+index*4,4))[0]
        if not v:terminated=True;break
        text=string(v);key,sep,value=text.partition('=')
        require(sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key),'Malformed environment key')
        rows.append(dict(key=key,**({'value':value} if key in safe else {'value_omitted':True})))
    require(terminated,'Environment vector exceeds diagnostic bound')
    _,after=session.command('ports '+name);(out/(name+'-ports-after.txt')).write_bytes(after)
    require(identity(after)==(pid,task) and kernel.u32(task+0x18)==mapva and
        struct.unpack('<I',user.read(storage,4))[0]==kernel_env and
        struct.unpack('<I',user.read(pointer,4))[0]==vector,'Process/environment identity changed')
    return dict(process=name,pid=pid,task=hex(task),slide=hex(slide),accessor=hex(address),
        storage=hex(storage),environ_pointer=hex(pointer),vector=hex(vector),libc_uuid=uuid,
        environment=rows,sequential=True,target_writes=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--process',action='append',required=True);a=p.parse_args()
    for name in a.process:b.f.validate_command('ports '+name)
    symbols=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'))
    reference=json.loads(b.o.confined(a.reference,b.o.ROOT/'research').read_text())
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields);events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','DONE','STOP'):print(json.dumps(row),flush=True)
            try:
                result=dict(tag=symbols.tag,processes=[])
                with b.open_session(dev,symbols.tag,out,record,300) as session:
                    kernel=b.m.Kernel(session,symbols)
                    for name in a.process:
                        result['processes'].append(capture(session,kernel,symbols,name,reference,out))
                        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                record('DONE');print(json.dumps(result,indent=2),flush=True)
            except BaseException as error:record('STOP',error=str(error),retry=False);raise
if __name__=='__main__':main()
