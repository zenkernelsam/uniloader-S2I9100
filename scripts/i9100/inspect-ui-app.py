#!/usr/bin/env python3
"""Read the original UIApplication singleton and interaction flags, without writes."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('ui_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
def identity(raw):
    m=re.search(rb'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)',raw)
    b.o.require(m is not None,'Process missing')
    return int(m[1]),int(m[2],16)
def capture(session,kernel,symbols,name,layout,out,flags_only=False):
    _,raw=session.command('ports '+name);(out/'ports-before.txt').write_bytes(raw)
    pid,task=identity(raw);mapva=kernel.u32(task+0x18);pmap=kernel.u32(mapva+0x2c);user=kernel.user_pmap(pmap)
    ptr,size=struct.unpack('<2I',kernel.read(task+0x210,8))
    b.o.require(4096<=ptr<=0x3fffffac and size>=84,'Invalid current dyld info')
    info=user.read(ptr,84);v=struct.unpack('<21I',info);slide=v[20]
    b.o.require(12<=v[0]<=15 and not slide&4095 and slide<=0x0375b000,'Original iOS6 cache slide invalid')
    gl=next(int(x['address'],16) for x in layout['globals'] if x['name']=='_UIApp')+slide
    app=struct.unpack('<I',user.read(gl,4))[0]
    b.o.require(4096<=app<=0x3fffff80 and not app&3,'UIApplication absent')
    obj=user.read(app,116);(out/'application.bin').write_bytes(obj)
    cls=struct.unpack_from('<I',obj)[0];chain=[];base=int(layout['classes']['UIApplication']['class_address'],16)+slide
    for _ in range(12):
        chain.append(hex(cls))
        if cls==base:break
        b.o.require(4096<=cls<=0x3fffffec and not cls&3,'Unknown class pointer')
        cls=struct.unpack_from('<I',user.read(cls,8),4)[0]
    else:raise ValueError('Not an UIApplication subclass')
    meta=layout['classes']['UIApplication'];ivars={}
    for x in meta['ivars']:
        at=x['offset'];n=x['size']
        if at+n>len(obj):raise ValueError('Ivar outside original instance')
        ivars[x['name']]=int.from_bytes(obj[at:at+n],'little') if n<=4 else obj[at:at+n].hex()
    flags=int.from_bytes(obj[88:101],'little');fields={}
    for x in meta['bitfields']['_applicationFlags']:
        fields[x['name']]=(flags>>x['bit'])&((1<<x['width'])-1)
    result=dict(tag=symbols.tag,process=name,pid=pid,task=hex(task),map=hex(mapva),pmap=hex(pmap),slide=hex(slide),application=hex(app),
                class_chain=chain,ivars=ivars,flags=fields,flags_hex=obj[88:101].hex(),snapshot='read-only sequential state')
    if flags_only:
        _,after=session.command('ports '+name);(out/'ports-after.txt').write_bytes(after)
        b.o.require(identity(after)==(pid,task) and kernel.u32(task+0x18)==mapva and struct.unpack('<I',user.read(gl,4))[0]==app,'Application identity changed')
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
    for key in ('_event','_touchesEvent','_touchMap'):
        address=ivars[key]
        if 4096<=address<=0x3fffff80:
            data=user.read(address,128);(out/(key.strip('_')+'.bin')).write_bytes(data)
            result[key.strip('_')+'_words']=[hex(x) for x in struct.unpack('<32I',data)]
    if 'UITouch' in layout['classes'] and 'UITouchesEvent' in layout['classes']:
        event=ivars['_touchesEvent'];touches=[];containers=[]
        def classname(cptr):
            q=struct.unpack('<5I',user.read(cptr,20))[4]&~3
            rw=struct.unpack('<3I',user.read(q,12));ro=rw[2] if rw[0]&0x80000000 else q
            nm=struct.unpack_from('<I',user.read(ro,20),16)[0]
            return user.read(nm,96).split(b'\0')[0].decode('utf-8','replace')
        eobj=user.read(event,32)
        addresses=[ivars['_touchMap']]+list(struct.unpack_from('<4I',eobj,16))
        found=set()
        for cptr in dict.fromkeys(addresses):
            if not 4096<=cptr<=0x3fffffc0:continue
            raw=user.read(cptr,36);idx=raw[11];sizes=(0,3,7,13,23,41,71,127)
            row=dict(address=hex(cptr),header=raw.hex(),class_name=classname(struct.unpack_from('<I',raw)[0]));containers.append(row)
            if not 0<idx<len(sizes):continue
            count=sizes[idx];values=struct.unpack_from('<I',raw,28)[0]
            if not 4096<=values<=0x3fffffff-count*4:continue
            vals=struct.unpack('<'+'I'*count,user.read(values,count*4));row['values']=[hex(v) for v in vals]
            for t in vals:
                if t in found or not 4096<=t<=0x3fffffb0:continue
                cls=struct.unpack('<I',user.read(t,4))[0]
                if cls!=int(layout['classes']['UITouch']['class_address'],16)+slide:continue
                found.add(t);raw=user.read(t,80);(out/f'touch-{t:08x}.bin').write_bytes(raw)
                item=dict(address=hex(t),phase=struct.unpack_from('<I',raw,16)[0],tap_count=struct.unpack_from('<I',raw,24)[0],
                    window=hex(struct.unpack_from('<I',raw,28)[0]),view=hex(struct.unpack_from('<I',raw,32)[0]),
                    location=list(struct.unpack_from('<2f',raw,52)),previous_location=list(struct.unpack_from('<2f',raw,60)),
                    path_index=raw[68],path_identity=raw[69],flags=raw[76],eaten=raw[77])
                view=int(item['view'],16);win=int(item['window'],16)
                if view:
                    item['view_class']=classname(struct.unpack('<I',user.read(view,4))[0])
                    (out/f'view-{view:08x}.bin').write_bytes(user.read(view,84))
                if win:
                    wobj=user.read(win,196);(out/f'window-{win:08x}.bin').write_bytes(wobj)
                    screen=struct.unpack_from('<I',wobj,132)[0]
                    item['window_class']=classname(struct.unpack_from('<I',wobj)[0])
                    if screen:
                        sc=user.read(screen,40);(out/f'screen-{screen:08x}.bin').write_bytes(sc)
                        item['screen']=dict(address=hex(screen),bounds=list(struct.unpack_from('<4f',sc,8)),scale=struct.unpack_from('<f',sc,24)[0])
                touches.append(item)
        result.update(touch_containers=containers,ui_touches=touches)
    _,after=session.command('ports '+name);(out/'ports-after.txt').write_bytes(after)
    b.o.require(identity(after)==(pid,task) and kernel.u32(task+0x18)==mapva and struct.unpack('<I',user.read(gl,4))[0]==app,'Application identity changed')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--process',default='Setup');p.add_argument('--layout',type=Path,required=True)
    p.add_argument('--flags-only',action='store_true',help='Read only identity and native interaction flags');a=p.parse_args()
    b.f.validate_command('ports '+a.process);sy=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'));layout=json.loads(a.layout.read_text())
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh output required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC missing')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**kw):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw);events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','STOP','DONE'):print(json.dumps(row),flush=True)
            try:
                with b.open_session(dev,sy.tag,out,record,180) as session:
                    result=capture(session,b.m.Kernel(session,sy),sy,a.process,layout,out,flags_only=a.flags_only)
                    print(json.dumps(result,indent=2),flush=True)
                record('DONE')
            except BaseException as e:record('STOP',error=str(e),retry=False);raise
if __name__=='__main__':main()
