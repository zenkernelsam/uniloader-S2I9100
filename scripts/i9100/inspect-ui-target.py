#!/usr/bin/env python3
"""Read the actual view/window recorded by the original Setup touch handler."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('target_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    sy=b.m.Symbols(a.kernel);j=json.loads(a.evidence.read_text());obs=j['ui_execution'];d=obs['diagnostic']
    b.o.require(sy.tag==json.loads((a.evidence.parent.parent/'result.json').read_text())['tag'],'Input evidence BUILD differs')
    row=next(x for x in reversed(obs['rows']) if x.get('touch',{}).get('view') and x['current_installation'])
    view,win=row['touch']['view'],row['touch']['window'];out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved device absent');out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**kw):
                r=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw);events.write(json.dumps(r)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','STOP','DONE'):print(json.dumps(r),flush=True)
            try:
                with b.open_session(dev,sy.tag,out,record,180) as session:
                    k=b.m.Kernel(session,sy);_,raw=session.command('ports Setup');(out/'ports.txt').write_bytes(raw)
                    m=re.search(rb'proc\s+(\d+)\s+Setup.*?task=(0x[0-9a-f]+)',raw);b.o.require(m and (int(m[1]),int(m[2],16))==(d['pid'],d['task']),'Recorded Setup replaced')
                    mapva=k.u32(d['task']+0x18);pm=k.u32(mapva+0x2c);user=k.user_pmap(pm)
                    def u32(v):return struct.unpack('<I',user.read(v,4))[0]
                    def text(v):return user.read(v,128).split(b'\0')[0].decode('utf-8','replace')
                    def cls(v):
                        c=u32(v);data=u32(c+16)&~3;h=struct.unpack('<3I',user.read(data,12));ro=h[2] if h[0]&0x80000000 else data
                        return dict(isa=hex(c),name=text(u32(ro+16)),instance_size=u32(ro+8))
                    result=dict(tag=sy.tag,pid=d['pid'],task=hex(d['task']),record_sequence=row['sequence'],touch=row['touch'],objects={})
                    for name,v,n in (('view',view,256),('window',win,256)):
                        raw=user.read(v,n);(out/(name+'.bin')).write_bytes(raw);result['objects'][name]=dict(address=hex(v),class_info=cls(v),words=[hex(x) for x in struct.unpack('<'+str(n//4)+'I',raw)])
                    layer=u32(view+4)
                    if layer:
                        raw=user.read(layer,160);(out/'layer.bin').write_bytes(raw);result['objects']['view_layer']=dict(address=hex(layer),class_info=cls(layer),words=[hex(x) for x in struct.unpack('<40I',raw)])
                    _,after=session.command('ports Setup');(out/'ports-after.txt').write_bytes(after)
                    b.o.require(re.search(rb'proc\s+'+str(d['pid']).encode()+rb'\s+Setup',after) is not None and k.u32(d['task']+0x18)==mapva,'Setup identity changed')
                    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
                record('DONE')
            except BaseException as e:record('STOP',error=str(e),retry=False);raise
if __name__=='__main__':main()
