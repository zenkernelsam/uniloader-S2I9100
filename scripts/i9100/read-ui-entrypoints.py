#!/usr/bin/env python3
"""Read observed Setup delegate entry bytes on one bounded native handle."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('entry_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--bytes',type=int,choices=(64,512,2048),default=64)
    p.add_argument('--controller',action='store_true',help='Read actual callback receiver, class ivars and index path')
    p.add_argument('--executable',type=Path,help='UUID-matched original executable resolves nonresident metadata')
    p.add_argument('--related',action='store_true',help='Read controller delegate, parent and navigation item')
    p.add_argument('--navigation-children',action='store_true',help='Read actual next-button item and view arrays');a=p.parse_args()
    executable=None
    if a.executable:
        path=b.o.confined(a.executable,b.f.REPO.parent)
        executable=b.module('entry_reference','objc-image.py').MachImage(path,'580dfd1edbd53d33844bca6635c0b3cd')
    sy=b.m.Symbols(a.kernel);e=json.loads(a.evidence.read_text());b.o.require(e['tag']==sy.tag,'Observed BUILD differs')
    observed=e.get('observations',e).get('ui_execution')
    callback=None
    if observed:
        d=observed['diagnostic'];callback=next(x for x in reversed(observed['rows']) if x['phase']==9 and x['current_installation'])
        e.update(pid=d['pid'],task=hex(d['task']),idversion=d['idversion'])
        methods=[dict(selector='tableView:didSelectRowAtIndexPath:',address=hex(d['header']+0xef18))]
    else:
        methods=[m for c in e['classes'].values() if c['name']=='BuddyLanguageController' for m in c['methods']
                 if m['selector']=='tableView:didSelectRowAtIndexPath:']
    b.o.require(not a.controller or callback is not None,'Controller requires an executed language callback')
    b.o.require(len(methods)==1,'Exact observed language delegate absent')
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**kw):
                v=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw);events.write(json.dumps(v)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','DONE','STOP'):print(json.dumps(v),flush=True)
            try:
                with b.open_session(dev,sy.tag,out,record,240 if a.controller else 120) as session:
                    k=b.m.Kernel(session,sy);d=struct.unpack('<32I',k.read(sy['_i9100_ui_execution_diag'],128))
                    b.o.require((d[2],d[3],d[12])==(e['pid'],int(e['task'],16),e['idversion']),'Observed Setup replaced')
                    user=k.user_pmap(k.u32(k.u32(d[3]+0x18)+0x2c));mh=user.read(d[4],4096);(out/'image-header.bin').write_bytes(mh)
                    header=struct.unpack_from('<7I',mh);b.o.require(header[0]==0xfeedface and header[1]==12 and header[3]==2,'Observed image not ARM executable')
                    at=28;uuid=None
                    for _ in range(header[4]):
                        cmd,n=struct.unpack_from('<2I',mh,at);b.o.require(n>=8 and at+n<=len(mh),'Unbounded executable commands')
                        if cmd==27:
                            uuid=mh[at+8:at+24].hex();break
                        at+=n
                    b.o.require(uuid=='580dfd1edbd53d33844bca6635c0b3cd','Original Setup UUID differs')
                    rows=[]
                    for m in methods:
                        address=int(m['address'],16)&~1;b.o.require(d[4]<=address<d[4]+0x200000,'Delegate outside observed executable')
                        raw=user.read(address,a.bytes);(out/(m['selector'].replace(':','_')+'.bin')).write_bytes(raw)
                        rows.append(dict(selector=m['selector'],address=hex(address),executable_offset=hex(address-d[4]),bytes=raw.hex()))
                        if observed:
                            jump=struct.pack('<2I',0xf000f8df,d[5]+8*64+1)
                            b.o.require(raw[:8]==jump,'Observed delegate entry no longer matches installed observer')
                            replay=user.read(d[5]+8*64+36,8);b.o.require(replay==bytes.fromhex('f0b503af2de9000d'),'Observed replay differs from original prologue')
                            (out/'delegate-original.bin').write_bytes(replay+raw[8:])
                            if executable:
                                b.o.require(executable.read(address-d[4]+executable.base,a.bytes)==replay+raw[8:],
                                    'Original executable callback differs from observed bytes')
                    objects={}
                    if a.controller:
                        with b.module('entry_hierarchy','inspect-ui-hierarchy.py').OriginalStrings() as original:
                            metadata={}
                            def meta_read(at,n):
                                b.o.require(4096<=at<at+n<=0x40000000 and 0<n<=4096,'Metadata outside user space')
                                value=bytearray()
                                while n:
                                    page=at&~4095;off=at&4095;count=min(n,4096-off)
                                    if page not in metadata:
                                        metadata[page]=user.read(page,4096);(out/f'metadata-{page:08x}.bin').write_bytes(metadata[page])
                                    value.extend(metadata[page][off:off+count]);at+=count;n-=count
                                return bytes(value)
                            def word(at,meta=True):return struct.unpack('<I',meta_read(at,4) if meta else user.read(at,4))[0]
                            def string(at):
                                try:return original.string(at-d[31])
                                except ValueError:
                                    if executable:
                                        try:return executable.string(at-d[4]+executable.base)
                                        except ValueError:pass
                                    return meta_read(at,min(128,4096-(at&4095))).split(b'\0')[0].decode('utf-8','strict')
                            def cls(isa):
                                data=word(isa+16)&~3;ro=word(data+8) if word(data)&0x80000000 else data
                                values=struct.unpack('<10I',meta_read(ro,40))
                                return dict(isa=hex(isa),name=string(values[4]),size=values[2],superclass=word(isa+4),ivars=values[7])
                            def obj(address,label):
                                c=cls(word(address,False));b.o.require(4<=c['size']<=4096,'Unknown live object size')
                                raw=user.read(address,c['size']);(out/(label+'.bin')).write_bytes(raw)
                                value=dict(address=hex(address),class_name=c['name'],bytes=len(raw),classes=[],fields={})
                                objects[label]=value
                                for _ in range(12):
                                    value['classes'].append(c['name']);iv=c['ivars'];packed={}
                                    if iv:
                                        step,count=struct.unpack('<2I',meta_read(iv,8));b.o.require(step==20 and count<=128,'Unknown live ivar list')
                                        for i in range(count):
                                            off,nm,ty,_,size=struct.unpack('<5I',meta_read(iv+8+i*step,20));off=word(off);name,kind=string(nm),string(ty)
                                            bit=re.fullmatch(r'b([0-9]+)',kind);shift=packed.get(off,0)
                                            if bit:
                                                width=int(bit[1]);size=(shift+width+7)//8;packed[off]=shift+width
                                            b.o.require(0<size<=64 and off+size<=len(raw),'Live field outside actual instance '+name)
                                            data=raw[off:off+size];item=dict(offset=off,size=size,type=kind,hex=data.hex())
                                            if size<=4:item['value']=int.from_bytes(data,'little')
                                            if bit:item['value']=(int.from_bytes(data,'little')>>shift)&((1<<width)-1)
                                            value['fields'][c['name']+':'+name]=item
                                            (out/'objects-partial.json').write_text(json.dumps(objects,indent=2)+'\n')
                                    if not c['superclass']:break
                                    c=cls(c['superclass'])
                                else:raise ValueError('Class depth exceeds bounded limit')
                                objects[label]=value;(out/'objects-partial.json').write_text(json.dumps(objects,indent=2)+'\n');return value
                            receiver=obj(callback['arguments'][0],'controller')
                            b.o.require(receiver['class_name']=='BuddyLanguageController','Executed receiver class changed')
                            # The index path is autoreleased after the callback.
                            # Its execution-time bytes are already in the ring;
                            # dereferencing that old address can inspect reused memory.
                            for name,item in receiver['fields'].items():
                                if any(x in name.lower() for x in ('delegate','parentviewcontroller','navigationcontroller','flowcontroller','navigationitem')) and item.get('value'):
                                    address=item['value']
                                    if item['type'].startswith('@') and 4096<=address<=0x3ffff000:
                                        target=cls(word(address,False));item['object_class']=target['name'];item['object_isa']=target['isa']
                                        if a.related and any(x in name.lower() for x in ('_delegate','_parentviewcontroller','_navigationitem')):
                                            label='related-'+name.split(':')[-1].lstrip('_')
                                            obj(address,label)
                            if a.navigation_children:
                                b.o.require(a.related,'Navigation children require related objects')
                                nav=objects['related-navigationItem']
                                def array_values(address):
                                    c=cls(word(address,False));header=user.read(address,24);used=struct.unpack_from('<I',header,4)[0]
                                    b.o.require(used<=8,'Navigation array outside bounded size')
                                    if c['name']=='__NSArrayI':
                                        return struct.unpack('<'+'I'*used,user.read(address+8,used*4)) if used else []
                                    if c['name']=='__NSArrayM':
                                        capacity,off,pointer=struct.unpack_from('<3I',header,8)[0],struct.unpack_from('<I',header,12)[0],struct.unpack_from('<I',header,20)[0]
                                        capacity>>=2;off>>=2;b.o.require(used<=capacity<=128 and off<capacity,'Unknown mutable navigation array')
                                        data=user.read(pointer,capacity*4)
                                        return [struct.unpack_from('<I',data,((off+i)%capacity)*4)[0] for i in range(used)]
                                    raise ValueError('Unsupported navigation array '+c['name'])
                                for key in ('_rightBarButtonItems','_customRightViews'):
                                    address=nav['fields']['UINavigationItem:'+key]['value']
                                    if address:
                                        for i,pointer in enumerate(array_values(address)):obj(pointer,'navigation-'+key.lstrip('_')+'-'+str(i))
                                address=nav['fields']['UINavigationItem:_navigationBar']['value']
                                if address:obj(address,'navigation-bar')
                    current=struct.unpack('<32I',k.read(sy['_i9100_ui_execution_diag'],128))
                    b.o.require((current[2],current[3],current[12])==(d[2],d[3],d[12]),'Setup identity changed')
                    result=dict(tag=sy.tag,pid=d[2],task=hex(d[3]),header=hex(d[4]),uuid=uuid,sites=rows,objects=objects,
                        original_executable_sha256=executable.sha256 if executable else None)
                    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
                record('DONE')
            except BaseException as error:record('STOP',error=str(error),retry=False);raise
if __name__=='__main__':main()
