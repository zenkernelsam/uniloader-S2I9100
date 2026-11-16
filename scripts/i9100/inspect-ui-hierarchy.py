#!/usr/bin/env python3
"""Read the view, table and recognizers actually hit by original Setup UIKit.

Only bounded reads on one BUILD-verified handle. UIKit/CoreFoundation geometry
is taken from the matching original cache; unsupported forms stop traversal.
No Objective-C invocation, touch, process resume, memory writes or retry.
"""
import argparse, importlib.util, json, mmap, re, struct
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location('hierarchy_boot', HERE/'capture-boot-snapshot.py')
b = importlib.util.module_from_spec(s); s.loader.exec_module(b)


class OriginalStrings:
    def __enter__(self):
        self.file=(b.f.REPO.parent/'assets/ios6-extract/dyld_cache6_armv7').open('rb')
        self.data=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ)
        b.o.require(self.data[:16].startswith(b'dyld_v1'),'Expected original cache')
        off,count=struct.unpack_from('<2I',self.data,16)
        b.o.require(1<=count<=16,'Unknown original cache mappings')
        self.maps=[struct.unpack_from('<QQQII',self.data,off+n*32) for n in range(count)]
        at=self.offset(0x32f2f000);mh=struct.unpack_from('<7I',self.data,at);at+=28;matched=False
        for _ in range(mh[4]):
            command,size=struct.unpack_from('<2I',self.data,at)
            if command==27:matched=self.data[at+8:at+24].hex()=='ad8b3ad23f413187a178179db39cfa6b'
            at+=size
        b.o.require(matched,'Original UIKit UUID differs');return self
    def offset(self,address,length=1):
        for va,size,off,_,_ in self.maps:
            if length>0 and va<=address and address+length<=va+size and off+address-va+length<=len(self.data):return off+address-va
        raise ValueError('String outside original cache')
    def string(self,address):
        off=self.offset(address);end=self.data.find(b'\0',off,min(off+16384,len(self.data)))
        b.o.require(end>=off,'Unterminated original selector');self.offset(address,end-off+1)
        return self.data[off:end].decode('utf-8','strict')
    def __exit__(self,*args):self.data.close();self.file.close()


def capture(session, kernel, symbols, layout, observation, out, original):
    obs = observation['ui_execution']; d = obs['diagnostic']
    b.o.require(d['state'] == 2, 'Original Setup observation absent')
    row = next(x for x in reversed(obs['rows']) if x.get('touch', {}).get('view') and x['current_installation'])
    _, raw = session.command('ports Setup'); (out/'ports-before.txt').write_bytes(raw)
    match = re.search(rb'proc\s+(\d+)\s+Setup.*?task=(0x[0-9a-f]+)', raw)
    b.o.require(match and (int(match[1]), int(match[2], 16)) == (d['pid'], d['task']), 'Recorded Setup replaced')
    mapva = kernel.u32(d['task']+0x18); user = kernel.user_pmap(kernel.u32(mapva+0x2c))
    classes = {}; objects = {}; arrays = {}; seen = set()
    result = dict(tag=symbols.tag, pid=d['pid'], idversion=d['idversion'], task=hex(d['task']),
                  record_sequence=row['sequence'], touch=row['touch'], classes=classes,
                  objects=objects, arrays=arrays, hierarchy=[], recognizers=[], snapshot='read-only sequential state')

    def save(): (out/'partial.json').write_text(json.dumps(result, indent=2)+'\n')
    def read(address, size):
        b.o.require(4096 <= address <= 0x40000000-size and 0 < size <= 4096, 'Object outside bounded user space')
        return user.read(address, size)
    def u32(address): return struct.unpack('<I', read(address, 4))[0]
    def text(address):
        try:return original.string(address-d['cache_slide'])
        except ValueError:return read(address,128).split(b'\0')[0].decode('utf-8','strict')
    def classinfo(address):
        if hex(address) in classes: return classes[hex(address)]
        data = u32(address+16) & ~3; header = struct.unpack('<3I', read(data, 12))
        ro = header[2] if header[0] & 0x80000000 else data
        w = struct.unpack('<10I', read(ro, 40)); name = text(w[4])
        b.o.require(4 <= w[2] <= 4096, 'Unknown original instance geometry')
        value = dict(address=hex(address), name=name, instance_size=w[2], superclass=hex(u32(address+4)), method_list=hex(w[5]), methods=[])
        classes[hex(address)] = value; return value
    def methods(value):
        pointer=int(value['method_list'],16)
        if pointer and not value['methods']:
            flags, count = struct.unpack('<2I', read(pointer, 8)); step = (flags & 0xffff) & ~3
            b.o.require(12 <= step <= 32 and count <= 1024, 'Unknown live method list')
            for start in range(0, count, 32):
                n = min(32, count-start); data = read(pointer+8+start*step, n*step)
                for i in range(n):
                    sel, _, imp = struct.unpack_from('<3I', data, i*step)
                    selector = text(sel)
                    if any(x in selector.lower() for x in ('select', 'touch', 'language', 'gesture', 'tableview')):
                        native=(imp&~1)-d['cache_slide']
                        value['methods'].append(dict(selector=selector,address=hex(imp),
                            original_cache_address=hex(native) if native>=0x30000000 else None,
                            executable_offset=hex((imp&~1)-d['header']) if (imp&~1)<0x30000000 else None))
    def objectinfo(address):
        if hex(address) in objects: return objects[hex(address)]
        c = classinfo(u32(address)); data = read(address, c['instance_size'])
        (out/f'object-{address:08x}.bin').write_bytes(data)
        obj = dict(address=hex(address), class_name=c['name'], isa=c['address'], bytes=len(data), ivars={}, flags={})
        chain=[]; cur=c
        for _ in range(12):
            chain.append(cur['name']); meta=layout['classes'].get(cur['name'])
            if meta:
                b.o.require(int(meta['class_address'],16)+d['cache_slide']==int(cur['address'],16), 'Live class differs from original cache')
                packed={}
                for iv in meta['ivars']:
                    at,n=iv['offset'],iv['size']
                    width=re.fullmatch(r'b([0-9]+)',iv.get('type') or '')
                    if width:
                        bit=packed.get(at,0);width=int(width[1]);n=(bit+width+7)//8;packed[at]=bit+width
                        b.o.require(at+n<=len(data),'Packed original ivar outside live instance '+cur['name']+':'+iv['name'])
                        obj['ivars'][iv['name']]=(int.from_bytes(data[at:at+n],'little')>>bit)&((1<<width)-1)
                    else:
                        b.o.require(at+n<=len(data),'Original ivar outside live instance '+cur['name']+':'+iv['name'])
                        part=data[at:at+n]; obj['ivars'][iv['name']]=int.from_bytes(part,'little') if n<=4 else part.hex()
                for field,entries in meta['bitfields'].items():
                    iv=next(x for x in meta['ivars'] if x['name']==field); bits=int.from_bytes(data[iv['offset']:iv['offset']+iv['size']],'little')
                    obj['flags'][field]={x['name']:(bits>>x['bit'])&((1<<x['width'])-1) for x in entries}
            sup=int(cur['superclass'],16)
            if not sup: break
            cur=classinfo(sup)
        else: raise ValueError('Class hierarchy outside bounded depth')
        obj['class_chain']=chain; objects[hex(address)]=obj; save(); return obj
    def array(address):
        if not address: return []
        if hex(address) in arrays: return [int(x,16) for x in arrays[hex(address)]['values']]
        c=classinfo(u32(address)); header=read(address,24); count=struct.unpack_from('<I',header,4)[0]
        b.o.require(count<=32,'Array exceeds live traversal budget')
        if c['name']=='__NSArrayI':
            vals=list(struct.unpack('<'+'I'*count,read(address+8,count*4))) if count else []
        elif c['name']=='__NSArrayM':
            capacity,offset=struct.unpack_from('<2I',header,8); capacity>>=2; offset>>=2; pointer=struct.unpack_from('<I',header,20)[0]
            b.o.require(count<=capacity<=128 and (offset<capacity or not capacity),'Unknown mutable array geometry')
            data=read(pointer,capacity*4) if capacity else b''
            vals=[struct.unpack_from('<I',data,((offset+i)%capacity)*4)[0] for i in range(count)]
        else: raise ValueError('Unsupported recognizer array '+c['name'])
        b.o.require(read(address,24)==header,'Recognizer array changed during read')
        arrays[hex(address)]=dict(class_name=c['name'],header=header.hex(),values=[hex(x) for x in vals]);return vals
    def recognizer(address):
        if not address or address in seen: return
        seen.add(address); obj=objectinfo(address)
        if 'UIGestureRecognizer' not in obj['class_chain']: raise ValueError('Recognizer array contains different object')
        result['recognizers'].append(hex(address))

    address=row['touch']['view']
    for _ in range(12):
        if not address: break
        b.o.require(hex(address) not in result['hierarchy'],'View hierarchy cycle')
        obj=objectinfo(address);result['hierarchy'].append(hex(address))
        for r in array(obj['ivars'].get('_gestureRecognizers',0)): recognizer(r)
        for key in ('_pan','_pinch','_swipe','_swipeGestureRecognizer','_gobblerGestureRecognizer','_longPressGestureRecognizer'):
            recognizer(obj['ivars'].get(key,0))
        delegate=obj['ivars'].get('_delegate',0)
        if delegate:
            actor=objectinfo(delegate);methods(classes[actor['isa']])
        table=obj['ivars'].get('_tableView',0)
        if table: result['table_from_cell']=hex(table)
        layer=obj['ivars'].get('_layer',0)
        if not layer or not obj['flags'].get('_viewFlags',{}).get('superLayerIsView'):break
        internal=u32(layer+12);native=read(internal,0x54);flags,parent=struct.unpack_from('<2I',native,4)
        (out/f'layer-{internal:08x}.bin').write_bytes(native)
        if flags&0x18000:
            result['unsupported_superlayer']=dict(view=hex(address),flags=hex(flags));break
        if not parent:break
        parent_layer=u32(parent+12);parent_internal=u32(parent_layer+12)
        address=u32(parent_internal+0x50)
    else: raise ValueError('View hierarchy exceeds bounded depth')
    if result.get('table_from_cell') and result['table_from_cell'] not in objects:
        obj=objectinfo(int(result['table_from_cell'],16));delegate=obj['ivars'].get('_delegate',0)
        if delegate:
            actor=objectinfo(delegate);methods(classes[actor['isa']])
    _,after=session.command('ports Setup');(out/'ports-after.txt').write_bytes(after)
    current=struct.unpack('<32I',kernel.read(symbols['_i9100_ui_execution_diag'],128))
    b.o.require((current[2],current[3],current[12])==(d['pid'],d['task'],d['idversion']) and kernel.u32(d['task']+0x18)==mapva,'Setup identity changed')
    b.o.require(re.search(rb'proc\s+'+str(d['pid']).encode()+rb'\s+Setup.*?task='+hex(d['task']).encode(),after),'Setup no longer present')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--layout',type=Path,required=True);a=p.parse_args()
    sy=b.m.Symbols(a.kernel);layout=json.loads(a.layout.read_text());out=b.o.confined(a.output,b.f.REPO/'out')
    b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**kw):
                value=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw);events.write(json.dumps(value)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','STOP','DONE'):print(json.dumps(value),flush=True)
            try:
                with b.open_session(dev,sy.tag,out,record,300) as session:
                    kernel=b.m.Kernel(session,sy);target=out/'execution';target.mkdir()
                    names={'_i9100_ui_execution_diag','_i9100_ui_execution_rows'}
                    obs=b.observations.capture_ui_observations(kernel,b.observations.ObservationSymbols(sy,names),target)
                    with OriginalStrings() as original:result=capture(session,kernel,sy,layout,obs,out,original)
                    print(json.dumps(dict(pid=result['pid'],hierarchy=result['hierarchy'],recognizers=result['recognizers'],classes={k:v['name'] for k,v in result['classes'].items()})),flush=True)
                record('DONE')
            except BaseException as error:record('STOP',error=str(error),retry=False);raise

if __name__=='__main__':main()
