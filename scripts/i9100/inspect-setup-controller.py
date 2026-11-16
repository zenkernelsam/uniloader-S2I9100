#!/usr/bin/env python3
"""Read original Setup singleton/navigation/current Skip objects, without actions."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('controller_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)

def capture(session,kernel,symbols,main,layout,out):
    _,raw=session.command('ports Setup');(out/'ports-before.txt').write_bytes(raw)
    match=re.search(rb'proc\s+(\d+)\s+Setup.*?task=(0x[0-9a-f]+)',raw)
    b.o.require(match is not None,'Current Setup missing');pid,task=int(match[1]),int(match[2],16)
    diag=struct.unpack('<32I',kernel.read(symbols['_i9100_ui_execution_diag'],128))
    b.o.require(diag[1]==2 and (diag[2],diag[3])==(pid,task),'Setup observer identity differs')
    header,slide=diag[4],diag[31];bias=header-0x1000
    mapva=kernel.u32(task+0x18);user=kernel.user_pmap(kernel.u32(mapva+0x2c))
    def read(v,n):
        b.o.require(4096<=v<=0x40000000-n and 0<n<=4096,'Object outside bounded user space');return user.read(v,n)
    def word(v):return struct.unpack('<I',read(v,4))[0]
    singleton=word(header+0x66260)
    b.o.require(word(singleton)==int(main['classes']['SetupController']['class_address'],16)+bias,'Original Setup singleton class differs')
    root=read(singleton,104);(out/'setup-controller.bin').write_bytes(root)
    window,windowview=struct.unpack_from('<2I',root,4);nav=struct.unpack_from('<I',root,36)[0]
    chain=[];isa=word(nav);expected=int(layout['classes']['UINavigationController']['class_address'],16)+slide
    for _ in range(12):
        chain.append(hex(isa))
        if isa==expected:break
        isa=word(isa+4)
    else:raise ValueError('Current navigation object is not original UINavigationController')
    children=word(nav+168);array=read(children,24);cls,count=struct.unpack_from('<2I',array)
    b.o.require(1<=count<=32,'Empty/unbounded navigation children')
    if cls==int(layout['classes']['__NSArrayI']['class_address'],16)+slide:
        values=list(struct.unpack('<'+'I'*count,read(children+8,count*4)))
    elif cls==int(layout['classes']['__NSArrayM']['class_address'],16)+slide:
        capacity,offset=struct.unpack_from('<2I',array,8);capacity>>=2;offset>>=2;pointer=struct.unpack_from('<I',array,20)[0]
        b.o.require(count<=capacity<=128 and offset<capacity,'Unknown navigation array shape')
        data=read(pointer,capacity*4);values=[struct.unpack_from('<I',data,((offset+i)%capacity)*4)[0] for i in range(count)]
    else:raise ValueError('Unknown navigation array class')
    top=values[-1];topclass=word(top);names={int(v['class_address'],16)+bias:k for k,v in main['classes'].items() if isinstance(v,dict)}
    name=names.get(topclass);b.o.require(name is not None,'Current page is not a known original Setup class')
    reference=b.module('controller_reference','objc-image.py').MachImage(b.o.ROOT/'research/ios6-setup-original-20261116-0724/Setup','580dfd1edbd53d33844bca6635c0b3cd')
    classdata=word(topclass+16)&~3;rw=struct.unpack('<3I',read(classdata,12));ro=rw[2] if rw[0]&0x80000000 else classdata
    info=struct.unpack('<10I',read(ro,40));b.o.require(4<=info[2]<=2048,'Unbounded live instance size')
    topdata=read(top,info[2]);(out/'appleid-controller.bin').write_bytes(topdata)
    fields={};live_offsets={}
    c=topclass
    for depth in range(12):
        if c>=0x30000000:break
        cd=word(c+16)&~3;crw=struct.unpack('<3I',read(cd,12));cro=crw[2] if crw[0]&0x80000000 else cd
        ci=struct.unpack('<10I',read(cro,40))
        if ci[7]:
            step,number=struct.unpack('<2I',read(ci[7],8));b.o.require(step==20 and number<=64,'Unknown live ivar list')
            for n in range(number):
                offset,nameptr,typeptr,_,size=struct.unpack('<5I',read(ci[7]+8+n*step,20))
                nm=reference.string(nameptr-bias);offset=word(offset)
                b.o.require(0<size<=64 and offset+size<=len(topdata),'Live ivar outside actual instance')
                fields[nm]=int.from_bytes(topdata[offset:offset+size],'little') if size<=4 else topdata[offset:offset+size].hex();live_offsets[nm]=offset
        c=word(c+4)
    result=dict(tag=symbols.tag,pid=pid,task=hex(task),header=hex(header),slide=hex(slide),singleton=hex(singleton),
        navigation=hex(nav),navigation_chain=chain,controllers=[hex(v) for v in values],top=hex(top),top_class=name,fields=fields,live_offsets=live_offsets,live_instance_size=info[2],objects={},sequential=True)
    def view(v,label):
        raw=read(v,96);(out/(label+'.bin')).write_bytes(raw);layer=struct.unpack_from('<I',raw,4)[0]
        entry=dict(address=hex(v),isa=hex(struct.unpack_from('<I',raw)[0]),layer=hex(layer),words=[hex(x) for x in struct.unpack('<24I',raw)])
        if layer:
            l=read(layer,32);(out/(label+'-layer.bin')).write_bytes(l);internal=struct.unpack_from('<I',l,12)[0]
            entry.update(layer_words=[hex(x) for x in struct.unpack('<8I',l)],internal=hex(internal))
            if internal:
                data=read(internal,192);(out/(label+'-internal.bin')).write_bytes(data);entry['internal_words']=[hex(x) for x in struct.unpack('<48I',data)]
        result['objects'][label]=entry
        (out/'partial.json').write_text(json.dumps(result,indent=2)+'\n')
    for label,v in (('window',window),('window-view',windowview),('navigation-view',word(nav+4)),('page-view',word(top+4)),('skip',fields.get('_skipButton',0)),('what-is',fields.get('_whatIsButton',0)),('toolbar',fields.get('_toolbar',0)),('web-view',fields.get('_webView',0))):
        if v:view(v,label)
    inset=read(header+0x662e0,32);(out/'runtime-insets.bin').write_bytes(inset);result['runtime_insets']=list(struct.unpack('<8f',inset))
    parents=[];cursor=int(result['objects'].get('skip',{}).get('internal','0'),16);seen=set()
    while cursor and len(parents)<16:
        b.o.require(cursor not in seen,'Layer parent cycle');seen.add(cursor)
        data=read(cursor,128);(out/f'parent-{cursor:08x}.bin').write_bytes(data)
        pos=struct.unpack_from('<2d',data,32);bounds=struct.unpack_from('<4d',data,48);parent=struct.unpack_from('<I',data,8)[0]
        parents.append(dict(internal=hex(cursor),parent=hex(parent),position=pos,bounds=bounds,flags=hex(struct.unpack_from('<I',data,96)[0])))
        cursor=parent
    b.o.require(not cursor,'Layer hierarchy exceeds diagnostic bound');result['skip_layer_chain']=parents
    if fields.get('_toolbar'):
        toolbar=fields['_toolbar'];items=word(toolbar+88);ah=read(items,24);icls,icount=struct.unpack_from('<2I',ah)
        b.o.require(0<=icount<=12,'Unbounded toolbar items')
        if icls==int(layout['classes']['__NSArrayI']['class_address'],16)+slide:
            ivals=list(struct.unpack('<'+'I'*icount,read(items+8,icount*4))) if icount else []
        elif icls==int(layout['classes']['__NSArrayM']['class_address'],16)+slide:
            cap,off=struct.unpack_from('<2I',ah,8);cap>>=2;off>>=2;ptr=struct.unpack_from('<I',ah,20)[0]
            b.o.require(icount<=cap<=128 and (not cap or off<cap),'Unknown toolbar item array')
            ar=read(ptr,cap*4) if cap else b'';ivals=[struct.unpack_from('<I',ar,((off+i)%cap)*4)[0] for i in range(icount)]
        else:raise ValueError('Unknown toolbar array class')
        entries=[]
        with b.module('toolbar_strings','inspect-ui-hierarchy.py').OriginalStrings() as strings:
            for index,item in enumerate(ivals):
                data=read(item,104);(out/f'toolbar-item-{index}.bin').write_bytes(data)
                title,action,target,v=struct.unpack_from('<I',data,8)[0],struct.unpack_from('<I',data,16)[0],struct.unpack_from('<I',data,20)[0],struct.unpack_from('<I',data,68)[0]
                action_name=None
                if action:
                    try:action_name=reference.string(action-bias)
                    except ValueError:
                        try:action_name=strings.string(action-slide)
                        except ValueError:action_name=read(action,64).split(b'\0')[0].decode('utf-8','strict')
                entries.append(dict(item=hex(item),title=hex(title),action=action_name,target=hex(target),view=hex(v),flags=data[80:83].hex()))
                if v:view(v,f'toolbar-button-{index}')
        result['toolbar_items']=entries
    _,after=session.command('ports Setup');(out/'ports-after.txt').write_bytes(after)
    current=re.search(rb'proc\s+(\d+)\s+Setup.*?task=(0x[0-9a-f]+)',after)
    b.o.require(current and (int(current[1]),int(current[2],16))==(pid,task) and kernel.u32(task+0x18)==mapva and
        word(header+0x66260)==singleton and read(children,24)==array and word(top)==topclass,'Setup/navigation identity changed')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--main-layout',type=Path,required=True);p.add_argument('--layout',type=Path,required=True);a=p.parse_args()
    symbols=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'));out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    main=json.loads(a.main_layout.read_text());layout=json.loads(a.layout.read_text())
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC absent');out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields);events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','DONE','STOP'):print(json.dumps(row),flush=True)
            try:
                with b.open_session(dev,symbols.tag,out,record,240) as session:
                    result=capture(session,b.m.Kernel(session,symbols),symbols,main,layout,out)
                record('DONE');print(json.dumps({k:result[k] for k in ('pid','top_class','singleton','navigation','top','fields','runtime_insets')},indent=2),flush=True)
            except BaseException as error:record('STOP',error=str(error),retry=False);raise
if __name__=='__main__':main()
