#!/usr/bin/env python3
"""Read original iOS6 UIKit Objective-C handlers and GraphicsServices getters."""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
import argparse,importlib.util,json,mmap,struct,re
from pathlib import Path
here=Path(__file__).resolve().parent;root=here.parents[2]
s=importlib.util.spec_from_file_location('cache_symbols',here/'symbolize-ios6-stacks.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
sys.path.insert(0,str(root/'assets/py-native-hid'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if not out.is_relative_to(root/'research') or out.exists():p.error('Fresh project research directory required')
    out.mkdir(parents=True)
    with (root/'assets/ios6-extract/dyld_cache6_armv7').open('rb') as f:
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            c=m.Cache(data)
            def read(v,n):return data[c.offset(v,n):c.offset(v,n)+n]
            def words(v,n):return struct.unpack('<'+'I'*n,read(v,n*4))
            def string(v):return c.string(c.offset(v),min(len(data),c.offset(v)+16384))
            base,name=next((v,n) for v,n in c.images if n.endswith('/UIKit'))
            mh=words(base,7);at=base+28;classlist=[]
            for _ in range(mh[4]):
                cmd,size=words(at,2)
                if cmd==1:
                    nsect=words(at+48,1)[0]
                    for j in range(nsect):
                        sec=read(at+56+j*68,68)
                        if sec[:16].rstrip(b'\0')==b'__objc_classlist':
                            v,n=struct.unpack_from('<2I',sec,32);classlist.extend(words(v,n//4))
                at+=size
            classes={};wanted={'UIApplication','UIWindow','UIEvent','UITouch','UITouchesEvent','UIView','UIScreen','UIGestureRecognizer','UITableView','UIScrollView'}
            for v in classlist:
                try:
                    ro=words(v,5)[4]&~3;w=words(ro,10);cn=string(w[4])
                    if cn not in wanted:continue
                    methods=[];ml=w[5]
                    if ml:
                        flags,count=words(ml,2);step=flags&0xffff;step&=~3
                        if not 12<=step<=32 or count>4096:raise ValueError('Unknown method list')
                        for k in range(count):
                            sel,types,imp=words(ml+8+k*step,3);sn=string(sel)
                            if any(x in sn.lower() for x in ('event','touch','hit','window','location','coordinate','select','gesture','phase')):
                                methods.append(dict(selector=sn,address=hex(imp&~1),thumb=bool(imp&1)))
                    ivars=[];iv=w[7]
                    if iv:
                        step,count=words(iv,2)
                        if not 20<=step<=40 or count>1024:raise ValueError('Unknown ivar list')
                        for k in range(count):
                            at=iv+8+k*step;offsetptr,nm,typ,align,size=words(at,5)
                            if not offsetptr or not nm:continue
                            ivars.append(dict(name=string(nm),offset=words(offsetptr,1)[0],size=size,type=string(typ) if typ else None))
                    bitfields={}
                    for ivar in ivars:
                        fields=re.findall(r'"([^\"]+)"b([0-9]+)',ivar.get('type') or '')
                        if fields:
                            bit=0;parts=[]
                            for fn,width in fields:
                                parts.append(dict(name=fn,bit=bit,width=int(width)));bit+=int(width)
                            bitfields[ivar['name']]=parts
                    classes[cn]=dict(class_address=hex(v),instance_size=w[2],methods=methods,ivars=ivars,bitfields=bitfields)
                except ValueError as e:
                    classes['error-'+hex(v)]=str(e)
            gsbase,gsname=next((v,n) for v,n in c.images if '/GraphicsServices.framework/' in n)
            _,gs,_=c.image_symbols(gsbase)
            names={'_GSEventGetType','_GSEventGetWindowContextId','_GSEventGetLocationInWindow','_GSEventGetHandInfo',
                   '_GSEventGetHIDEvent','_GSEventGetTimestamp','_GSEventCreateWithEventRecord','_GSSendEvent','_GSEventGetWindow'}
            getters=[dict(name=n,address=hex(v)) for v,n in gs if n in names]
            _,usymbols,_=c.image_symbols(base)
            globals=[dict(name=sn,address=hex(v)) for v,sn in usymbols if sn in ('_UIApp','_UIApplicationInstance','_UIApplicationHandleEvent') or 'sharedApplication' in sn]
            (out/'handlers.json').write_text(json.dumps(dict(uikit=name,classes=classes,graphicsservices=getters,globals=globals),indent=2)+'\n')
            md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=False
            targets=[(x['name'],int(x['address'],16),256) for x in getters]
            for cn,obj in classes.items():
                if isinstance(obj,dict):
                    for x in obj['methods']:
                        if cn=='UIApplication' and any(z in x['selector'].lower() for z in ('handle','sendevent','gsevent')):
                            targets.append((cn+':'+x['selector'],int(x['address'],16),1400))
                        if cn=='UIApplication' and x['selector'] in ('isIgnoringInteractionEvents','isSuspendedEventsOnly','ignoresInteractionEvents','blockInteractionEventsCount','keyWindow','windows','_touchMap'):
                            targets.append((cn+':'+x['selector'],int(x['address'],16),80))
                        if cn=='UIWindow' and x['selector'] in ('sendEvent:','_sendTouchesForEvent:'):
                            targets.append((cn+':'+x['selector'],int(x['address'],16),1400))
                        if cn=='UIWindow' and x['selector'] in ('_transformDisplayToWindowCoordinates:','convertDeviceToWindow:','convertWindowToDevice:','_touchData'):
                            targets.append((cn+':'+x['selector'],int(x['address'],16),256))
                        if cn=='UITouch' and x['selector'] in ('setPhase:','_setPhase:','_setLocationInWindow:resetPrevious:'):
                            targets.append((cn+':'+x['selector'],int(x['address'],16),256))
            lines=[]
            for label,v,n in targets:
                lines.append('FUNCTION '+label+' '+hex(v))
                for ins in md.disasm(read(v,n),v):lines.append(f'{ins.address:08x} {ins.bytes.hex():12s} {ins.mnemonic:10s} {ins.op_str}')
                lines.append('')
            (out/'native-ui.txt').write_text('\n'.join(lines)+'\n')
            print(json.dumps(dict(result='READ',uikit_classes=list(classes),getters=getters,disassembled=len(targets),output=str(out)),indent=2))
if __name__=='__main__':main()
