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
def flag_fields(encoding):
    """ARM32 named flag structs, including ordinary fields between bitfields."""
    if not encoding.startswith('{?=') or not encoding.endswith('}'):return []
    body=encoding[3:-1];tokens=list(re.finditer(r'"([^"]+)"(b[0-9]+|[cCsSiIlLqQfdB])',body))
    if ''.join(x[0] for x in tokens)!=body:raise ValueError('Unsupported original flag structure encoding')
    sizes={'c':8,'C':8,'B':8,'s':16,'S':16,'i':32,'I':32,'l':32,'L':32,'q':64,'Q':64,'f':32,'d':64}
    bit=0;result=[]
    for token in tokens:
        name,kind=token[1],token[2]
        if kind.startswith('b'):
            width=int(kind[1:]);result.append(dict(name=name,bit=bit,width=width));bit+=width
        else:
            width=sizes[kind];align=min(width,32);bit=(bit+align-1)//align*align
            result.append(dict(name=name,bit=bit,width=width,type=kind));bit+=width
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--classes',nargs='*',default=[],help='Additional original Objective-C classes')
    p.add_argument('--all-classes',action='store_true',help='Read all original classes in the explicitly selected images')
    p.add_argument('--images',nargs='+',default=['UIKit'],help='Cache image leaf names containing the requested classes')
    p.add_argument('--native',action='append',default=[],help='Disassemble original Class:selector (up to 4096 bytes)')
    p.add_argument('--only-native',action='store_true',help='Omit the default disassembly set')
    p.add_argument('--executable',type=Path,help='UUID-matched original Setup for its classes and callbacks')
    p.add_argument('--executable-uuid',default='580dfd1edbd53d33844bca6635c0b3cd',help='Explicit UUID for another original executable; Setup remains the default')
    p.add_argument('--class-methods',action='store_true',help='Read original Objective-C metaclass methods and their ABI encodings')
    p.add_argument('--native-class',action='append',default=[],help='Disassemble original Class:classSelector')
    p.add_argument('--native-address',action='append',default=[],help='Disassemble an original mapped address in the selected cache or executable')
    p.add_argument('--native-symbol',action='append',default=[],help='Disassemble an exported original UIKit function (up to 12288 bytes)')
    p.add_argument('--symbol-image',default='UIKit',help='Exact selected cache image leaf for exported native symbols')
    a=p.parse_args()
    out=a.output.resolve()
    if not out.is_relative_to(root/'research') or out.exists():p.error('Fresh project research directory required')
    out.mkdir(parents=True)
    with (root/'assets/ios6-extract/dyld_cache6_armv7').open('rb') as f:
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            c=m.Cache(data)
            executable=None
            if a.executable:
                refpath=a.executable.resolve()
                if not refpath.is_relative_to(root):raise ValueError('Original reference outside project')
                spec=importlib.util.spec_from_file_location('ui_reference',here/'objc-image.py')
                ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
                if not re.fullmatch(r'[0-9a-f]{32}',a.executable_uuid):raise ValueError('Expected an exact original executable UUID')
                executable=ref.MachImage(refpath,a.executable_uuid)
            def read(v,n):
                if executable and v<0x30000000:return executable.read(v,n)
                return data[c.offset(v,n):c.offset(v,n)+n]
            def words(v,n):return struct.unpack('<'+'I'*n,read(v,n*4))
            def string(v):
                if executable and v<0x30000000:return executable.string(v)
                return c.string(c.offset(v),min(len(data),c.offset(v)+16384))
            base,name=next((v,n) for v,n in c.images if n.endswith('/UIKit'))
            classlist=[]
            image_sources=c.images+([(executable.base,str(executable.path))] if executable else [])
            for imagebase,imagename in image_sources:
                if imagename.rsplit('/',1)[-1] not in a.images:continue
                mh=words(imagebase,7);at=imagebase+28
                for _ in range(mh[4]):
                    cmd,size=words(at,2)
                    if cmd==1:
                        nsect=words(at+48,1)[0]
                        for j in range(nsect):
                            sec=read(at+56+j*68,68)
                            if sec[:16].rstrip(b'\0')==b'__objc_classlist':
                                v,n=struct.unpack_from('<2I',sec,32)
                                classlist.extend((q,imagename) for q in words(v,n//4))
                    at+=size
            classes={};wanted={'UIApplication','UIWindow','UIEvent','UITouch','UITouchesEvent','UIView','UIScreen','UIGestureRecognizer','UITableView','UIScrollView'}|set(a.classes)
            native=set(a.native)
            for v,imagename in classlist:
                try:
                    ro=words(v,5)[4]&~3;w=words(ro,10);cn=string(w[4])
                    if cn not in wanted and not a.all_classes:continue
                    methods=[];ml=w[5]
                    if ml:
                        flags,count=words(ml,2);step=flags&0xffff;step&=~3
                        if not 12<=step<=32 or count>4096:raise ValueError('Unknown method list')
                        for k in range(count):
                            sel,types,imp=words(ml+8+k*step,3);sn=string(sel)
                            if a.all_classes or cn in a.classes or cn+':'+sn in native or any(x in sn.lower() for x in ('event','touch','hit','window','location','coordinate','select','gesture','phase')):
                                methods.append(dict(selector=sn,selector_address=hex(sel),types=string(types),address=hex(imp&~1),thumb=bool(imp&1)))
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
                            parts=flag_fields(ivar['type'])
                            if parts and max(x['bit']+x['width'] for x in parts)>ivar['size']*8:raise ValueError('Original flags exceed original ivar')
                            bitfields[ivar['name']]=parts
                    classes[cn]=dict(class_address=hex(v),superclass=hex(words(v,2)[1]),image=imagename,instance_size=w[2],methods=methods,ivars=ivars,bitfields=bitfields)
                    if a.class_methods or a.native_class:
                        meta=words(v,1)[0];mro=words(meta,5)[4]&~3;mw=words(mro,10);ml=mw[5];mm=[]
                        if ml:
                            flags,count=words(ml,2);step=(flags&0xffff)&~3
                            if not 12<=step<=32 or count>4096:raise ValueError('Unknown metaclass method list')
                            for k in range(count):
                                sel,types,imp=words(ml+8+k*step,3)
                                mm.append(dict(selector=string(sel),selector_address=hex(sel),address=hex(imp&~1),thumb=bool(imp&1),types=string(types)))
                        classes[cn]['class_methods']=mm
                except ValueError as e:
                    classes['error-'+hex(v)]=str(e)
            gsbase,gsname=next((v,n) for v,n in c.images if '/GraphicsServices.framework/' in n)
            _,gs,_=c.image_symbols(gsbase)
            names={'_GSEventGetType','_GSEventGetWindowContextId','_GSEventGetLocationInWindow','_GSEventGetHandInfo',
                   '_GSEventGetHIDEvent','_GSEventGetTimestamp','_GSEventCreateWithEventRecord','_GSSendEvent','_GSEventGetWindow'}
            getters=[dict(name=n,address=hex(v)) for v,n in gs if n in names]
            _,usymbols,_=c.image_symbols(base)
            symbolbase=next(v for v,n in c.images if n.rsplit('/',1)[-1]==a.symbol_image)
            _,export_symbols,_=c.image_symbols(symbolbase)
            exports={sn:v for v,sn in export_symbols}
            globals=[dict(name=sn,address=hex(v)) for v,sn in usymbols if sn in ('_UIApp','_UIApplicationInstance','_UIApplicationHandleEvent') or 'sharedApplication' in sn]
            (out/'handlers.json').write_text(json.dumps(dict(uikit=name,classes=classes,graphicsservices=getters,globals=globals),indent=2)+'\n')
            md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=False
            targets=[] if a.only_native else [(x['name'],int(x['address'],16),256) for x in getters]
            targets.extend(('original-address-'+v,int(v,0),4096) for v in a.native_address)
            for symbol in a.native_symbol:
                if symbol not in exports:raise ValueError('Original UIKit symbol absent: '+symbol)
                targets.append((symbol,exports[symbol],12288))
            found_native=set()
            for cn,obj in classes.items():
                if isinstance(obj,dict):
                    for x in obj.get('class_methods',[]):
                        key=cn+':'+x['selector']
                        if key in a.native_class:
                            targets.append(('+'+key,int(x['address'],16),4096))
                            found_native.add(key)
                    for x in obj['methods']:
                        if cn+':'+x['selector'] in native:
                            targets.append((cn+':'+x['selector'],int(x['address'],16),4096))
                            found_native.add(cn+':'+x['selector'])
                        if a.only_native:continue
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
            requested=native|set(a.native_class)
            if requested-found_native:raise ValueError('Original selectors absent: '+', '.join(sorted(requested-found_native)))
            for label,v,n in targets:
                lines.append('FUNCTION '+label+' '+hex(v))
                literals={}
                for ins in md.disasm(read(v,n),v):
                    note='';match=re.fullmatch(r'(r[0-9]+), #(0x[0-9a-f]+|[0-9]+)',ins.op_str)
                    if ins.mnemonic=='movw' and match:literals[match[1]]=int(match[2],0)
                    elif ins.mnemonic=='movt' and match and match[1] in literals:
                        literals[match[1]]|=int(match[2],0)<<16
                    elif ins.mnemonic=='add' and ins.op_str.endswith(', pc'):
                        reg=ins.op_str.split(',')[0]
                        if reg in literals:
                            address=(literals.pop(reg)+ins.address+4)&0xffffffff
                            try:
                                value=words(address,1)[0];note=f' ; original[{address:08x}]={value:08x}'
                                for candidate in (address,value):
                                    try:
                                        cf=words(candidate,4)
                                        if cf[1]==0x7c8 and 0<cf[3]<=128:
                                            note+=' CFString '+repr(read(cf[2],cf[3]).decode('utf-8','strict'))
                                    except (ValueError,UnicodeError,struct.error):pass
                                try:
                                    st=string(value)
                                    if 0<len(st)<160 and all(x.isprintable() for x in st):note+=' '+repr(st)
                                except (ValueError,UnicodeError):pass
                            except (ValueError,struct.error):pass
                    lines.append(f'{ins.address:08x} {ins.bytes.hex():12s} {ins.mnemonic:10s} {ins.op_str}'+note)
                lines.append('')
            (out/'native-ui.txt').write_text('\n'.join(lines)+'\n')
            print(json.dumps(dict(result='READ',uikit_classes=list(classes),getters=getters,disassembled=len(targets),output=str(out)),indent=2))
if __name__=='__main__':main()
