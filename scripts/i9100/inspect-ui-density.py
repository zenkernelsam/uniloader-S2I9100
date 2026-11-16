#!/usr/bin/env python3
"""Read density installation, original GS/UIKit metrics and power on one handle."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('density_boot',HERE/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
FIELDS=('version','state','pid','task','header','code','attempts','vm_result','reason','restore_error',
        'installed','stage','idversion','option','slide','site','factory_before','once_before','reserved0','reserved1')

def capture(session,kernel,symbols,layout,out,record):
    raw=kernel.read(symbols['_i9100_ui_density_diag'],240);(out/'density-diag.bin').write_bytes(raw)
    rows=[dict(zip(FIELDS,struct.unpack_from('<20I',raw,n*80))) for n in range(3)]
    result=dict(tag=symbols.tag,installation=dict(zip(('backboardd','SpringBoard','Setup'),rows)),
                processes={},power={},sequential=True,physical_touch_verified=False)
    def save(): (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    for name in ('valid','percent','mv','connected','charging','temp','reason','revision_value'):
        raw=kernel.read(symbols['_i9100_power_'+name],4)
        result['power'][name]=struct.unpack('<i' if name in ('temp','reason') else '<I',raw)[0]
    save()
    ui=b.module('density_ui','inspect-ui-app.py')
    for name in ('backboardd','SpringBoard','Setup'):
        target=out/name;target.mkdir()
        _,before=session.command('ports '+name);(target/'ports-before.txt').write_bytes(before)
        match=re.search(rb'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)',before)
        if not match:
            result['processes'][name]=dict(present=False);save();continue
        pid,task=int(match[1]),int(match[2],16);mapva=kernel.u32(task+0x18)
        user=kernel.user_pmap(kernel.u32(mapva+0x2c));ptr,size=struct.unpack('<2I',kernel.read(task+0x210,8))
        b.o.require(4096<=ptr<=0x3fffffac and size>=84,'Invalid current dyld info')
        dyld=struct.unpack('<21I',user.read(ptr,84));slide=dyld[20]
        b.o.require(12<=dyld[0]<=15 and not slide&4095 and slide<=0x0375b000,'Invalid original iOS6 slide')
        scale_raw=user.read(0x3a283e7c+slide,4);pixels_raw=user.read(0x3a282460+slide,8)
        (target/'gs-scale.bin').write_bytes(scale_raw);(target/'gs-pixels.bin').write_bytes(pixels_raw)
        scale=struct.unpack('<f',scale_raw)[0];pixels=list(struct.unpack('<2I',pixels_raw))
        entry=dict(pid=pid,task=hex(task),slide=hex(slide),gs_scale=scale,gs_scale_bits=scale_raw.hex(),gs_pixels=pixels,present=True)
        producer=2 if result['installation'][name]['version']>=2 else 1
        entry['producer_schema']=producer
        site=(0x34c34d44 if producer==2 else 0x3867f554)+slide
        site_raw=user.read(site,8);(target/'density-site.bin').write_bytes(site_raw)
        entry['density_site']=dict(address=hex(site),physical=hex(user.translate(site)),bytes=site_raw.hex())
        if site_raw[:4]==bytes.fromhex('dff800f0'):
            code=struct.unpack_from('<I',site_raw,4)[0]&~1
            length=36 if producer==2 else 24
            b.o.require(4096<=code<=0x40000000-length,'Invalid private density code target')
            raw_code=user.read(code,length);(target/'density-code.bin').write_bytes(raw_code);entry['density_site']['code']=hex(code);entry['density_site']['code_bytes']=raw_code.hex()
        if producer==2:
            entry['gs_initial_scale_bits']=hex(result['installation'][name]['factory_before'])
            entry['installed_via']=result['installation'][name]['reserved1'];dictionary=0
        else:
            entry['mg_export_bytes']=user.read(0x3867ab00+slide,12).hex()
            cache=user.read(0x3acd7d4c+slide,8);dictionary,once=struct.unpack('<2I',cache)
            entry['mg_factory']=dict(dictionary=hex(dictionary),once=hex(once))
        if dictionary:
            header=user.read(dictionary,36);(target/'mg-dictionary.bin').write_bytes(header)
            index=header[11];sizes=(0,3,7,13,23,41,71,127)
            b.o.require(((header[8]>>3)&1)==1 and 0<index<len(sizes),'Unknown original MG dictionary geometry')
            count=sizes[index];values,keys=struct.unpack_from('<2I',header,28)
            value_raw=user.read(values,count*4);key_raw=user.read(keys,count*4)
            (target/'mg-values.bin').write_bytes(value_raw);(target/'mg-keys.bin').write_bytes(key_raw)
            entries=[]
            for key,value in zip(struct.unpack('<'+'I'*count,key_raw),struct.unpack('<'+'I'*count,value_raw)):
                if value in (0,0xffffffff):continue
                item=dict(key=hex(key),value=hex(value))
                if key==0x3acd6288+slide:
                    number=user.read(value,24);(target/'mg-scale-number.bin').write_bytes(number);item['scale_number_hex']=number.hex()
                entries.append(item)
            b.o.require(user.read(dictionary,36)==header and user.read(values,count*4)==value_raw and user.read(keys,count*4)==key_raw,'Original MG dictionary changed')
            entry['mg_factory']['entries']=entries
        result['processes'][name]=entry;save()
        entry['gs_initialized']=0<scale<=4 and all(0<n<=2048 for n in pixels)
        if name!='backboardd':
            uidir=target/'UIKit';uidir.mkdir()
            app=ui.capture(session,kernel,symbols,name,layout,uidir,flags_only=True,geometry=True)
            entry['screen']=app['main_screen'];entry['flags']={n:app['flags'][n] for n in ('isClassic','idleTimerDisabled','isSuspended','isSuspendedEventsOnly','blockInteractionEvents')}
        _,after=session.command('ports '+name);(target/'ports-after.txt').write_bytes(after)
        current=re.search(rb'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)',after)
        b.o.require(current and (int(current[1]),int(current[2],16))==(pid,task) and kernel.u32(task+0x18)==mapva,'Density owner changed')
        result['processes'][name]=entry;save();record('METRICS',process=name,**entry)
    save();return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--layout',type=Path,required=True);p.add_argument('--require-installed',type=int,choices=(1333,1500))
    p.add_argument('--frame',action='store_true');a=p.parse_args()
    symbols=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'));layout=json.loads(a.layout.read_text())
    b.o.require('_i9100_ui_density_diag' in symbols.values,'Kernel lacks density diagnostic')
    b.o.require({'UIApplication','UIScreen','__NSArrayI','__NSArrayM'}<=layout['classes'].keys(),'Original UIKit/array layout required')
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        device=b.o.cdc(b.o.Host().inventory());b.o.require(device and b.o.normalize_location(device['location'])==profile['location'],'Approved CDC absent');out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields);events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','METRICS','CLOSED','DONE','STOP'):print(json.dumps(row),flush=True)
            try:
                with b.open_session(device,symbols.tag,out,record,300) as session:
                    answer,_=session.command('panic-status')
                    if answer!='OK panic=0 seconds=00000000':b.retain_current_panic(session,out,record);raise ValueError('Current panic retained')
                    kernel=b.m.Kernel(session,symbols);result=capture(session,kernel,symbols,layout,out,record)
                    if a.frame:
                        target=out/'frame';target.mkdir();result['frame']=b.frame.capture_frame(kernel,symbols,target,device,32768,record)
                        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                    if a.require_installed:
                        expected=4/3 if a.require_installed==1333 else 1.5
                        for name,installation in result['installation'].items():
                            process=result['processes'][name]
                            b.o.require(installation['version']==2 and installation['state']==2 and installation['option']==a.require_installed and
                                installation['installed']>0 and process['present'] and installation['pid']==process['pid'] and
                                installation['task']==int(process['task'],16),'Current '+name+' density not installed')
                            b.o.require(process['density_site'].get('code')==hex(installation['code']),'Current '+name+' calibration code differs')
                            if process['gs_initialized']:
                                b.o.require(process['gs_pixels']==[480,800] and abs(process['gs_scale']-expected)<0.00001,'Original '+name+' GS density differs')
                            else:b.o.require(name=='backboardd','Original '+name+' GS metrics not initialized')
                            if 'screen' in process:
                                screen=process['screen'];bounds=screen['bounds']
                                b.o.require(abs(screen['scale']-expected)<0.00001 and abs(bounds[2]*expected-480)<0.01 and abs(bounds[3]*expected-800)<0.01,'Original '+name+' UIKit geometry differs')
                    record('DONE',power=result['power'],qualified=bool(a.require_installed),physical_touch_verified=False)
            except BaseException as exc:record('STOP',error=str(exc),retry=False);raise
if __name__=='__main__':main()
