#!/usr/bin/env python3
"""Read actual HID execution and optional scanout on one bounded handle.

No input, reboot, flash or retry. Self-test admission is explicit; failure
retains the observed state and closes the original handle normally.
"""
import argparse,importlib.util,json,struct
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('hid_scene_boot',HERE/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--frame',action='store_true');p.add_argument('--require-self-test',action='store_true')
    p.add_argument('--filter-state',action='store_true',help='Retain bounded current service/client dictionary pages from the executed shim')
    a=p.parse_args();out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    symbols=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'))
    names={'_i9100_hid_execution_diag','_i9100_hid_execution_rows','_i9100_touch_observation','_i9100_input_test',
           '_i9100_graphics_seq','_i9100_process_exit','_i9100_backboard_exit','_i9100_quiet_charge_diag','_i9100_ui_sounds_unavailable_diag'}
    names.update({'_i9100_power_'+n for n in ('valid','percent','mv','connected','charging','temp','reason','revision_value')})
    names.update({'_i9100_hid_fixed_cadence_diag','_i9100_touch_sender_identity'})
    selected=b.observations.ObservationSymbols(symbols,names)
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        device=b.o.cdc(b.o.Host().inventory())
        b.o.require(device and device['service'].lower()=='usbser' and b.o.normalize_location(device['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','STATE','FRAME_PROGRESS','PANIC_TRANSITION_SAVED','CLOSED','DONE','STOP'):print(json.dumps(row),flush=True)
            try:
                with b.open_session(device,symbols.tag,out,record,600) as session:
                    answer,_=session.command('panic-status')
                    if answer!='OK panic=0 seconds=00000000':
                        b.retain_current_panic(session,out,record);raise RuntimeError('Current panic retained')
                    kernel=b.m.Kernel(session,symbols);before=out/'before';before.mkdir()
                    state=b.observations.capture_ui_observations(kernel,selected,before)
                    record('STATE',hid=state.get('hid_execution'),touch=state.get('touch'),power=state.get('power'),graphics=state.get('i9100_graphics_seq'),springboard_exit=state.get('i9100_process_exit'),backboard_exit=state.get('i9100_backboard_exit'),quiet_charge=state.get('quiet_charge_feedback'))
                    probe=state.get('hid_execution',{})
                    if a.require_self_test:
                        b.o.require(probe.get('version')==2 and probe.get('state')==2 and probe.get('installed',0)>0 and probe.get('self_test_count')==probe.get('installed') and probe.get('matching_svc_count',0)>=1,'Actual HID observer self-test not confirmed')
                    result=dict(tag=symbols.tag,sequential=True,observations=state,interaction_verified=False)
                    if a.filter_state:
                        rows=state.get('hid_execution_rows',{}).get('rows',[])
                        shim=next((r for r in reversed(rows) if r['phase']==5 and r['current_installation']),None)
                        b.o.require(shim is not None,'No current executed shim context')
                        mapva=kernel.u32(probe['task']+0x18);pmap=kernel.u32(mapva+0x2c);user=kernel.user_pmap(pmap)
                        target=out/'filter';target.mkdir()
                        addresses={shim['arguments'][0]&~4095,shim['arguments'][2]&~4095,(shim['arguments'][2]&~4095)+4096}
                        addresses.update(r['arguments'][0]&~4095 for r in rows if r['phase']==6 and r['current_installation'])
                        pages={}
                        for address in sorted(addresses):
                            b.o.require(4096<=address<=0x3ffff000,'Filter object outside user map')
                            raw=user.read(address,4096);(target/f'user-{address:08x}.bin').write_bytes(raw);pages[hex(address)]=len(raw)
                        service=shim['arguments'][2];dictionary=struct.unpack('<I',user.read(service+0x7c,4))[0]
                        header=user.read(dictionary,36);idx=header[11];sizes=(0,3,7,13,23,41,71,127)
                        # CF-744.18 ARM32 CFBasicHash: 8B runtime +16B bits
                        # +4B callbacks, then value/key pointers. Validate
                        # this bounded dictionary form before following it.
                        b.o.require(((header[8]>>3)&1)==1 and 0<idx<len(sizes),'Unknown client dictionary geometry')
                        count=sizes[idx];values,keys=struct.unpack_from('<2I',header,28)
                        raw_values=user.read(values,count*4);raw_keys=user.read(keys,count*4)
                        (target/'dictionary.bin').write_bytes(header);(target/'values.bin').write_bytes(raw_values);(target/'keys.bin').write_bytes(raw_keys)
                        entries=[]
                        for key,value in zip(struct.unpack('<'+'I'*count,raw_keys),struct.unpack('<'+'I'*count,raw_values)):
                            if value in (0,0xffffffff):continue
                            data=user.read(value,32);length,capacity=struct.unpack_from('<2I',data,8)
                            (target/f'context-{value:08x}.bin').write_bytes(data)
                            if not (length<=capacity and 20<=capacity<=64 and ((struct.unpack_from('<I',data,4)[0]>>8)&1023)==20):
                                entries.append(dict(client=hex(key),data=hex(value),header=data.hex(),context_valid=False));continue
                            pointer=((value+0x27)&~15) if data[4]&4 else struct.unpack_from('<I',data,20)[0]
                            payload=user.read(pointer,20);words=struct.unpack('<5I',payload)
                            (target/f'payload-{value:08x}.bin').write_bytes(payload)
                            entry=dict(client=hex(key),data=hex(value),header=data.hex(),pointer=hex(pointer),words=list(words),deadline=words[1]|words[2]<<32)
                            if words[0]:
                                number=user.read(words[0],24);(target/f'number-{words[0]:08x}.bin').write_bytes(number);entry['interval_number_hex']=number.hex()
                            entries.append(entry)
                            (target/'clients-partial.json').write_text(json.dumps(entries,indent=2)+'\n')
                        b.o.require(user.read(dictionary,36)==header and user.read(values,count*4)==raw_values and user.read(keys,count*4)==raw_keys,'Client dictionary changed during read')
                        (target/'clients.json').write_text(json.dumps(dict(dictionary=hex(dictionary),header=header.hex(),buckets=count,entries=entries,sequential=True),indent=2)+'\n')
                        identity=kernel.read(symbols['_i9100_hid_execution_diag'],128)
                        current=struct.unpack('<32I',identity)
                        b.o.require((current[2],current[3],current[12])==(probe['pid'],probe['task'],probe['idversion']),'Filter owner changed')
                        result['filter']=dict(system=hex(shim['arguments'][0]),service=hex(shim['arguments'][2]),task=hex(probe['task']),map=hex(mapva),pmap=hex(pmap),pages=pages,client_entries=entries)
                    if a.frame:
                        target=out/'frame';target.mkdir()
                        result['frame']=b.frame.capture_frame(kernel,symbols,target,device,8192,record)
                    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                record('DONE',frame=bool(a.frame),interaction_verified=False)
            except BaseException as e:record('STOP',error=str(e),retry=False);raise
if __name__=='__main__':main()
