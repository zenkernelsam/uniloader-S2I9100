#!/usr/bin/env python3
"""Exercise actual roundtrip orchestration with local retained evidence only."""
import importlib.util,json,hashlib,struct
from datetime import datetime
from pathlib import Path

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('roundtrip_check',here/'verify-charge-roundtrip.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
out=m.o.REPO/'out'/('charge-roundtrip-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
tag='0123456789abcdef';source='fedcba9876543210'
manifest=dict(control_tag=tag,standalone_charge_control_tag=source)
package=out/'package';package.mkdir()
profile=json.loads((m.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
device=dict(instance=m.o.CDC,status='OK',port='COM12',service='usbser',location=profile['location'])

def write_events(path,events):path.write_text(''.join(json.dumps(row)+'\n' for row in events))
def epoch_fixture(full=False):
    words=[0]*32;words[:4]=[0x45433949,2,128,3]
    words[4:17]=[14,1,1,1,1,0,0,0,0,0,1,1,50]
    words[17:21]=[4000,250,0,0]
    elapsed=400000000000;words[21:27]=[1000000000,0,elapsed&0xffffffff,elapsed>>32,1000000000,0]
    words[27:31]=[900000000,0,1,7]
    if full:
        words[9]=1;words[14]=words[15]=0;words[19]=0xfffffffc
        words[23]=words[24]=words[25]=words[26]=0
    raw=struct.pack('<32I',*words);words[31]=m.h.checksum(raw)
    return struct.pack('<32I',*words)

def owner(path,shutdown=False,handoff=None):
    path.mkdir();(path/'owner.json').write_text(json.dumps(dict(pid=123,tag=tag,process_created_100ns=456))+'\n')
    events=[dict(phase='READY',pid=123,tag=tag)]
    if shutdown:
        target=path/'task-0001';target.mkdir()
        (target/'result.json').write_text(json.dumps(dict(reply='OK poweroff-charge',shutdown_disconnect_observed=True))+'\n')
        events.append(dict(phase='TASK_DONE',id='0001',action='poweroff-charge'))
    elif handoff:
        task=path/'task-0000';task.mkdir()
        words=[0]*32;words[:4]=[m.h.MAGIC,1,128,7]
        words[4:14]=[14,1,15,1,1,1,50,4000,250,0]
        words[17:21]=[1,1,0,0];words[21:27]=[660000000,0,660000100,0,660000200,0]
        words[27:31]=[14,11,13,0]
        if handoff.startswith('epoch-'):words[27]=440
        if handoff=='epoch-full':
            words[14]=1;words[17]=words[18]=words[27]=0;words[13]=0xfffffffc
        raw=struct.pack('<32I',*words);words[31]=m.h.checksum(raw);raw=struct.pack('<32I',*words)
        decoded=m.h.decode(raw)
        observed=dict(decoded,root_stable=True,kernel_tag=tag)
        charge=dict(charger_handoff=observed)
        if handoff.startswith('stop-'):
            charge.update(version=3,samples=[dict(sequence=1,stop_confirmation_available=True,stop_uncertain=0,measurements_valid=True,reason=0)],
                stop_confirmation=dict(uncertain=False,measurement_valid=True))
            if handoff=='stop-uncertain':
                charge['samples'][0]['stop_uncertain']=1;charge['stop_confirmation']['uncertain']=True
            if handoff=='stop-invalid':charge['samples'][0]['measurements_valid']=False
            if handoff=='stop-missing':charge.pop('stop_confirmation')
            if handoff=='stop-monitor-dead':charge['stop_confirmation']['measurement_valid']=False
        if handoff.startswith(('deadline-','epoch-')) and handoff!='deadline-missing':
            sampled_ns=decoded['sampled_ticks']*1000//24
            elapsed=(decoded['elapsed_seconds']+1)*1000000000
            start=max(1,sampled_ns-elapsed);base=0 if elapsed<sampled_ns else elapsed-sampled_ns+1
            charge['charger_deadline_adoption']=dict(consistent=True,state=1,revision=14,enabled_after_init=0,
                full=0,recharging=0,timeout=0,charge_start_ns=start,elapsed_base_ns=base,deadline_seconds=18000)
            if handoff=='epoch-full':
                charge['charger_deadline_adoption'].update(full=1,charge_start_ns=0,elapsed_base_ns=0)
            if handoff=='deadline-rejected':charge['charger_deadline_adoption'].update(state=3,timeout=1)
            if handoff=='deadline-extended':charge['charger_deadline_adoption']['charge_start_ns']+=1000000000
        if handoff.startswith('epoch-'):
            wrapper=struct.pack('<8I',0x57453949,1,160,1,1,1,900000020,0)+epoch_fixture(handoff=='epoch-full')
            charge['charger_handoff']['shutdown_charge_epoch']=m.h.decode_epoch_return(wrapper)
            if handoff=='epoch-missing':charge['charger_handoff'].pop('shutdown_charge_epoch')
            if handoff=='epoch-rejected':charge['charger_handoff']['shutdown_charge_epoch']['state']=3
        if handoff=='handoff-corrupt':
            raw=bytes((raw[0]^1,))+raw[1:]
        if handoff!='handoff-missing':(task/'charge-handoff.bin').write_bytes(raw)
        (task/'result.json').write_text(json.dumps(dict(charge=charge))+'\n')
        events.append(dict(phase='TASK_DONE',id='0000',action='charge'))
    events.extend([dict(phase='DONE'),dict(phase='CLOSED')]);write_events(path/'events.jsonl',events)

def charger(path,scenario):
    path.mkdir();lines=[f'I9CHC2 READY {tag} {source}\n']
    for seq in range(1,5):
        ms=(seq-1)*30000
        lines.append(f'I9CHG2 seq={seq:08x} ms={ms:016x} valid=1 soc=75 mv=4000 temp=250 charging=1 reason=0 full=0 timeout=0 recharging=0 elapsed={ms//1000}\n')
        if scenario.startswith('policy-') and scenario!='policy-missing':
            sampled=ms*24000 if ms else 24
            scheduled=sampled+24000000
            polls=1+(seq-1)*30
            lines.append('I9PS1 '+' '.join(f'{value:08x}' for value in (seq,polls,sampled&0xffffffff,sampled>>32,
                scheduled&0xffffffff,scheduled>>32,11,1))+'\n')
        if scenario.startswith('download-stop-') and scenario!='download-stop-missing':
            lines.append(f'I9DS1 {seq:08x} 00000000 00000000 00000000 00000001 00000001 00000000 00000000\n')
        if scenario.startswith(('sense-','route-')) and scenario!='sense-missing':
            sense_time=max(1,ms-3)
            lines.append(f'I9CS1 {seq:08x} {sense_time:08x} 00000000 000007d0 000003ff 000003ce 00000001 00000000\n')
            lines.append(f'I9RG1 {seq:08x} 0000c800 00004b00 00000032 010e0104 00000100 00000004 00000000\n')
        lines.append('I9UI1 00000001 5ec00000 00000780 00000020\n')
        lines.append('I9FB1 00000000 00008035 5ec00000 00000780 000efb1f 5ed77000 01000000 00000001\n')
        if scenario.startswith('art-') and scenario!='art-missing':
            # Native frame 12 is the measured 75% level. Repeated blank
            # reports keep frames/stores fixed while device time advances.
            lines.append('I9CR1 00000001 0000000c 00000002 0004e200 00000000 0000001c 00000001 00000000\n')
            lines.append('I9BT1 00000001 0000000b 00000000 00000001 00000fa0 0000004b 00000000 00000000\n')
            if 'dirty-' in scenario and scenario!='art-dirty-missing':
                lines.append('I9DR1 00000002 00000a80 00000a80 00000001 000000a0 00000001 00000001 00000001\n')
            if 'transport-' in scenario and scenario!='art-transport-missing':
                lines.append('I9UT1 00040000 80488200 20080040 00000000 00000180 000000a0 00000001 00000000\n')
        if scenario in ('panel-success','panel-unqualified','panel-scanout-running','panel-id-mismatch','panel-id-partial') or scenario.startswith('recovery-'):
            lines.append('I9PL1 00000001 00000003 00000000 00000000 00000002 00001003 00001000 00001000\n')
            lines.append('I9PD1 0000003f 000000a1 00000012 00000011\n')
            if scenario.startswith('recovery-') and scenario!='recovery-missing':
                lines.append('I9PR1 00000000 00000000 00000000 00000003\n')
    text=''.join(lines)
    if scenario.startswith('epoch-'):
        epoch=m.h.decode_epoch(epoch_fixture(scenario=='epoch-full'))
        previous,current=(0,0) if scenario=='epoch-full' else (400,422)
        status=f'I9CE1 00000001 00000001 00000001 {epoch["checksum"]:08x} {previous:08x} {current:08x} {900000020:08x} 00000000\n'
        text+=status
        if scenario=='epoch-full':
            text=text.replace('soc=75 mv=4000','soc=99 mv=4180').replace('charging=1 reason=0 full=0','charging=0 reason=-4 full=1')
        if scenario=='epoch-missing-log':text=text.replace(status,'')
        if scenario=='epoch-extended':text=text.replace('000001a6','00000100')
    if scenario=='no-draw':text=text.replace('I9UI1 00000001','I9UI1 00000000')
    if scenario=='no-blank':text=text.replace('01000000 00000001','00000000 00000000')
    if scenario=='wrong-tag':text=text.replace(tag,'aaaaaaaaaaaaaaaa')
    if scenario=='gap':text=text.replace('seq=00000004','seq=00000009')
    if scenario=='wrong-format':text=text.replace('00008035','0000802d')
    if scenario=='wrong-end':text=text.replace('5ed77000','5ee77000')
    if scenario=='panel-unqualified':text=text.replace('I9PL1 00000001','I9PL1 00000000')
    if scenario=='panel-scanout-running':text=text.replace('00001000 00001000','00001000 00001003')
    if scenario=='panel-id-mismatch':text=text.replace('I9PD1 0000003f 000000a1 00000012','I9PD1 0000003f 000000a1 00000013')
    if scenario=='panel-id-partial':text=text.replace('I9PD1 0000003f','I9PD1 00000007')
    if scenario=='recovery-unlimited':text=text.replace('I9PR1 00000000','I9PR1 00000002')
    if scenario=='recovery-error':text=text.replace('I9PR1 00000000 00000000 00000000','I9PR1 00000001 00000001 00000004')
    if scenario=='recovery-stage':text=text.replace('I9PR1 00000000 00000000 00000000 00000003','I9PR1 00000000 00000000 00000000 00000001')
    if scenario=='recovery-without-attempt':text=text.replace('I9PR1 00000000 00000000','I9PR1 00000000 00000001')
    if scenario=='art-invalid-level':text=text.replace('I9CR1 00000001 0000000c','I9CR1 00000001 00000012')
    if scenario=='art-undecoded':text=text.replace('I9CR1 00000001','I9CR1 00000000')
    if scenario=='art-start-not-ready':text=text.replace('I9BT1 00000001','I9BT1 00000000')
    if scenario=='art-stale-voltage':text=text.replace('I9BT1 00000001 0000000b 00000000 00000001 00000fa0','I9BT1 00000001 0000000b 00000000 00000001 00000d00')
    if scenario=='art-redrew-asleep':
        at=text.rfind('I9CR1 00000001 0000000c 00000002 0004e200')
        text=text[:at]+text[at:].replace('I9CR1 00000001 0000000c 00000002 0004e200','I9CR1 00000001 0000000c 00000003 0004e201',1)
    if scenario=='art-fault-asleep':
        at=text.rfind('I9CR1 ')
        text=text[:at]+text[at:].replace('00000001 00000000\n','00000001 00000001\n',1)
    if scenario=='art-soc-advanced':
        # Actual battery SOC advances while asleep, but a sleeping image
        # correctly remains at the earlier sprite level.
        at=text.rfind('I9CHG2 ')
        text=text[:at]+text[at:].replace('soc=75','soc=78',1).replace('0000004b','0000004e',1)
    if scenario=='art-old-partial':
        text=text.replace('I9CR1 00000001 0000000c 00000002 0004e200 00000000 0000001c 00000001 00000000\n','',1)
    if scenario=='art-partial-final':text=text[:-20]
    if scenario=='art-transport-invalid':text=text.replace('000000a0 00000001 00000000','00004000 00000002 00000000')
    if scenario in ('bootstrap-fault','art-bootstrap-fault'):
        text+='I9BF1 00000001 00000005 0000000b 00000001 0000004b 00000fa0 00000001 00000000\n'
    if scenario=='bootstrap-fault-partial':text+='I9BF1 00000001 00000005'
    if scenario=='sense-uncertain':text=text.replace('000003ce 00000001 00000000','000003ce 00000001 00000001')
    if scenario=='sense-no-adc':text=text.replace('000003ff 000003ce','000003fe ffffffff')
    if scenario=='sense-stale':text=text.replace('000007d0 000003ff','000fffff 000003ff')
    if scenario=='sense-wrong-sequence':text=text.replace('I9RG1 00000004','I9RG1 00000005')
    if scenario=='sense-partial':text=text.replace('00000100 00000004 00000000\n','00000100\n')
    if scenario=='sense-duplicate':text=text.replace('I9RG1 00000004','I9CS1 00000004 00015f8d 00000000 000007d0 000003ff 000003ce 00000001 00000000\nI9RG1 00000004')
    if scenario=='sense-readback':text=text.replace('00000100 00000004','00000100 00000000')
    if scenario=='sense-newline':text=text[:text.index('\n',text.rfind('I9RG1 '))]
    if scenario=='art-dirty-unhidden':text=text.replace('000000a0 00000001 00000001 00000001','000000a0 00000000 00000001 00000001')
    if scenario=='art-dirty-too-wide':text=text.replace('I9DR1 00000002 00000a80 00000a80','I9DR1 00000002 00000a80 000fffff')
    if scenario=='art-dirty-no-progress':text=text.replace('000000a0 00000001 00000001 00000001','00000000 00000001 00000001 00000001')
    if scenario=='art-dirty-redrew':
        at=text.rfind('I9DR1 ');text=text[:at]+text[at:].replace('00000a80','00000a81',1)
    if scenario.startswith('policy-'):
        lines=text.splitlines(keepends=True);indices=[n for n,line in enumerate(lines) if line.startswith('I9PS1 ')]
        if indices and scenario not in ('policy-success','policy-missing'):
            at=indices[-1];fields=lines[at].split();values=[int(value,16) for value in fields[1:]]
            if scenario=='policy-wrong-sequence':values[0]+=1
            if scenario=='policy-too-fast':values[1]+=30
            if scenario=='policy-stale':values[2]-=48000000;values[4]-=48000000
            if scenario=='policy-bad-cadence':values[4]+=1
            if scenario=='policy-samples':values[6]=12
            if scenario=='policy-duplicate':lines.insert(at,lines[at])
            elif scenario=='policy-partial':lines[at]='I9PS1 00000004\n'
            else:lines[at]='I9PS1 '+' '.join(f'{value:08x}' for value in values)+'\n'
        text=''.join(lines)
    if scenario=='download-stop-denied':text=text.replace('00000000 00000000 00000000 00000001 00000001 00000000','00000001 00000001 00000000 00000001 00000001 00000000')
    if scenario=='download-stop-uncertain':text=text.replace('00000001 00000001 00000000 00000000\n','00000001 00000001 00000001 00000000\n')
    if scenario=='download-stop-mismatch':text=text.replace('I9DS1 00000004','I9DS1 00000005')
    if scenario=='download-stop-invalid-count':text=text.replace('00000000 00000000 00000000 00000001 00000001 00000000','00000000 00000001 00000000 00000001 00000001 00000000')
    if scenario=='download-stop-partial':text=text.replace('I9DS1 00000004 00000000 00000000 00000000 00000001 00000001 00000000 00000000\n','I9DS1 00000004 00000000\n')
    if scenario=='download-stop-newline':text=text[:text.index('\n',text.rfind('I9DS1 '))]
    if scenario=='route-low-power':text=text.replace('010e0104','010e0105')
    if scenario=='route-no-pump':text=text.replace('010e0104','010e0100')
    if scenario=='route-pull':text=text.replace('00000100 00000004 00000000','00000100 00000004 00000010')
    if scenario=='route-missing-muic':text=text.replace('000003ff','000003df')
    if scenario=='route-accessory':text=text.replace('010e0104','010e0124')
    raw=text.encode();(path/'received.bin').write_bytes(raw)
    write_events(path/'events.jsonl',[dict(phase='CHARGER_IDENTITY',device=dict(device,instance=m.o.CDC.replace('OS6','CHG'))),
        dict(phase='DTR_OK',time='2026-11-19T01:00:00+00:00'),
        dict(phase='CHARGER_RX',bytes=len(raw),total=len(raw),time='2026-11-19T01:02:00+00:00'),
        dict(phase='DONE',bytes=len(raw),time='2026-11-19T01:02:00+00:00'),dict(phase='CLOSED')])

for scenario in ('success','no-draw','no-blank','wrong-tag','gap','wrong-format','wrong-end','shutdown-failure','boot-timeout',
                 'art-success','art-missing','art-redrew-asleep','art-start-not-ready','art-transport-success','art-transport-missing',
                 'bootstrap-fault','bootstrap-fault-partial','art-bootstrap-fault',
                 'handoff-success','handoff-missing','handoff-corrupt',
                 'deadline-success','deadline-missing','deadline-rejected','deadline-extended',
                 'epoch-success','epoch-full','epoch-missing','epoch-rejected','epoch-extended','epoch-missing-log',
                 'stop-success','stop-uncertain','stop-invalid','stop-missing','stop-monitor-dead',
                 'sense-success','sense-missing','sense-uncertain','sense-no-adc','sense-stale',
                 'sense-wrong-sequence','sense-partial','sense-duplicate','sense-readback','sense-newline',
                 'art-dirty-success','art-dirty-missing','art-dirty-unhidden','art-dirty-too-wide','art-dirty-no-progress','art-dirty-redrew',
                 'policy-success','policy-missing','policy-wrong-sequence','policy-too-fast','policy-stale',
                 'policy-bad-cadence','policy-samples','policy-duplicate','policy-partial',
                 'download-stop-success','download-stop-missing','download-stop-denied','download-stop-uncertain',
                 'download-stop-mismatch','download-stop-invalid-count','download-stop-partial','download-stop-newline',
                 'route-success','route-accessory','route-low-power','route-no-pump','route-pull','route-missing-muic'):
    directory=out/scenario;directory.mkdir();calls=[];records=[]
    class Host:
        def inventory(self):return [device]
        def settle(self,seconds):assert seconds==90
    def child(argv,process,seconds,record):
        calls.append(list(map(str,argv)));process.mkdir()
        tool=Path(argv[2]).name
        target=Path(argv[argv.index('--output')+1])
        if tool=='ui-session.py':
            if '--poweroff-on-ready' in argv:
                if scenario=='shutdown-failure':raise RuntimeError('modeled shutdown child STOP')
                owner(target,True)
            else:owner(target,handoff=scenario if scenario.startswith(('handoff-','deadline-','epoch-','stop-')) else None)
        elif tool=='capture-charge-loader.py':charger(target,scenario)
        elif tool=='charge-command.py':
            assert argv[argv.index('--action')+1]=='boot'
            if scenario=='boot-timeout':raise RuntimeError('modeled boot child uncertain; retained')
            target.mkdir();write_events(target/'events.jsonl',[dict(phase='SEND'),dict(phase='ACK'),dict(phase='DONE'),dict(phase='CLOSED')])
        else:raise AssertionError('Unexpected child '+tool)
    actual_manifest=dict(manifest,standalone_charge_art=dict(local_asset=True),
        standalone_charge_transport='transport-' in scenario,standalone_charge_dirty_regions='dirty-' in scenario) if scenario.startswith('art-') else manifest
    if scenario.startswith('handoff-'):actual_manifest=dict(manifest,standalone_charge_handoff=True)
    if scenario.startswith('deadline-'):actual_manifest=dict(manifest,standalone_charge_handoff=True,standalone_charge_deadline_adoption=True)
    if scenario.startswith('epoch-'):actual_manifest=dict(manifest,standalone_charge_handoff=True,standalone_charge_deadline_adoption=True,standalone_charge_shutdown_epoch=True)
    if scenario.startswith('stop-'):actual_manifest=dict(manifest,standalone_charge_handoff=True,charge_stop_confirmation=True)
    if scenario.startswith('sense-'):actual_manifest=dict(manifest,standalone_charge_sense=True)
    if scenario.startswith('route-'):actual_manifest=dict(manifest,standalone_charge_sense=True,charge_route_control_version=1)
    if scenario.startswith('policy-'):actual_manifest=dict(manifest,standalone_charge_single_owner=True)
    if scenario.startswith('download-stop-'):actual_manifest=dict(manifest,standalone_charge_download_stop=True)
    expected_success=scenario in ('success','art-success','art-transport-success','art-dirty-success','handoff-success','deadline-success','epoch-success','epoch-full','stop-success','sense-success','policy-success','download-stop-success','route-success','route-accessory')
    try:m.run_roundtrip(package,actual_manifest,directory,lambda phase,**row:records.append(dict(phase=phase,**row)),child,Host())
    except (ValueError,RuntimeError):assert not expected_success
    else:
        assert expected_success and records[-1]['phase']=='DONE' and records[-1]['writes_to_flash']==0
        assert records[-1]['native_artwork_verified']==scenario.startswith('art-')
        assert records[-1]['charger_handoff_verified']==scenario.startswith(('handoff-','deadline-','epoch-','stop-'))
        assert records[-1]['charger_deadline_verified']==scenario.startswith(('deadline-','epoch-'))
        assert records[-1]['shutdown_charge_epoch_verified']==scenario.startswith('epoch-')
        assert records[-1]['stop_confirmation_verified']==scenario.startswith('stop-')
        assert records[-1]['native_charge_sense_verified']==scenario.startswith(('sense-','route-'))
        assert records[-1]['charger_route_readback_verified']==scenario.startswith('route-')
        assert records[-1]['shared_charge_policy_verified']==scenario.startswith('policy-')
        assert records[-1]['charger_download_stop_verified']==scenario.startswith('download-stop-')
    assert all('odin-loop.py' not in call and 'flash' not in call for call in calls)
    if scenario in ('no-draw','no-blank','wrong-tag','gap','wrong-format','wrong-end'):assert len(calls)==2
    if scenario=='shutdown-failure':assert len(calls)==1
    if scenario=='boot-timeout':assert len(calls)==3
    if scenario=='success':assert len(calls)==4
    if scenario.startswith('sense-'):assert len(calls)==(4 if expected_success else 2)
    if scenario.startswith('route-'):assert len(calls)==(4 if expected_success else 2)
    if scenario.startswith('policy-'):assert len(calls)==(4 if expected_success else 2)
    if scenario.startswith('download-stop-'):assert len(calls)==(4 if expected_success else 2)
    if scenario.startswith('bootstrap-fault'):assert len(calls)==2
    if scenario.startswith(('handoff-','deadline-','epoch-','stop-')):
        assert len(calls)==(2 if scenario in ('epoch-missing-log','epoch-extended') else 4)
    if scenario.startswith('art-'):
        capture=calls[1];assert capture[capture.index('--seconds')+1]=='180'
        assert len(calls)==(4 if expected_success else 2)
    (directory/'result.json').write_text(json.dumps(dict(scenario=scenario,child_count=len(calls),records=records,hardware=False),indent=2)+'\n')
for scenario in ('panel-success','panel-unqualified','panel-scanout-running','panel-missing','panel-id-mismatch','panel-id-partial'):
    directory=out/scenario;charger(directory,scenario)
    try:m.qualify_charger(directory,tag+' '+source,True)
    except ValueError:assert scenario!='panel-success'
    else:assert scenario=='panel-success'
for scenario in ('recovery-success','recovery-unlimited','recovery-error','recovery-stage','recovery-without-attempt','recovery-missing'):
    directory=out/scenario;charger(directory,scenario)
    try:m.qualify_charger(directory,tag+' '+source,True,True)
    except ValueError:assert scenario!='recovery-success'
    else:assert scenario=='recovery-success'
for scenario in ('art-success','art-soc-advanced','art-old-partial','art-missing','art-invalid-level','art-undecoded','art-start-not-ready',
                 'art-stale-voltage','art-redrew-asleep','art-fault-asleep','art-partial-final',
                 'art-transport-success','art-transport-missing','art-transport-invalid','art-bootstrap-fault'):
    directory=out/('decoder-'+scenario);charger(directory,scenario)
    try:m.qualify_charger(directory,tag+' '+source,require_art=True,require_transport='transport-' in scenario)
    except ValueError:assert scenario not in ('art-success','art-soc-advanced','art-old-partial','art-transport-success')
    else:assert scenario in ('art-success','art-soc-advanced','art-old-partial','art-transport-success')

directory=out/'expired-relay';directory.mkdir();write_events(directory/'events.jsonl',[dict(phase='WAIT_EXPIRED')])
records=[];assert not m.wait_resumed(directory,60,lambda phase,**data:records.append(dict(phase=phase,**data)))
assert records[-1]['device_actions']==0
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,scope='Actual no-flash orchestrator and real timed/UI/register decoders; child processes and device I/O are stand-ins'),indent=2)+'\n')
print('PASS actual charger roundtrip ordering; shutdown/boot uncertainty and identity/UI/blank/gap refusal stop later children; no flash child')
print('EVIDENCE',out)
