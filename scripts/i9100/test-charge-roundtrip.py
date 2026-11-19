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
        raw=struct.pack('<32I',*words);words[31]=m.h.checksum(raw);raw=struct.pack('<32I',*words)
        decoded=m.h.decode(raw)
        observed=dict(decoded,root_stable=True,kernel_tag=tag)
        charge=dict(charger_handoff=observed)
        if handoff.startswith('deadline-') and handoff!='deadline-missing':
            start=max(1,decoded['sampled_ticks']*1000//24-(decoded['elapsed_seconds']+1)*1000000000)
            charge['charger_deadline_adoption']=dict(consistent=True,state=1,revision=14,enabled_after_init=0,
                full=0,recharging=0,timeout=0,charge_start_ns=start,deadline_seconds=18000)
            if handoff=='deadline-rejected':charge['charger_deadline_adoption'].update(state=3,timeout=1)
            if handoff=='deadline-extended':charge['charger_deadline_adoption']['charge_start_ns']+=1000000000
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
        lines.append('I9UI1 00000001 5ec00000 00000780 00000020\n')
        lines.append('I9FB1 00000000 00008035 5ec00000 00000780 000efb1f 5ed77000 01000000 00000001\n')
        if scenario.startswith('art-') and scenario!='art-missing':
            # Native frame 12 is the measured 75% level. Repeated blank
            # reports keep frames/stores fixed while device time advances.
            lines.append('I9CR1 00000001 0000000c 00000002 0004e200 00000000 0000001c 00000001 00000000\n')
            lines.append('I9BT1 00000001 0000000b 00000000 00000001 00000fa0 0000004b 00000000 00000000\n')
            if 'transport-' in scenario and scenario!='art-transport-missing':
                lines.append('I9UT1 00040000 80488200 20080040 00000000 00000180 000000a0 00000001 00000000\n')
        if scenario in ('panel-success','panel-unqualified','panel-scanout-running','panel-id-mismatch','panel-id-partial') or scenario.startswith('recovery-'):
            lines.append('I9PL1 00000001 00000003 00000000 00000000 00000002 00001003 00001000 00001000\n')
            lines.append('I9PD1 0000003f 000000a1 00000012 00000011\n')
            if scenario.startswith('recovery-') and scenario!='recovery-missing':
                lines.append('I9PR1 00000000 00000000 00000000 00000003\n')
    text=''.join(lines)
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
    raw=text.encode();(path/'received.bin').write_bytes(raw)
    write_events(path/'events.jsonl',[dict(phase='CHARGER_IDENTITY',device=dict(device,instance=m.o.CDC.replace('OS6','CHG'))),
        dict(phase='DTR_OK',time='2026-11-19T01:00:00+00:00'),
        dict(phase='CHARGER_RX',bytes=len(raw),total=len(raw),time='2026-11-19T01:02:00+00:00'),
        dict(phase='DONE',bytes=len(raw),time='2026-11-19T01:02:00+00:00'),dict(phase='CLOSED')])

for scenario in ('success','no-draw','no-blank','wrong-tag','gap','wrong-format','wrong-end','shutdown-failure','boot-timeout',
                 'art-success','art-missing','art-redrew-asleep','art-start-not-ready','art-transport-success','art-transport-missing',
                 'bootstrap-fault','bootstrap-fault-partial','art-bootstrap-fault',
                 'handoff-success','handoff-missing','handoff-corrupt',
                 'deadline-success','deadline-missing','deadline-rejected','deadline-extended'):
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
            else:owner(target,handoff=scenario if scenario.startswith(('handoff-','deadline-')) else None)
        elif tool=='capture-charge-loader.py':charger(target,scenario)
        elif tool=='charge-command.py':
            assert argv[argv.index('--action')+1]=='boot'
            if scenario=='boot-timeout':raise RuntimeError('modeled boot child uncertain; retained')
            target.mkdir();write_events(target/'events.jsonl',[dict(phase='SEND'),dict(phase='ACK'),dict(phase='DONE'),dict(phase='CLOSED')])
        else:raise AssertionError('Unexpected child '+tool)
    actual_manifest=dict(manifest,standalone_charge_art=dict(local_asset=True),
        standalone_charge_transport='transport-' in scenario) if scenario.startswith('art-') else manifest
    if scenario.startswith('handoff-'):actual_manifest=dict(manifest,standalone_charge_handoff=True)
    if scenario.startswith('deadline-'):actual_manifest=dict(manifest,standalone_charge_handoff=True,standalone_charge_deadline_adoption=True)
    expected_success=scenario in ('success','art-success','art-transport-success','handoff-success','deadline-success')
    try:m.run_roundtrip(package,actual_manifest,directory,lambda phase,**row:records.append(dict(phase=phase,**row)),child,Host())
    except (ValueError,RuntimeError):assert not expected_success
    else:
        assert expected_success and records[-1]['phase']=='DONE' and records[-1]['writes_to_flash']==0
        assert records[-1]['native_artwork_verified']==scenario.startswith('art-')
        assert records[-1]['charger_handoff_verified']==scenario.startswith(('handoff-','deadline-'))
        assert records[-1]['charger_deadline_verified']==scenario.startswith('deadline-')
    assert all('odin-loop.py' not in call and 'flash' not in call for call in calls)
    if scenario in ('no-draw','no-blank','wrong-tag','gap','wrong-format','wrong-end'):assert len(calls)==2
    if scenario=='shutdown-failure':assert len(calls)==1
    if scenario=='boot-timeout':assert len(calls)==3
    if scenario=='success':assert len(calls)==4
    if scenario.startswith('bootstrap-fault'):assert len(calls)==2
    if scenario.startswith(('handoff-','deadline-')):assert len(calls)==4
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
