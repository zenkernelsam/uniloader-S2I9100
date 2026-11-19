#!/usr/bin/env python3
"""Exercise actual roundtrip orchestration with local retained evidence only."""
import importlib.util,json
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
def owner(path,shutdown=False):
    path.mkdir();(path/'owner.json').write_text(json.dumps(dict(pid=123,tag=tag,process_created_100ns=456))+'\n')
    events=[dict(phase='READY',pid=123,tag=tag)]
    if shutdown:
        target=path/'task-0001';target.mkdir()
        (target/'result.json').write_text(json.dumps(dict(reply='OK poweroff-charge',shutdown_disconnect_observed=True))+'\n')
        events.append(dict(phase='TASK_DONE',id='0001',action='poweroff-charge'))
    events.extend([dict(phase='DONE'),dict(phase='CLOSED')]);write_events(path/'events.jsonl',events)

def charger(path,scenario):
    path.mkdir();lines=[f'I9CHC2 READY {tag} {source}\n']
    for seq in range(1,5):
        ms=(seq-1)*30000
        lines.append(f'I9CHG2 seq={seq:08x} ms={ms:016x} valid=1 soc=75 mv=4000 temp=250 charging=1 reason=0 full=0 timeout=0 recharging=0 elapsed={ms//1000}\n')
        lines.append('I9UI1 00000001 5ec00000 00000780 00000020\n')
        lines.append('I9FB1 00000000 00008035 5ec00000 00000780 000efb1f 5ed77000 01000000 00000001\n')
        if scenario in ('panel-success','panel-unqualified','panel-scanout-running'):
            lines.append('I9PL1 00000001 00000003 00000000 00000000 00000002 00001003 00001000 00001000\n')
    text=''.join(lines)
    if scenario=='no-draw':text=text.replace('I9UI1 00000001','I9UI1 00000000')
    if scenario=='no-blank':text=text.replace('01000000 00000001','00000000 00000000')
    if scenario=='wrong-tag':text=text.replace(tag,'aaaaaaaaaaaaaaaa')
    if scenario=='gap':text=text.replace('seq=00000004','seq=00000009')
    if scenario=='wrong-format':text=text.replace('00008035','0000802d')
    if scenario=='wrong-end':text=text.replace('5ed77000','5ee77000')
    if scenario=='panel-unqualified':text=text.replace('I9PL1 00000001','I9PL1 00000000')
    if scenario=='panel-scanout-running':text=text.replace('00001000 00001000','00001000 00001003')
    raw=text.encode();(path/'received.bin').write_bytes(raw)
    write_events(path/'events.jsonl',[dict(phase='CHARGER_IDENTITY',device=dict(device,instance=m.o.CDC.replace('OS6','CHG'))),
        dict(phase='DTR_OK',time='2026-11-19T01:00:00+00:00'),
        dict(phase='CHARGER_RX',bytes=len(raw),total=len(raw),time='2026-11-19T01:02:00+00:00'),
        dict(phase='DONE',bytes=len(raw),time='2026-11-19T01:02:00+00:00'),dict(phase='CLOSED')])

for scenario in ('success','no-draw','no-blank','wrong-tag','gap','wrong-format','wrong-end','shutdown-failure','boot-timeout'):
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
            else:owner(target)
        elif tool=='capture-charge-loader.py':charger(target,scenario)
        elif tool=='charge-command.py':
            assert argv[argv.index('--action')+1]=='boot'
            if scenario=='boot-timeout':raise RuntimeError('modeled boot child uncertain; retained')
            target.mkdir();write_events(target/'events.jsonl',[dict(phase='SEND'),dict(phase='ACK'),dict(phase='DONE'),dict(phase='CLOSED')])
        else:raise AssertionError('Unexpected child '+tool)
    try:m.run_roundtrip(package,manifest,directory,lambda phase,**row:records.append(dict(phase=phase,**row)),child,Host())
    except (ValueError,RuntimeError):assert scenario!='success'
    else:assert scenario=='success' and records[-1]['phase']=='DONE' and records[-1]['writes_to_flash']==0
    assert all('odin-loop.py' not in call and 'flash' not in call for call in calls)
    if scenario in ('no-draw','no-blank','wrong-tag','gap','wrong-format','wrong-end'):assert len(calls)==2
    if scenario=='shutdown-failure':assert len(calls)==1
    if scenario=='boot-timeout':assert len(calls)==3
    if scenario=='success':assert len(calls)==4
    (directory/'result.json').write_text(json.dumps(dict(scenario=scenario,child_count=len(calls),records=records,hardware=False),indent=2)+'\n')
for scenario in ('panel-success','panel-unqualified','panel-scanout-running','panel-missing'):
    directory=out/scenario;charger(directory,scenario)
    try:m.qualify_charger(directory,tag+' '+source,True)
    except ValueError:assert scenario!='panel-success'
    else:assert scenario=='panel-success'

directory=out/'expired-relay';directory.mkdir();write_events(directory/'events.jsonl',[dict(phase='WAIT_EXPIRED')])
records=[];assert not m.wait_resumed(directory,60,lambda phase,**data:records.append(dict(phase=phase,**data)))
assert records[-1]['device_actions']==0
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,scope='Actual no-flash orchestrator and real timed/UI/register decoders; child processes and device I/O are stand-ins'),indent=2)+'\n')
print('PASS actual charger roundtrip ordering; shutdown/boot uncertainty and identity/UI/blank/gap refusal stop later children; no flash child')
print('EVIDENCE',out)
