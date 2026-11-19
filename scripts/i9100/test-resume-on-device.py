#!/usr/bin/env python3
"""Verify readiness dispatch; no phone inventory, process launch or flash."""
import importlib.util,json
from pathlib import Path
from datetime import datetime
from types import SimpleNamespace
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('resume_dispatch',here/'resume-on-device.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
profile=json.loads((m.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
repo=here.parents[1];out=repo/'out'/('resume-device-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
normal=dict(instance=m.o.CDC,status='OK',port='COM12',service='usbser',location=profile['location'])
charger=dict(normal,instance=normal['instance'].replace('OS6','CHG'),port='COM14')
download=dict(profile,status='OK',port='')
journal=out/'utf8-timeline.jsonl'
records=[dict(phase='DEVICE_STATE',name='USB 串行设备 (COM12)',location='原连接口'),dict(phase='DONE')]
journal.write_text(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in records),encoding='utf-8')
assert m.read_events(journal)==records
partial=out/'unfinished.jsonl';partial.write_bytes(b'{"phase":"DONE"}')
try:m.read_events(partial)
except ValueError:pass
else:raise AssertionError('Unfinished journal accepted')
assert m.device_mode([charger],profile)==(None,'old-charger')
assert m.device_mode([normal],profile)[0]=='cycle'
assert m.device_mode([download],profile)[0]=='bootstrap'
for devices in ([normal,download],[normal,charger],[dict(normal,location='other')],[dict(download,service='dg_ssudbus')]):
    try:m.device_mode(devices,profile)
    except ValueError:pass
    else:raise AssertionError('Unqualified mode selected')
summary=[]
for scenario,states,expect in (
    ('charger-timeout',[[charger]]*6,None),('missing-timeout',[[]]*6,None),
    ('normal-transition',[[charger],[],[normal],[normal]],'cycle'),
    ('download-transition',[[charger],[download],[download]],'bootstrap'),
    ('mode-change',[[normal],[download],[download]],'bootstrap')):
    directory=out/scenario;directory.mkdir();plan=SimpleNamespace(parent=directory,data={'profile':profile})
    time=[0];events=[];count=[0]
    class Host:
        def inventory(self):
            index=min(count[0],len(states)-1);count[0]+=1;return states[index]
    result=m.wait_device(Host(),plan,100,lambda phase,**data:events.append(dict(phase=phase,**data)),
        clock=lambda:time[0],sleep=lambda n:time.__setitem__(0,time[0]+n))
    assert result==expect and not (directory/'started.json').exists()
    summary.append(dict(scenario=scenario,result=result,observations=count[0],seconds=time[0],events=events))
directory=out/'consumed';directory.mkdir();(directory/'started.json').write_text('{}\n')
try:m.wait_device(SimpleNamespace(inventory=lambda:[normal]),SimpleNamespace(parent=directory,data={'profile':profile}),
    100,lambda *a,**kw:None)
except ValueError:pass
else:raise AssertionError('Consumed plan reused')
(out/'result.json').write_text(json.dumps(dict(result='PASS',cases=summary,hardware=False),indent=2)+'\n')
print('PASS old charger read-only wait, bounded timeout, stable normal/download dispatch, topology rejection and consumed-plan refusal')
print('EVIDENCE',out)
