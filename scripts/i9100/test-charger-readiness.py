#!/usr/bin/env python3
"""Check real readiness ordering with delayed PnP/DOS facades; no serial IO."""
import importlib.util,json
from pathlib import Path
from datetime import datetime
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('charger_readiness_test',here/'charger-readiness.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
repo=here.parents[1];out=repo/'out'/('charger-readiness-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
profile=json.loads((repo/'out/automation/inventory-20261106-211114-download-profile.json').read_text(encoding='utf-8'))
charger=dict(instance=m.CHARGER,port='COM14',status='OK',service='usbser',location=profile['location'])
cases=[]
for name,states,targets,expected in (
    ('pnp-before-dos',[[charger]]*4,[None,None,'\\Device\\USBSER000','\\Device\\USBSER000'],True),
    ('absent-then-ready',[[],[charger],[charger]],[None,'\\Device\\USBSER000','\\Device\\USBSER000'],True),
    ('dos-absent',[[charger]]*12,[None]*12,False),
    ('broken-pnp',[[dict(charger,status='Error')]]*12,[None]*12,False),
    ('wrong-driver',[[dict(charger,service='dg_ssudbus')]],[],False),
    ('wrong-topology',[[dict(charger,location='elsewhere')]],[],False),
    ('duplicate',[[charger,charger]],[],False),
    ('normal-cdc',[[dict(charger,instance=m.CHARGER.replace('CHG','OS6'))]]*12,[None]*12,False)):
    clock=[0];count=[0];queries=[];events=[]
    class Host:
        def inventory(self):
            values=states[min(count[0],len(states)-1)];count[0]+=1;return values
    def target(port):
        queries.append(port);return targets[min(count[0]-1,len(targets)-1)]
    try:value=m.wait_charger(Host(),profile,10,lambda phase,**fields:events.append(dict(phase=phase,**fields)),
        target=target,clock=lambda:clock[0],sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds))
    except (ValueError,TimeoutError):assert not expected
    else:assert expected and value==charger and events[-1]['stable_observations']==2 and events[-1]['serial_openers']==0
    cases.append(dict(name=name,pnp_queries=count[0],native_queries=len(queries),serial_openers=0,events=events))
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,cases=cases),indent=2)+'\n',encoding='utf-8')
print('PASS delayed PnP/DOS readiness, stable interface, identity/driver/topology refusal and no serial opener during wait')
print('EVIDENCE',out)
