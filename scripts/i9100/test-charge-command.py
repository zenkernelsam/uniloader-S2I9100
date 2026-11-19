#!/usr/bin/env python3
"""Exercise one-shot charger maintenance with a fake native transport.

Package integrity is real; USB inventory/read/write/time are explicitly modeled.
No device access or removal. Each failure keeps its original evidence directory.
"""
import argparse,importlib.util,json,sys
from contextlib import nullcontext
from pathlib import Path
from datetime import datetime
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('charger_command',here/'charge-command.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
repo=here.parents[1];package=a.package.resolve();assert package.is_relative_to(repo/'out')
manifest=json.loads((package/'manifest.json').read_text());tag=manifest['control_tag']
charger_tag=manifest['standalone_charge_control_tag'];assert manifest['standalone_charge_control_version']==2
out=repo/'out'/('charge-command-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
profile=json.loads((m.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
class Host:
    def inventory(self):return [dict(instance='USB\\VID_0525&PID_A4A7\\S2I9100-CHG',service='usbser',location=profile['location'],port='COM14')]
m.o.host_lock=lambda:nullcontext();m.o.Host=Host
cases=[]
original_clock=m.time.monotonic
for scenario in ('boot','download','missing-ready','wrong-tag','wrong-loader','wrong-ack','boot-refused','overflow-ready','fragmented-ready'):
    clock=[0.0];m.time.monotonic=lambda:clock[0];instances=[]
    class Transport:
        def __init__(self,port,record):
            assert port=='COM14';self.closed=False;self.writes=[];instances.append(self)
            if scenario=='missing-ready':self.queue=[]
            elif scenario=='wrong-tag':self.queue=[f'I9CHC2 READY 0000000000000000 {charger_tag}\n'.encode()]
            elif scenario=='wrong-loader':self.queue=[f'I9CHC2 READY {tag} 0000000000000000\n'.encode()]
            elif scenario=='fragmented-ready':
                ready=f'I9CHC2 READY {tag} {charger_tag}\n'.encode();self.queue=[ready[:11],ready[11:27],ready[27:]]
            else:self.queue=[(b'x'*200+b'\n' if scenario=='overflow-ready' else b'')+f'I9CHC2 READY {tag} {charger_tag}\n'.encode()]
        def ticks(self):return 123
        def read(self):clock[0]+=1;return self.queue.pop(0) if self.queue else b''
        def write(self,wire):
            self.writes.append(wire);action='download' if scenario=='download' else 'boot'
            assert wire==f'I9CHC2 0000007b {tag} {charger_tag} {action}\n'.encode()
            if scenario=='wrong-ack':self.queue.append(b'I9CHC2 0000007c OK boot\n')
            elif scenario=='boot-refused':self.queue.append(b'I9CHC2 0000007b ERR boot-unavailable\n')
            else:self.queue.append(f'I9CHC2 0000007b OK {action}\n'.encode())
        def close(self):self.closed=True
    m.f.WinTransport=Transport
    action='download' if scenario=='download' else 'boot'
    sys.argv=['charge-command.py','--package',str(package),'--action',action,'--output',str(out/scenario)]
    failed=False
    try:m.main()
    except (RuntimeError,TimeoutError):failed=True
    assert len(instances)==1 and instances[0].closed
    expect_failure=scenario in ('missing-ready','wrong-tag','wrong-loader','wrong-ack','boot-refused');assert failed==expect_failure
    assert len(instances[0].writes)==(0 if scenario in ('missing-ready','wrong-tag','wrong-loader') else 1)
    if scenario=='boot-refused':assert clock[0]<20,'Explicit boot refusal became a timeout'
    rows=[json.loads(x) for x in (out/scenario/'events.jsonl').read_text().splitlines()]
    assert rows[-1]['phase']=='CLOSED' and ('ACK' in [r['phase'] for r in rows])==(not expect_failure)
    cases.append(dict(scenario=scenario,failed=failed,writes=len(instances[0].writes)))
m.time.monotonic=original_clock
(out/'result.json').write_text(json.dumps(dict(result='PASS',cases=cases,hardware=False,scope='Actual command flow and package integrity; native transport facade'),indent=2)+'\n')
print('PASS kernel/source READY and exact ACK; no writes before both identities; explicit refusal, fragment/overflow framing, no resend and normal close')
print('EVIDENCE',out)
