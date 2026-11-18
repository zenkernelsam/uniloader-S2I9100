#!/usr/bin/env python3
"""One opener for the distinct standalone-charger identity; log capture only."""
import argparse,importlib.util,json,re,time,os
from pathlib import Path
from datetime import datetime,timezone
here=Path(__file__).resolve().parent
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
f=module('charger_forensic',here/'forensic-session.py');o=module('charger_odin',here/'odin-loop.py')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=120);p.add_argument('--wait',type=int,default=180);a=p.parse_args()
 if not 10<=a.seconds<=1800 or not 0<=a.wait<=1800:p.error('Bounded capture/wait required')
 out=o.confined(a.output,f.REPO/'out');o.require(not out.exists(),'Fresh charger evidence required')
 profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
 with o.host_lock():
  out.mkdir(parents=True)
  with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
   def record(phase,**kw):
    row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw);events.write(json.dumps(row)+'\n');events.flush();print(json.dumps(row),flush=True)
   record('BEGIN',pid=os.getpid(),writes=0);transport=None
   try:
    end=time.monotonic()+a.wait;device=None;host=o.Host()
    while True:
     candidates=[d for d in host.inventory() if d.get('instance','').upper().endswith('S2I9100-CHG')]
     if candidates:
      o.require(len(candidates)==1,'Distinct charger identity ambiguous');device=candidates[0];break
     if time.monotonic()>=end:raise TimeoutError('Charger identity absent; no opener attempted')
     time.sleep(1)
    o.require(device.get('service','').lower()=='usbser' and o.normalize_location(device['location'])==profile['location'],'Approved charger location/driver differs')
    record('CHARGER_IDENTITY',device=device);transport=f.WinTransport(device['port'],record)
    end=time.monotonic()+a.seconds
    while time.monotonic()<end:
     data=transport.read()
     if data:capture.write(data);capture.flush()
    record('DONE',bytes=capture.tell(),writes=0)
   except BaseException as error:record('STOP',error=str(error),retry=False);raise
   finally:
    if transport:transport.close()
    record('CLOSED')
if __name__=='__main__':main()
