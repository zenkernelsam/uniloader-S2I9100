#!/usr/bin/env python3
"""One exact build-matched charger boot/download action on one native handle.

Never used on an old charger lacking I9CHC1 READY. No write until its matching
handshake, no command resend, flash, reset ioctl or opener retry.
"""
import argparse,importlib.util,json,re,time
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
def module(name,file):
 s=importlib.util.spec_from_file_location(name,here/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
f=module('charge_command_forensic','forensic-session.py');o=module('charge_command_odin','odin-loop.py')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--expect',required=True)
 p.add_argument('--action',choices=('boot','download'),required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();o.require(re.fullmatch('[0-9a-f]{16}',a.expect),'Exact expected build tag required')
 out=o.confined(a.output,f.REPO/'out');o.require(not out.exists(),'Fresh evidence required')
 profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
 with o.host_lock():
  devices=[d for d in o.Host().inventory() if d.get('instance','').upper().endswith('S2I9100-CHG')]
  o.require(len(devices)==1 and devices[0]['service'].lower()=='usbser' and o.normalize_location(devices[0]['location'])==profile['location'],'Approved distinct charger absent')
  out.mkdir(parents=True);transport=None
  with (out/'events.jsonl').open('x',encoding='utf-8') as events,(out/'received.bin').open('xb') as capture:
   def record(phase,**data):
    row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**data);events.write(json.dumps(row)+'\n');events.flush()
    if phase in ('OPEN_OK','DTR_OK','IDENTITY_OK','SEND','ACK','DONE','STOP','CLOSED'):print(json.dumps(row),flush=True)
   line=bytearray();drop=False
   def wait_for(expected):
    nonlocal drop,line
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
     raw=transport.read()
     if raw:capture.write(raw);capture.flush()
     for byte in raw:
      if byte==13:continue
      if byte==10:
       data=bytes(line);line.clear();bad=drop;drop=False
       if bad:continue
       if data==expected:return
       if data.startswith(b'I9CHC1 READY ') and data!=('I9CHC1 READY '+a.expect).encode():raise RuntimeError('Charger build differs; action not sent')
      elif byte<32 or byte>126 or len(line)>=160:drop=True
      elif not drop:line.append(byte)
    raise TimeoutError('Charger reply timeout; no resend')
   try:
    transport=f.WinTransport(devices[0]['port'],record)
    wait_for(('I9CHC1 READY '+a.expect).encode());record('IDENTITY_OK',tag=a.expect)
    seq=transport.ticks()&0xffffffff;o.require(seq>0,'Nonzero fresh sequence required')
    wire=f'I9CHC1 {seq:08x} {a.expect} {a.action}\n'.encode()
    record('SEND',sequence=seq,action=a.action,bytes=len(wire));transport.write(wire)
    wait_for(f'I9CHC1 {seq:08x} OK {a.action}'.encode());record('ACK',sequence=seq,action=a.action)
    record('DONE',meaning='Exact ACK; destination enumeration still requires separate observation')
   except BaseException as error:record('STOP',error=str(error),retry=False);raise
   finally:
    if transport:transport.close()
    record('CLOSED')
if __name__=='__main__':main()
