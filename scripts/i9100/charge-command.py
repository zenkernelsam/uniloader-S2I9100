#!/usr/bin/env python3
"""One exact build-matched charger boot/download action on one native handle.

Never used on an old charger lacking I9CHC2 READY. No write until its matching
handshake, no command resend, flash, reset ioctl or opener retry.
"""
import argparse,importlib.util,json,re,time,hashlib
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
def module(name,file):
 s=importlib.util.spec_from_file_location(name,here/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
f=module('charge_command_forensic','forensic-session.py');o=module('charge_command_odin','odin-loop.py')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True)
 p.add_argument('--action',choices=('boot','download'),required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();package=o.confined(a.package,f.REPO/'out');manifest=json.loads((package/'manifest.json').read_text())
 o.require(manifest.get('standalone_charge_control') is True,'Offline package lacks a qualified charger command channel')
 o.require(manifest.get('standalone_charge_control_version')==2,'Old charger protocol rejected before opening a port')
 expected=manifest['control_tag'];o.require(re.fullmatch('[0-9a-f]{16}',expected),'Exact package build tag required')
 charger_tag=manifest.get('standalone_charge_control_tag','')
 o.require(re.fullmatch('[0-9a-f]{16}',charger_tag),'Source-qualified charger tag required')
 identity=json.loads((package/'charger-identity.json').read_text())
 o.require(identity.get('schema')==2 and identity.get('tag')==charger_tag and
    identity.get('kernel_sha256')==manifest['artifacts']['mach_kernel']['sha256'],
    'Charger identity record differs from the package')
 identity_input={key:identity[key] for key in ('schema','kernel_sha256','sources','flags')}
 o.require(hashlib.sha256(json.dumps(identity_input,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]==charger_tag,
    'Charger source/profile identity does not reproduce its tag')
 for name in ('zImage','mach_kernel'):
  artifact=manifest['artifacts'][name];path=package/name
  o.require(path.stat().st_size==artifact['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest()==artifact['sha256'],'Package artifact differs before device access')
 o.require(b'I9CHC2 READY ' in (package/'zImage').read_bytes() and (charger_tag+'\0').encode() in (package/'zImage').read_bytes(),
    'Charger protocol/source tag absent from the actual loader binary')
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
   def wait_for(expected_line,error_prefix=None):
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
       if data==expected_line:return
       if data.startswith(b'I9CHC') and b' READY ' in data and data!=f'I9CHC2 READY {expected} {charger_tag}'.encode():
        raise RuntimeError('Charger kernel/source identity differs; action not sent')
       if error_prefix and data.startswith(error_prefix):
        raise RuntimeError(data.decode('ascii','strict'))
      elif byte<32 or byte>126 or len(line)>=160:drop=True
      elif not drop:line.append(byte)
    raise TimeoutError('Charger reply timeout; no resend')
   try:
    transport=f.WinTransport(devices[0]['port'],record)
    wait_for(f'I9CHC2 READY {expected} {charger_tag}'.encode());record('IDENTITY_OK',tag=expected,charger_tag=charger_tag)
    seq=transport.ticks()&0xffffffff;o.require(seq>0,'Nonzero fresh sequence required')
    wire=f'I9CHC2 {seq:08x} {expected} {charger_tag} {a.action}\n'.encode()
    record('SEND',sequence=seq,action=a.action,bytes=len(wire));transport.write(wire)
    wait_for(f'I9CHC2 {seq:08x} OK {a.action}'.encode(),f'I9CHC2 {seq:08x} ERR '.encode());record('ACK',sequence=seq,action=a.action)
    record('DONE',meaning='Exact ACK; destination enumeration still requires separate observation')
   except BaseException as error:record('STOP',error=str(error),retry=False);raise
   finally:
    if transport:transport.close()
    record('CLOSED')
if __name__=='__main__':main()
