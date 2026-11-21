#!/usr/bin/env python3
"""Capture and qualify the new charger, then issue one boot on the same handle.

One opener and one DTR only. Failed/partial identity, observation, write or ACK
stops the session without retry or forced termination. The exact pre-command
observation is retained while the owner remains open, never marked CLOSED.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import time

HERE=Path(__file__).resolve().parent
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
f=module('verified_charge_forensic','forensic-session.py')
o=module('verified_charge_odin','odin-loop.py')
readiness=module('verified_charge_readiness','charger-readiness.py')
check=module('verified_charge_roundtrip','verify-charge-roundtrip.py')

def utc_now():return datetime.now(timezone.utc).isoformat()
def digest(raw):return hashlib.sha256(raw).hexdigest()

class Receiver:
    def __init__(self,tag,charger):
        self.expected=f'I9CHC2 READY {tag} {charger}'.encode()
        self.line=bytearray();self.drop=False;self.ready=False;self.ack=False;self.sequence=None
    def feed(self,raw):
        for byte in raw:
            if byte==13:continue
            if byte==10:
                line=bytes(self.line);self.line.clear();bad=self.drop;self.drop=False
                if bad:continue
                if line.startswith(b'I9CHC') and b' READY ' in line:
                    if line!=self.expected:raise ValueError('Wrong charger BUILD/source identity; no action')
                    self.ready=True
                if self.sequence is not None and line.startswith(f'I9CHC2 {self.sequence:08x} '.encode()):
                    if line!=f'I9CHC2 {self.sequence:08x} OK boot'.encode():
                        raise ValueError(line.decode('ascii','strict'))
                    self.ack=True
            elif byte<32 or byte>126 or len(self.line)>=256:self.drop=True
            elif not self.drop:self.line.append(byte)

def read_package(package):
    manifest=json.loads((package/'manifest.json').read_text(encoding='utf8'))
    for flag in ('standalone_charge','standalone_charge_control','standalone_charge_first_packet_liveness'):
        o.require(manifest.get(flag) is True,'New source-qualified charger package required')
    o.require(manifest.get('standalone_charge_control_version')==2,'Exact new protocol required')
    for name in ('zImage','mach_kernel'):
        expected=manifest['artifacts'][name];file=package/name
        o.require(file.stat().st_size==expected['bytes'] and o.sha(file)==expected['sha256'],'Package changed')
    tag=manifest['control_tag'];charger=manifest['standalone_charge_control_tag']
    o.require(re.fullmatch('[0-9a-f]{16}',tag) and re.fullmatch('[0-9a-f]{16}',charger) and
        tag==manifest['artifacts']['mach_kernel']['sha256'][:16],'Exact actual kernel/source tag required')
    identity=json.loads((package/'charger-identity.json').read_text(encoding='utf8'))
    inputs={key:identity[key] for key in ('schema','kernel_sha256','sources','flags')}
    expected=digest(json.dumps(inputs,sort_keys=True,separators=(',',':')).encode())[:16]
    o.require(inputs['schema']==2 and inputs['kernel_sha256']==manifest['artifacts']['mach_kernel']['sha256'] and
        identity['tag']==charger==expected,'Source identity changed')
    image=(package/'zImage').read_bytes()
    o.require(b'I9CHC2 READY ' in image and (charger+'\0').encode() in image and b'I9LV1 ' in image and b'I9RT1 ' in image,
        'Actual charger binary lacks its source tag and required observation paths')
    art=manifest.get('standalone_charge_art')
    if art:
        file=o.confined(o.ROOT/art['path'],o.ROOT/'assets')
        o.require(file.stat().st_size==art['bytes'] and o.sha(file)==art['sha256'] and file.read_bytes() in image,
            'Original charging artwork differs from the actual package')
    return manifest

def qualify_observation(directory,manifest):
    value=check.qualify_charger(directory,manifest['control_tag']+' '+manifest['standalone_charge_control_tag'],
        manifest.get('panel_sleep') is True,manifest.get('standalone_panel_recovery') is True,
        manifest.get('standalone_charge_art') is not None,manifest.get('standalone_charge_transport') is True,
        manifest.get('standalone_charge_sense') is True,manifest.get('standalone_charge_dirty_regions') is True,
        manifest.get('standalone_charge_single_owner') is True,manifest.get('standalone_charge_download_stop') is True,
        manifest.get('charge_route_control_version')==1,True,True)
    # Buffered startup logs do not prove continuous monitoring now. Require
    # the final device groups to have arrived across a real host interval.
    samples=[row for row in value['summary']['samples'] if row['version']==2][-3:]
    arrivals=[datetime.fromisoformat(row['host_received_at']) for row in samples]
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    ended=datetime.fromisoformat(events[-1]['time'])
    o.require((arrivals[-1]-arrivals[0]).total_seconds()>=48 and
        0<=(ended-arrivals[-1]).total_seconds()<=45,'Only buffered or stale charging reports received')
    return value

def run(package,out,seconds,wait,transport_factory=f.WinTransport,host=None):
    manifest=read_package(package);tag=manifest['control_tag'];charger=manifest['standalone_charge_control_tag']
    profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    o.require(not out.exists() and 90<=seconds<=300 and 0<=wait<=180,'Fresh bounded session required')
    with o.host_lock():
        out.mkdir(parents=True);transport=None;receiver=Receiver(tag,charger);sent=False
        with (out/'events.jsonl').open('x',encoding='utf8') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**data):
                row=dict(time=utc_now(),phase=phase,**data);events.write(json.dumps(row)+'\n');events.flush()
                if phase!='CHARGER_RX':print(json.dumps(row),flush=True)
            def receive():
                raw=transport.read()
                if raw:
                    o.require(capture.tell()+len(raw)<=64*1024*1024,'Bounded charger capture exhausted')
                    capture.write(raw);capture.flush();record('CHARGER_RX',bytes=len(raw),total=capture.tell());receiver.feed(raw)
                return raw
            record('BEGIN',pid=os.getpid(),openers=1,writes=0)
            try:
                device=readiness.wait_charger(host or o.Host(),profile,wait,record)
                record('CHARGER_IDENTITY',device=device)
                transport=transport_factory(device['port'],record)
                end=time.monotonic()+20
                while not receiver.ready:
                    o.require(time.monotonic()<end,'Charger READY timeout; no reopen')
                    receive()
                record('IDENTITY_OK',tag=tag,charger_tag=charger)
                end=time.monotonic()+seconds
                while time.monotonic()<end:receive()
                record('OBSERVATION_COMPLETE',bytes=capture.tell(),writes=0,tag=tag,charger_tag=charger)
                observation=out/'observation';observation.mkdir()
                retained=(out/'received.bin').read_bytes();journal=(out/'events.jsonl').read_bytes()
                (observation/'received.bin').write_bytes(retained);(observation/'events.jsonl').write_bytes(journal)
                # No fabricated terminal events: this is a frozen, completed
                # capture interval while its original command owner is alive.
                began_qualification=time.monotonic()
                qualification=qualify_observation(observation,manifest)
                (out/'charger-qualified.json').write_text(json.dumps(qualification,indent=2)+'\n',encoding='utf8')
                o.require(time.monotonic()-began_qualification<5,'Qualification took too long for the latest live status; no boot')
                record('CHARGER_QUALIFIED',observation_sha256=digest(retained),bytes=len(retained))
                # Boot can follow only this live handle's latest qualifier.
                # Do not reopen if the call fails; never synthesize a nonce.
                sequence=transport.ticks()&0xffffffff
                o.require(0<sequence<0xffffffff,'Invalid command nonce')
                receiver.sequence=sequence
                wire=f'I9CHC2 {sequence:08x} {tag} {charger} boot\n'.encode()
                o.require(not sent,'Second command refused');sent=True
                record('SEND',sequence=sequence,action='boot',bytes=len(wire));transport.write(wire)
                end=time.monotonic()+20
                while not receiver.ack:
                    o.require(time.monotonic()<end,'Boot ACK timeout; no resend');receive()
                record('ACK',sequence=sequence,action='boot')
                record('DONE',bytes=capture.tell(),writes=1,meaning='One qualified interval and one exact boot ACK on the same handle')
            except BaseException as error:record('STOP',error=str(error),retry=False,command_sent=sent);raise
            finally:
                if transport:transport.close()
                capture.flush();record('CLOSED')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=180)
    p.add_argument('--wait',type=int,default=180);a=p.parse_args()
    run(o.confined(a.package,f.REPO/'out'),o.confined(a.output,f.REPO/'out'),a.seconds,a.wait)
if __name__=='__main__':main()
