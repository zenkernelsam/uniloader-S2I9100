#!/usr/bin/env python3
"""One explicit, bounded touch test through a BUILD-verified serial handle.

No physical GPIO writes, no command retry. Queue completion is not proof that
the UI accepted a gesture; capture the real framebuffer afterwards.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import struct
import time

HERE=Path(__file__).resolve().parent


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def main():
    f=module('input_forensic','forensic-session.py')
    m=module('input_memory','live-memory.py')
    o=module('input_odin','odin-loop.py')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    gestures=p.add_mutually_exclusive_group(required=True)
    gestures.add_argument('--tap',type=int,nargs=2,metavar=('X','Y'))
    gestures.add_argument('--swipe',type=int,nargs=4,metavar=('X0','Y0','X1','Y1'))
    gestures.add_argument('--home',action='store_true')
    p.add_argument('--ms',type=int)
    a=p.parse_args()
    points=([0,0,0,0] if a.home else a.swipe if a.swipe else a.tap+a.tap)
    ms=a.ms if a.ms is not None else (200 if a.home else 400 if a.swipe else 100)
    command=('hid-home '+format(ms,'x') if a.home else 'hid-swipe '+' '.join(format(n,'x') for n in [*points,ms]))
    f.validate_command(command,allow_input_test=True)
    symbols=m.Symbols(a.kernel)
    o.require('_i9100_input_test' in symbols.values,'Kernel has no input mailbox')
    out=o.confined(a.output,f.REPO/'out');o.require(not out.exists(),'Fresh output directory required')
    profile=json.loads((f.REPO/'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location'])==profile['location'],'No approved live CDC')
        out.mkdir(parents=True);transport=None
        with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','STOP','DONE'):print(json.dumps(row),flush=True)
            try:
                transport=f.WinTransport(device['port'],record)
                session=f.Session(transport,symbols.tag,record,capture,timeout=20,allow_input_test=True)
                session.handshake();kernel=m.Kernel(session,symbols)
                address=symbols['_i9100_input_test']
                before=struct.unpack('<16I',kernel.read(address,64))
                o.require(before[0]==1 and before[14 if a.home else 12]==1 and before[1] in (1,4,5),'Input disabled or reader not ready; no command sent')
                reply,_=session.command(command)
                o.require(reply=='OK input-queued','Input request was not accepted')
                deadline=time.monotonic()+5
                samples=[]
                while True:
                    state=struct.unpack('<16I',kernel.read(address,64));samples.append(list(state))
                    o.require(list(state[3:8])==[*points,ms] and state[2]==before[2]+1 and state[13]==int(a.home),'Mailbox ownership changed')
                    if state[1]==4:break
                    o.require(state[1]!=5,'Input canceled for physical input or closed reader')
                    o.require(time.monotonic()<deadline,'Input queue completion timeout; no resend')
                    time.sleep(.1)
                result=dict(tag=symbols.tag,device=device,command=command,sequence=state[2],
                    enqueued=state[8],phase=state[1],queue_completed=True,ui_delivery_verified=False,samples=samples)
                (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps(result,indent=2),flush=True);record('DONE',queue_only=True)
            except BaseException as exc:record('STOP',error=str(exc),retry=False);raise
            finally:
                if transport is not None:transport.close()


if __name__=='__main__':main()
