#!/usr/bin/env python3
"""Observe bounded UI/media state and natural panic on one verified handle.

The user authorizes device access separately. No flash, input, reset, lock
patch, serial resend or second opener. The retained bytes belong to a sequence
of observations, not an atomic snapshot. A refused memory command preserves
the current panic first through SnapshotSession's original handle.
"""
import argparse
from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import time

HERE=Path(__file__).resolve().parent
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
    boot=module('watch_boot','capture-boot-snapshot.py');o=boot.o
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seconds',type=int,choices=range(30,601),default=240);a=p.parse_args()
    out=o.confined(a.output,boot.f.REPO/'out');o.require(not out.exists(),'Fresh health evidence required')
    symbols=boot.m.Symbols(o.confined(a.kernel,boot.f.REPO/'out'))
    profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory());o.require(device and device['service'].lower()=='usbser' and o.normalize_location(device['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields);events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','SAMPLE','PANIC_TRANSITION_SAVED','PANIC_TRANSITION_STOP','DONE','STOP','CLOSED'):print(json.dumps(row),flush=True)
            try:
                with boot.open_session(device,symbols.tag,out,record,600) as session:
                    kernel=boot.m.Kernel(session,symbols);deadline=time.monotonic()+a.seconds;number=0
                    names={'_i9100_media_threads','_i9100_audio_wait_diag','_i9100_media_audio_runtime','_i9100_media_kill_payload','_i9100_springboard_kill_payload',
                           '_i9100_audio_property_lock_diag','_i9100_process_exit','_i9100_backboard_exit','_i9100_signal_exit','_i9100_graphics_seq','_i9100_syscall_restart_diag','_i9100_previous_boot'}
                    names.update({'_i9100_power_'+n for n in ('valid','percent','mv','connected','charging','temp','reason','revision_value')})
                    selected=boot.observations.ObservationSymbols(symbols,names)
                    while True:
                        answer,_=session.command('panic-status');active,remaining=boot.panic.countdown(answer)
                        if active:
                            boot.retain_current_panic(session,out,record);break
                        target=out/f'sample-{number:03}';target.mkdir()
                        result=boot.observations.capture_ui_observations(kernel,selected,target)
                        (target/'results.json').write_text(json.dumps(dict(tag=symbols.tag,sequential=True,observations=result),indent=2))
                        for name in ('SpringBoard','mediaserverd'):
                            _,raw=session.command('threads '+name);(target/(name+'-threads.txt')).write_bytes(raw)
                        record('SAMPLE',number=number,graphics=result.get('i9100_graphics_seq'),exit=result.get('i9100_process_exit'),wait_count=result.get('audio_waits',{}).get('count'))
                        number+=1
                        if time.monotonic()>=deadline:break
                        # Each wait is bounded, preserves the one existing
                        # handle and performs no speculative device command.
                        time.sleep(min(15,max(0,deadline-time.monotonic())))
                record('DONE',samples=number,ui_verified=False)
            except BaseException as error:record('STOP',error=str(error),retry=False);raise
if __name__=='__main__':main()
