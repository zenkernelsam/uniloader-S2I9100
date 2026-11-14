#!/usr/bin/env python3
"""Collect boot evidence on one BUILD-verified serial handle, without actions.

No flash/reboot/touch, no serial retry. Optional full framebuffer shares the
same handle. Time/command budgets stop subsequent requests; a Windows opener
stuck inside the driver still requires external recovery, never forced exit.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file)
    value=importlib.util.module_from_spec(s);s.loader.exec_module(value);return value

f=module('boot_forensic','forensic-session.py')
m=module('boot_memory','live-memory.py')
o=module('boot_odin','odin-loop.py')
observations=module('boot_observations','inspect-mdns.py')
stack=module('boot_stack','inspect-stacks.py')
frame=module('boot_frame','capture-framebuffer.py')
panic=module('boot_panic','panic-recovery.py')


def retain_current_panic(session,out,record):
    """Save a positively identified panic on this existing handle once.

    An explicit panic-readonly response is a completed refusal, not a timeout
    or an uncertain driver call. Use new sequence numbers for the two allowed
    panic queries; never resend the refused memory request or open a new port.
    """
    answer,_=session.command('panic-status');active,remaining=panic.countdown(answer)
    if not active:raise ValueError('panic-readonly did not confirm an active panic')
    _,raw=session.command('panic-log');(out/'panic-log.bin').write_bytes(raw)
    header,text=panic.decode_snapshot(raw)
    (out/'panic-log.txt').write_text(text.decode('utf-8','replace'),encoding='utf-8')
    result=dict(active=active,remaining_seconds=remaining,snapshot=header,bytes=len(raw))
    (out/'panic-transition.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    record('PANIC_TRANSITION_SAVED',**result)
    return result


class SnapshotSession(f.Session):
    def __init__(self,*args,budget_seconds=300,command_limit=1024,**kwargs):
        super().__init__(*args,**kwargs)
        self.deadline=self.clock()+budget_seconds
        self.command_limit=command_limit;self.command_count=0
        original_sleep=self.sleep
        def bounded_sleep(seconds):
            if self.clock()+seconds>=self.deadline:
                raise TimeoutError('Snapshot time budget exhausted before write; no retry')
            original_sleep(seconds)
            if self.clock()>=self.deadline:
                raise TimeoutError('Snapshot time budget exhausted before write; no retry')
        self.sleep=bounded_sleep

    def _wait(self,predicate,label):
        remaining=self.deadline-self.clock()
        if remaining<=0:raise TimeoutError('Snapshot time budget exhausted; no retry')
        timeout=self.timeout;self.timeout=min(timeout,remaining)
        try:return super()._wait(predicate,label)
        finally:self.timeout=timeout

    def watch_panic(self,out,record):
        self.panic_output=out;self.panic_record=record;self.panic_transition=None
        self.panic_save_attempted=False

    def command(self,verb):
        # Read-only requests remain on the same nonce/BUILD session.
        if verb not in ('ping','root-status','panic-status','panic-log') and not re.fullmatch(r'(threads|ports) [A-Za-z0-9_.-]{1,32}|read-memory [0-9a-fA-F]{8} [0-9a-fA-F]{1,8}',verb):
            raise ValueError('Snapshot command is outside its read-only scope')
        f.validate_command(verb)
        if self.clock()>=self.deadline or self.command_count>=self.command_limit:
            raise TimeoutError('Snapshot time/command budget exhausted; no retry')
        self.command_count+=1
        try:return super().command(verb)
        except f.ProtocolError as error:
            if str(error)=='ERR panic-readonly' and hasattr(self,'panic_output') and not self.panic_save_attempted:
                self.panic_save_attempted=True
                # No incomplete DATA can be interpreted as the following
                # scalar reply. The exact refusal had no binary payload.
                self.receiver.line.clear();self.receiver.drop=False
                try:self.panic_transition=retain_current_panic(self,self.panic_output,self.panic_record)
                except BaseException as saving_error:
                    self.panic_record('PANIC_TRANSITION_STOP',error=str(saving_error),retry=False)
            raise


@contextmanager
def open_session(device,tag,out,record,budget_seconds=300):
    transport=None;session=None
    with (out/'received.bin').open('xb') as received:
        try:
            transport=f.WinTransport(device['port'],record)
            session=SnapshotSession(transport,tag,record,received,timeout=20,budget_seconds=budget_seconds)
            session.watch_panic(out,record)
            session.handshake()
            yield session
        except BaseException:
            if session is not None and session.receiver.payload and not session.receiver.complete:
                (out/'incomplete-data.partial').write_bytes(session.receiver.payload)
            raise
        finally:
            if transport is not None:transport.close()
            received.flush();record('CLOSED')


def collect_snapshot(session,symbols,out,device,record,with_frame=False):
    if not (session.receiver.ready and session.receiver.tag_seen and session.receiver.expected_tag==symbols.tag):
        raise ValueError('Snapshot requires the matching READY/BUILD handshake')
    result=dict(tag=symbols.tag,device=device,tables={},ui_observations={},
                snapshot='sequential observations on one handle; not an atomic system snapshot',
                springboard_interaction_verified=False)
    def save():
        (out/'results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    def retain_panic():
        _,raw=session.command('panic-log');(out/'panic-log.bin').write_bytes(raw)
        header,text=panic.decode_snapshot(raw)
        (out/'panic-log.txt').write_text(text.decode('utf-8','replace'),encoding='utf-8')
        result.update(mode='panic-retained',panic_snapshot=header,commands=session.command_count);save()
    answer,_=session.command('panic-status');active,remaining=panic.countdown(answer)
    result['panic_initial']=dict(active=active,remaining_seconds=remaining)
    result['panic']=dict(result['panic_initial']);save()
    if active:
        retain_panic()
        return result
    answer,_=session.command('root-status');result['root_reply']=answer;save()
    kernel=m.Kernel(session,symbols)
    names=observations.LS_SYMBOLS|observations.ABORT_SYMBOLS|{
        key for key in symbols.values if key.endswith('leo_graphics_state')}
    selected=observations.ObservationSymbols(symbols,names)
    result['ui_observations']=observations.capture_ui_observations(kernel,selected,out)
    save();record('OBSERVATIONS_SAVED')
    processes=[]
    for name in ('SpringBoard','locationd','lsd','backboardd'):
        process=stack.capture_process(session,kernel,name,out,m,True,1)
        # Save the original snapshot before rechecking PID. A respawn must
        # not discard the registers that established this stale identity.
        processes.append(process);result['processes']=processes
        (out/'stacks.json').write_text(json.dumps(dict(tag=symbols.tag,processes=processes),indent=2)+'\n',encoding='utf-8')
        save()
        _,after=session.command('threads '+name)
        (out/(name+'-threads-after.txt')).write_bytes(after)
        current=re.search(rb'proc\s+(\d+)\s+',after)
        before_pid=process.get('pid');after_pid=int(current[1]) if current else None
        if before_pid!=after_pid:raise RuntimeError(name+' PID changed during its capture; no retry')
        record('PROCESS_SAVED',process=name,pid=before_pid)
    if with_frame:
        target=out/'frame';target.mkdir()
        result['frame']=frame.capture_frame(kernel,symbols,target,device,8192,record)
        save()
    # The initial query only describes the start of collection. Check again
    # after the last requested data, on this same handle, before normal DONE.
    answer,_=session.command('panic-status');active,remaining=panic.countdown(answer)
    result['panic']=dict(active=active,remaining_seconds=remaining);save()
    if active:
        result['panic_started_during_snapshot']=True;save()
        retain_panic()
        return result
    result['mode']='normal-evidence';result['commands']=session.command_count;save()
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--frame',action='store_true',help='Also collect a real full framebuffer on this same handle')
    p.add_argument('--budget-seconds',type=int,choices=(120,180,300,600),default=300)
    a=p.parse_args();kernel=o.confined(a.kernel,f.REPO/'out');out=o.confined(a.output,f.REPO/'out')
    o.require(not out.exists(),'Fresh snapshot directory required')
    symbols=m.Symbols(kernel)
    profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory())
        o.require(device and device['service'].lower()=='usbser' and o.normalize_location(device['location'])==profile['location'],
                  'Approved live kernel CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','OBSERVATIONS_SAVED','PROCESS_SAVED','FRAME_PROGRESS','DONE','STOP','CLOSED'):
                    print(json.dumps(row),flush=True)
            try:
                with open_session(device,symbols.tag,out,record,a.budget_seconds) as session:
                    result=collect_snapshot(session,symbols,out,device,record,a.frame)
                # CLOSED precedes DONE. Never equate saved results with a
                # finished collection while its handle may still be alive.
                record('DONE',mode=result['mode'],springboard_interaction_verified=False)
            except BaseException as exc:
                record('STOP',error=str(exc),retry=False);raise


if __name__=='__main__':main()
