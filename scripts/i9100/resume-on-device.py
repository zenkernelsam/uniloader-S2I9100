#!/usr/bin/env python3
"""Wait read-only for the approved S2, then execute one preapproved KERNEL plan.

The old charger is observed through PnP only. No attempt to reboot it, open its
port, reset a hub, resend commands, retry a consumed plan or kill a child.
Human unattended authorization is required before using this action entry.
"""
import argparse,importlib.util,json,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('resume_odin',here/'odin-loop.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)

def device_mode(devices,profile):
    cdc=o.cdc(devices);downloads=o.samsung(devices)
    chargers=[d for d in devices if d['instance'].upper().endswith('\\S2I9100-CHG')]
    o.require(len(chargers)<=1,'Ambiguous charger identity; no action selected')
    if cdc:
        o.require(not downloads and not chargers,'USB identities overlap; no mode selected')
        o.require(cdc['service'].lower()=='usbser' and o.normalize_location(cdc['location'])==profile['location'],
            'Normal S2 port driver/topology differs')
        return 'cycle',cdc['instance']
    if downloads:
        o.require(not chargers,'Download and charger identities overlap; no mode selected')
        actual=o.download(devices,profile);return 'bootstrap',actual['instance']
    if chargers:
        device=chargers[0]
        o.require(device['status']=='OK' and device['service'].lower()=='usbser' and
            o.normalize_location(device['location'])==profile['location'],'Charger identity/topology differs')
        return None,'old-charger'
    return None,'absent'

def wait_device(host,plan,seconds,record,clock=time.monotonic,sleep=time.sleep):
    deadline=clock()+seconds;last=None;state=None
    while clock()<deadline:
        o.require(not (plan.parent/'started.json').exists(),'Plan was consumed while waiting; no execution')
        devices=host.inventory()
        if clock()>=deadline:
            record('WAIT_EXPIRED',seconds=seconds,device_actions=0)
            return None
        mode,identity=device_mode(devices,plan.data['profile'])
        current=(mode,identity)
        if current!=state:record('DEVICE_STATE',mode=mode,identity=identity);state=current
        if mode and current==last:return mode
        last=current if mode else None
        sleep(min(20,max(0,deadline-clock())))
    record('WAIT_EXPIRED',seconds=seconds,device_actions=0)
    return None

def run_child(argv,directory,seconds,record):
    directory.mkdir()
    with (directory/'stdout.txt').open('xb') as stdout,(directory/'stderr.txt').open('xb') as stderr:
        child=subprocess.Popen(list(map(str,argv)),cwd=o.ROOT,stdout=stdout,stderr=stderr)
        o.save(directory/'process.json',dict(pid=child.pid,argv=list(map(str,argv)),started=datetime.now(timezone.utc).isoformat()))
        record('CHILD_STARTED',pid=child.pid,evidence=str(directory))
        deadline=time.monotonic()+seconds
        while True:
            result=child.poll()
            if result is not None:
                o.save(directory/'finished.json',dict(pid=child.pid,exit_code=result,finished=datetime.now(timezone.utc).isoformat()))
                record('CHILD_FINISHED',pid=child.pid,exit_code=result)
                o.require(result==0,'Child stopped; its evidence retained, no retry')
                return
            if time.monotonic()>=deadline:
                raise o.UncertainProcess(f'Child {child.pid} is still live after its budget; preserve it, no kill/retry/new opener')
            try:child.wait(timeout=min(20,max(1,deadline-time.monotonic())))
            except subprocess.TimeoutExpired:continue

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',type=Path,required=True);p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--approve-plan',required=True);p.add_argument('--confirm-kernel',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--wait-seconds',type=int,default=1800);p.add_argument('--capture-seconds',type=int,default=180)
    a=p.parse_args();o.require(60<=a.wait_seconds<=3600 and 60<=a.capture_seconds<=600,'Bounded wait/capture required')
    package=o.confined(a.package,o.REPO/'out');manifest=json.loads((package/'manifest.json').read_text())
    plan=o.Plan(a.plan,a.approve_plan)
    o.require(plan.data['profile'] is not None and plan.data['validation']=='control','One approved normal KERNEL plan required')
    o.require(a.confirm_kernel==plan.data['files']['zImage']==manifest['artifacts']['zImage']['sha256'],
        'Reviewed KERNEL SHA differs from plan/package')
    o.require(plan.data['control_tag']==manifest['control_tag'],'Plan BUILD differs from package')
    for name in ('zImage','mach_kernel'):
        artifact=manifest['artifacts'][name];path=package/name
        o.require(path.is_file() and path.stat().st_size==artifact['bytes'] and o.sha(path)==artifact['sha256'],
            'Reviewed package artifact changed')
    o.require(not (plan.parent/'started.json').exists(),'Consumed plan cannot be armed again')
    output=o.confined(a.output,o.REPO/'out');o.require(not output.exists(),'Fresh readiness evidence required')
    output.mkdir(parents=True)
    with (output/'events.jsonl').open('x',encoding='utf-8') as events:
        def record(phase,**fields):
            row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
            events.write(json.dumps(row)+'\n');events.flush();print(json.dumps(row),flush=True)
        o.save(output/'armed.json',dict(package=str(package),plan=str(plan.path),plan_sha=a.approve_plan,
            kernel_sha=a.confirm_kernel,wait_seconds=a.wait_seconds,capture_seconds=a.capture_seconds))
        record('ARMED',wait_seconds=a.wait_seconds,old_charger_commands=0,phone_port_openers=0)
        try:
            mode=wait_device(o.Host(),plan,a.wait_seconds,record)
            if mode is None:return
            plan.verify();record('READY_TO_EXECUTE',mode=mode)
            run_child([sys.executable,'-B',here/'odin-loop.py','execute','--plan',plan.path,
                '--approve-plan',a.approve_plan,'--mode',mode,'--confirm-kernel',a.confirm_kernel],
                output/'deployment',900,record)
            timeline=[json.loads(line) for line in (plan.parent/'timeline.jsonl').read_text().splitlines()]
            o.require(timeline and timeline[-1]['phase']=='DONE','Plan did not prove deployment success; no post-opener')
            run_child([sys.executable,'-B',here/'ui-session.py','serve','--kernel',package/'mach_kernel',
                '--output',output/'boot-evidence','--seconds',str(a.capture_seconds),'--charge-on-ready',
                '--on-ready','diagnostics','--on-ready','frame','--on-ready','charge',
                '--allow-reboot-download','--allow-poweroff-charge'],
                output/'capture-process',a.capture_seconds+180,record)
            record('DONE',meaning='One KERNEL plan and one bounded post-boot owner completed; final UI/charger tests remain')
        except BaseException as error:record('STOP',error=str(error),retry=False);raise

if __name__=='__main__':main()
