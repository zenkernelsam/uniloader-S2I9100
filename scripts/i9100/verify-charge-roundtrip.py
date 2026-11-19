#!/usr/bin/env python3
"""Validate the new standalone charger once, after an approved deployment.

No flash or input injection. Uses existing bounded single-owner tools for a
normal charging shutdown, timed charger logs and one exact remote boot. A
STOP or uncertain child preserves evidence and forbids subsequent openers.
"""
import argparse,importlib.util,json,re,sys,time
from datetime import datetime,timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

r=module('charge_roundtrip_resume','resume-on-device.py')
o=r.o
s=module('charge_roundtrip_summary','summarize-charge-loader.py')

def rows(path):
    return r.read_events(path)

def owner_complete(path,tag):
    metadata=json.loads((path/'owner.json').read_text(encoding='utf-8'))
    o.require(metadata.get('tag')==tag and type(metadata.get('process_created_100ns')) is int,
        'Owner identity differs from expected BUILD')
    events=rows(path/'events.jsonl');ready=[row for row in events if row['phase']=='READY']
    o.require(len(ready)==1 and ready[0].get('tag')==tag and ready[0].get('pid')==metadata.get('pid'),
        'Single original owner handshake missing')
    o.require(events[-1]['phase']=='CLOSED' and sum(row['phase']=='DONE' for row in events)==1 and
        not any(row['phase']=='STOP' for row in events),'Owner did not complete normally; no next opener')
    return events

def qualify_charger(path,expected,require_panel_sleep=False,require_recovery=False):
    summary=s.summarize(path)
    raw=(path/'received.bin').read_bytes()
    o.require(re.search(rb'^I9CHC2 READY '+expected.encode()+rb'\r?$',raw,re.MULTILINE) is not None,
        'Matching deployed charger kernel/source identity missing from logs')
    timed=[sample for sample in summary['samples'] if sample['version']==2]
    o.require(len(timed)>=3 and all(sample['valid'] for sample in timed[-3:]),'Three real timed charger samples required')
    o.require(all(sample.get('interval_available') for sample in timed[-2:]) and
        timed[-1]['measured_ms']-timed[-3]['measured_ms']>=50000,
        'Continuous device measurement interval did not span 50 seconds')
    ui=re.findall(rb'^I9UI1 ((?:[0-9a-f]{8} ){3}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
    fb=re.findall(rb'^I9FB1 ((?:[0-9a-f]{8} ){7}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
    o.require(ui and fb,'Actual charger UI/register records missing')
    values=[int(word,16) for word in ui[-1].split()]
    registers=[int(word,16) for word in fb[-1].split()]
    o.require(values==[1,0x5ec00000,1920,32], 'New charger did not draw into its expected original window')
    o.require(registers[0]&1==0 and registers[1]&1==1 and (registers[1]>>2)&15==13 and registers[2]==0x5ec00000 and
        registers[3]==1920 and registers[4]==((479<<11)|799) and registers[5]==0x5ed77000 and
        registers[6]&0x01000000 and registers[7]==1,'Window2 geometry or real blank register did not qualify')
    o.require(timed[-1]['soc']>=5 and timed[-1]['millivolts']>=3500 and
        50<=timed[-1]['temperature_deci_c']<=400 and timed[-1]['reason'] in (0,-4) and
        not timed[-1]['timeout'],'Latest battery state does not qualify a boot contrast')
    panel_values=None
    panel_identity=None;panel_recovery=None
    if require_panel_sleep:
        panels=re.findall(rb'^I9PL1 ((?:[0-9a-f]{8} ){7}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
        o.require(panels,'Actual standalone panel sleep record missing')
        panel_values=[int(word,16) for word in panels[-1].split()]
        o.require(panel_values[0]==1 and panel_values[1]==3 and panel_values[2]==0 and
            panel_values[3]!=0xff and panel_values[3]&0x14==0 and panel_values[4]>=2 and
            panel_values[5]&3==3 and panel_values[6]==panel_values[7]==panel_values[5]&~3,
            'Standalone panel did not qualify sleep and actual stopped scanout')
        identities=re.findall(rb'^I9PD1 ((?:[0-9a-f]{8} ){3}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
        o.require(identities,'Actual panel identity/qualification mask missing')
        panel_identity=[int(word,16) for word in identities[-1].split()]
        o.require(panel_identity[0]==0x3f and panel_identity[1] in (0xa1,0xa2) and panel_identity[2]==0x12 and
            panel_identity[3]!=0xff and panel_identity[3]<=255,'Panel identity failed complete stable read qualification')
        if require_recovery:
            recoveries=re.findall(rb'^I9PR1 ((?:[0-9a-f]{8} ){3}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
            o.require(recoveries,'Panel recovery record required by this actual package is missing')
            panel_recovery=[int(word,16) for word in recoveries[-1].split()]
            o.require(panel_recovery[0]<=1 and panel_recovery[1]<=2 and
                (panel_recovery[0] or not panel_recovery[1]) and not panel_recovery[2] and
                panel_recovery[3]==panel_values[1],'Panel recovery budget/result disagrees with its sleep state')
    elif require_recovery:raise ValueError('Recovery qualification requires panel-sleep observations')
    return dict(summary=summary,ui=values,fimd=registers,panel_sleep=panel_values,panel_identity=panel_identity,panel_recovery=panel_recovery,measured_interval_ms=timed[-1]['measured_ms']-timed[-3]['measured_ms'],
        limit='Draw/register/timed-log qualification; no physical image or keypress acceptance inferred')

def wait_resumed(directory,seconds,record,clock=time.monotonic,sleep=time.sleep):
    deadline=clock()+seconds
    while True:
        events=rows(directory/'events.jsonl')
        phase=events[-1]['phase']
        if phase=='DONE':return True
        if phase=='WAIT_EXPIRED':
            record('WAIT_EXPIRED',device_actions=0,reason='Deployment relay did not find a ready device');return False
        o.require(phase!='STOP','Deployment relay stopped; no charger actions')
        if clock()>=deadline:
            record('WAIT_EXPIRED',device_actions=0,reason='Bounded wait for deployment completion expired');return False
        sleep(min(20,deadline-clock()))

def verify_deployment(directory,package,manifest,completed_capture=None):
    armed=json.loads((directory/'armed.json').read_text(encoding='utf-8'))
    o.require(Path(armed['package']).resolve()==package and armed['kernel_sha']==manifest['artifacts']['zImage']['sha256'],
        'Deployment relay package differs')
    plan=o.Plan(armed['plan'],armed['plan_sha']);timeline=rows(plan.parent/'timeline.jsonl')
    o.require(plan.data['control_tag']==manifest['control_tag'] and (plan.parent/'started.json').is_file() and
        timeline[-1]['phase']=='DONE','Reviewed one-time deployment did not finish successfully')
    for name in ('deployment',) if completed_capture is not None else ('deployment','capture-process'):
        finished=json.loads((directory/name/'finished.json').read_text(encoding='utf-8'))
        o.require(finished.get('exit_code')==0,'Deployment/capture process is not finished normally')
    if completed_capture is not None:
        # An outer host journal error can occur AFTER its one-time KERNEL
        # child proved DONE. Continue only with a separately completed,
        # matching single-owner capture; retain the old STOP unchanged.
        o.require(not (directory/'capture-process').exists() and not (directory/'boot-evidence').exists(),
            'Original post-deployment capture already started; no alternate opener')
        o.require(completed_capture.resolve()!=directory.resolve(), 'Separate completed capture evidence required')
        owner_complete(completed_capture,manifest['control_tag'])
    else:owner_complete(directory/'boot-evidence',manifest['control_tag'])

def run_roundtrip(package,manifest,out,record,child=r.run_child,host=None):
    tag=manifest['control_tag'];charger_tag=manifest['standalone_charge_control_tag']
    host=host or o.Host();profile=json.loads((o.OUT/'inventory-20261106-211114-download-profile.json').read_text(encoding='utf-8'))
    mode,_=r.device_mode(host.inventory(),profile)
    o.require(mode=='cycle','Expected running reviewed XNU, no shutdown attempted')
    record('SHUTDOWN_BEGIN',writes_to_flash=0)
    child([sys.executable,'-B',HERE/'ui-session.py','serve','--kernel',package/'mach_kernel',
        '--output',out/'shutdown-evidence','--seconds','240','--allow-poweroff-charge','--poweroff-on-ready'],
        out/'shutdown-process',420,record)
    events=owner_complete(out/'shutdown-evidence',tag)
    result=json.loads((out/'shutdown-evidence/task-0001/result.json').read_text(encoding='utf-8'))
    o.require(result.get('reply')=='OK poweroff-charge' and result.get('shutdown_disconnect_observed') is True and
        any(row.get('phase')=='TASK_DONE' and row.get('action')=='poweroff-charge' for row in events),
        'Normal shutdown ACK/disconnect missing; no subsequent opener')
    record('SHUTDOWN_COMPLETE')
    child([sys.executable,'-B',HERE/'capture-charge-loader.py','--output',out/'charger-evidence',
        '--seconds','120','--wait','180'],out/'charger-process',420,record)
    evidence=qualify_charger(out/'charger-evidence',tag+' '+charger_tag,manifest.get('panel_sleep') is True,
        manifest.get('standalone_panel_recovery') is True)
    o.save(out/'charger-qualified.json',evidence);record('CHARGER_QUALIFIED',measured_interval_ms=evidence['measured_interval_ms'])
    child([sys.executable,'-B',HERE/'charge-command.py','--package',package,'--action','boot',
        '--output',out/'boot-command-evidence'],out/'boot-command-process',120,record)
    command=rows(out/'boot-command-evidence/events.jsonl')
    o.require(command[-1]['phase']=='CLOSED' and sum(row['phase']=='SEND' for row in command)==1 and
        sum(row['phase']=='ACK' for row in command)==1 and sum(row['phase']=='DONE' for row in command)==1 and
        not any(row['phase']=='STOP' for row in command),'Exact boot acknowledgement not proved')
    device=o.wait_for(host,lambda devices:o.cdc(devices),180,'Original XNU CDC after charger boot')
    o.require(device['service'].lower()=='usbser' and o.normalize_location(device['location'])==profile['location'],
        'Boot destination identity/topology differs')
    host.settle(90)
    child([sys.executable,'-B',HERE/'ui-session.py','serve','--kernel',package/'mach_kernel',
        '--output',out/'returned-xnu-evidence','--seconds','120','--charge-on-ready','--on-ready','diagnostics'],
        out/'returned-xnu-process',300,record)
    owner_complete(out/'returned-xnu-evidence',tag)
    record('DONE',meaning='Normal shutdown, timed new charger UI/blank records, one remote boot and same XNU BUILD verified',
        writes_to_flash=0,physical_power_key_verified=False,energy_balance_verified=False)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--resume-evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--completed-capture',type=Path,help='Explicit separate normal capture after a successful KERNEL child and a host-only relay failure')
    p.add_argument('--wait-seconds',type=int,default=3600);a=p.parse_args()
    o.require(60<=a.wait_seconds<=3600,'Bounded wait required')
    package=o.confined(a.package,o.REPO/'out');manifest=json.loads((package/'manifest.json').read_text(encoding='utf-8'))
    o.require(manifest.get('standalone_charge_control_version')==2 and manifest.get('standalone_charge') is True,
        'Only the reviewed new charger capability is eligible')
    for name in ('zImage','mach_kernel'):
        artifact=manifest['artifacts'][name];path=package/name
        o.require(path.stat().st_size==artifact['bytes'] and o.sha(path)==artifact['sha256'],'Reviewed package changed')
    o.require(manifest['control_tag']==manifest['artifacts']['mach_kernel']['sha256'][:16],
        'Manifest control identity differs from actual kernel')
    identity=json.loads((package/'charger-identity.json').read_text(encoding='utf-8'))
    identity_input={key:identity[key] for key in ('schema','kernel_sha256','sources','flags')}
    import hashlib
    o.require(identity_input['schema']==2 and identity_input['kernel_sha256']==manifest['artifacts']['mach_kernel']['sha256'] and
        identity['tag']==manifest['standalone_charge_control_tag']==hashlib.sha256(
            json.dumps(identity_input,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16],
        'Charger source/profile identity differs before any device access')
    directory=o.confined(a.resume_evidence,o.REPO/'out');out=o.confined(a.output,o.REPO/'out')
    o.require(not out.exists(),'Fresh roundtrip evidence required');out.mkdir(parents=True)
    with (out/'events.jsonl').open('x',encoding='utf-8') as stream:
        def record(phase,**values):
            row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**values)
            stream.write(json.dumps(row)+'\n');stream.flush();print(json.dumps(row),flush=True)
        record('WAIT_DEPLOYMENT',relay=str(directory),writes_to_flash=0)
        try:
            completed=o.confined(a.completed_capture,o.REPO/'out') if a.completed_capture else None
            if completed is None and not wait_resumed(directory,a.wait_seconds,record):return
            verify_deployment(directory,package,manifest,completed)
            if completed is not None:record('COMPLETED_DEPLOYMENT_CONTINUED',capture=str(completed),writes_to_flash=0,
                meaning='Successful KERNEL plan and separate normal capture verified; old relay STOP retained')
            # Reserve a distinct no-flash validation once, without modifying
            # or reusing the KERNEL plan. A second verifier fails before USB.
            with (directory/'charger-roundtrip-started.json').open('x',encoding='utf-8') as reservation:
                json.dump(dict(package=str(package),output=str(out)),reservation)
            run_roundtrip(package,manifest,out,record)
        except BaseException as error:
            record('STOP',error=str(error),retry=False);raise

if __name__=='__main__':main()
