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
h=module('charge_roundtrip_handoff','charge-handoff.py')

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

def qualify_art_records(raw,timed,require_transport=False):
    """Match complete native render/start records to measured charger groups.

    The image remains static while blanked, so its sprite level must NOT be
    compared with the newer SOC measured during sleep. Instead prove that
    three timed blank observations retained the same rendered image and that
    the latest startup admission used its own measured voltage and SOC.
    """
    groups=[]
    o.require(len(timed)>=3,'Three measured artwork groups required')
    # A reader can inherit older incomplete groups after the log reserve
    # dropped their trailing diagnostics. Prove only the final continuous
    # interval; never let missing startup logs negate a later full capture.
    for index in range(len(timed)-3,len(timed)):
        sample=timed[index]
        end=timed[index+1]['end_offset'] if index+1<len(timed) else len(raw)
        block=raw[sample['end_offset']:end]
        records={}
        tags=('I9CR1','I9BT1','I9FB1')+(('I9UT1',) if require_transport else ())
        for tag in tags:
            matches=re.findall(rb'^'+tag.encode()+rb' ((?:[0-9a-f]{8} ){7}[0-9a-f]{8})\r?$',block,re.MULTILINE)
            o.require(len(matches)==1,'Exactly one '+tag+' record must belong to each timed charger group')
            records[tag]=[int(word,16) for word in matches[0].split()]
        groups.append(dict(sequence=sample['sequence'],measured_ms=sample['measured_ms'],sample=sample,**records))
    recent=groups
    o.require(len(recent)==3 and recent[-1]['measured_ms']-recent[0]['measured_ms']>=50000,
        'Three complete artwork groups must span 50 seconds')
    for group in recent:
        render,start,fb=group['I9CR1'],group['I9BT1'],group['I9FB1']
        o.require(render[0]==1 and render[1]<18 and render[2]>0 and render[4]<=480*800,
            'Native artwork did not qualify a rendered sprite')
        o.require(fb[6]&0x01000000 and fb[7]==1,'Artwork stability requires actual blank scanout records')
        sample=group['sample']
        wire_reason=sample['reason']&0xffffffff
        o.require(start[0] in (0,1) and start[1]<=11 and start[3]==1 and
            start[4]==sample['millivolts'] and start[5]==sample['soc'] and start[7]==wire_reason,
            'Native startup state differs from its own battery measurement')
        if require_transport:
            transport=group['I9UT1']
            o.require(transport[5]<16384 and transport[6] in (0,1),
                'Charger endpoint snapshot has an impossible ring/busy state')
    first=recent[0]['I9CR1']
    o.require(all(group['I9CR1'][:4]==first[:4] and group['I9CR1'][4]==first[4] for group in recent[1:]),
        'Artwork frame/store counters advanced while the display was blanked')
    o.require(all(group['I9CR1'][7]==first[7] for group in recent[1:]),
        'Timer fault count advanced during the blank observation interval')
    if require_transport:
        drops=[group['I9UT1'][7] for group in recent]
        o.require(all(drops[n]>=drops[n-1] for n in (1,2)),
            'Transport dropped-log count reset within the measured interval')
    last=recent[-1]
    o.require(last['I9BT1'][0]==1 and last['I9BT1'][1]==11 and last['sample']['millivolts']>=3600,
        'Native low-voltage startup admission is not ready')
    return dict(groups=recent,image_stable_while_blanked=True,
        interval_ms=last['measured_ms']-recent[0]['measured_ms'],
        artwork_level_during_sleep=first[1],startup_ready=True,
        transport_snapshots=[group['I9UT1'] for group in recent] if require_transport else None,
        limit='Production render/start counters and matched device measurements; no physical keypress or pixel capture inferred')

def qualify_charger(path,expected,require_panel_sleep=False,require_recovery=False,require_art=False,require_transport=False):
    summary=s.summarize(path)
    raw=(path/'received.bin').read_bytes()
    # A failed payload stays in a healthy supervised charger, but that does
    # not make the same payload eligible for another automatic boot attempt.
    # This rejection also applies to builds which omit the new artwork.
    fault_prefix=re.search(rb'^I9BF1(?: |$)',raw,re.MULTILINE)
    if fault_prefix:
        faults=re.findall(rb'^I9BF1 ((?:[0-9a-f]{8} ){7}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
        o.require(faults,'Partial bootstrap fault record; no boot attempt')
        reason,stage,*_=map(lambda word:int(word,16),faults[-1].split())
        raise ValueError(f'Bootstrap fault parked in charger: reason={reason}, stage={stage}; no boot attempt')
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
    o.require(not require_transport or require_art,'Transport groups require native artwork reports')
    art=qualify_art_records(raw,timed,require_transport) if require_art else None
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
    return dict(summary=summary,ui=values,fimd=registers,artwork=art,panel_sleep=panel_values,panel_identity=panel_identity,panel_recovery=panel_recovery,measured_interval_ms=timed[-1]['measured_ms']-timed[-3]['measured_ms'],
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

def qualify_inherited_deadline(record,adopted):
    o.require(adopted and adopted.get('consistent') is True and
        adopted.get('revision')==record['revision'] and not adopted.get('enabled_after_init'),
        'Returned Power owner did not publish a checked stopped adoption')
    o.require(adopted.get('full')==record['full'] and adopted.get('recharging')==record['recharging'],
        'Loader full/recharge policy was not inherited')
    if record['full'] or not record['connected']:
        o.require(adopted.get('charge_start_ns')==0 and not adopted.get('timeout') and
            not adopted.get('elapsed_base_ns',0) and
            adopted.get('state')==(1 if record['full'] else 2),'Stopped/offline handoff changed its policy')
    else:
        sampled_ns=record['sampled_ticks']*1000//24
        elapsed=(record['elapsed_seconds']+1)*1000000000
        expected_start=max(1,sampled_ns-elapsed)
        expected_base=0 if elapsed<sampled_ns else elapsed-sampled_ns+1
        o.require(adopted.get('charge_start_ns')==expected_start and adopted.get('state') in (1,4) and
            adopted.get('timeout')==int(adopted.get('state')==4) and
            adopted.get('elapsed_base_ns',0)==expected_base,
            'Original charging deadline was replaced, rejected or extended')
    return dict(state=adopted['state'],charge_start_ns=adopted['charge_start_ns'],elapsed_base_ns=adopted.get('elapsed_base_ns',0),
        deadline_seconds=adopted['deadline_seconds'],full=adopted['full'],recharging=adopted['recharging'],
        limit='Conservative whole-second inheritance, not measured net current or full long-duration hardware validation')

def shutdown_epoch_logs(raw):
    rows=re.findall(rb'^I9CE1 ((?:[0-9a-f]{8} ){7}[0-9a-f]{8})\r?$',raw,re.MULTILINE)
    o.require(rows,'Actual loader shutdown-epoch result missing')
    fields=[[int(word,16) for word in row.split()] for row in rows]
    latest=fields[-1]
    o.require(latest[0]==1 and latest[1:3]==[1,1] and all(row[:5]==latest[:5] for row in fields),
        'Normal shutdown charge epoch did not restore once into the loader')
    o.require(latest[4]<=latest[5]<=latest[4]+602,
        'Initial inherited period differs from its bounded RTC interval')
    return latest

def qualify_shutdown_epoch(raw,returned):
    latest=shutdown_epoch_logs(raw)
    o.require(returned and returned.get('valid') is True and returned.get('state')==1,
        'Returned XNU lacks the actual consumed shutdown epoch')
    source=returned['source'];rtc=returned['rtc_seconds']
    o.require(source['checksum']==latest[3] and source['elapsed_ns']//1000000000==latest[4] and
        rtc==(latest[7]<<32)|latest[6] and 0<=rtc-source['rtc_seconds']<=600,
        'Loader logs and retained shutdown source/RTC identity differ')
    expected=(source['elapsed_ns']+(rtc-source['rtc_seconds']+2)*1000000000)//1000000000 if source['elapsed_ns'] else 0
    o.require(latest[5]==expected,'Inherited loader charging allowance was restarted or extended')
    return dict(restored=True,source=source,restored_rtc_seconds=rtc,initial_elapsed_seconds=latest[5],
        limit='Actual retained normal-halt/loader/returned-XNU evidence, not a physical charging-current measurement')

def qualify_stop_confirmation(charge):
    o.require(charge.get('version')==3 and charge.get('samples'),
        'New stop-confirmation package requires its actual v3 Power records')
    latest=charge['samples'][-1]
    o.require(latest.get('stop_confirmation_available') is True and latest.get('stop_uncertain')==0 and
        latest.get('measurements_valid') is True and
        charge.get('stop_confirmation',{}).get('uncertain') is False,
        'Power stop or current measurement is still uncertain; round trip is not validated')
    return dict(confirmed=True,sequence=latest.get('sequence'),reason=latest.get('reason'),
        limit='Last Power policy disable/readback and sample status; no net current inferred')

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
    require_art=manifest.get('standalone_charge_art') is not None
    child([sys.executable,'-B',HERE/'capture-charge-loader.py','--output',out/'charger-evidence',
        '--seconds','180' if require_art else '120','--wait','180'],out/'charger-process',480 if require_art else 420,record)
    evidence=qualify_charger(out/'charger-evidence',tag+' '+charger_tag,manifest.get('panel_sleep') is True,
        manifest.get('standalone_panel_recovery') is True,require_art,manifest.get('standalone_charge_transport') is True)
    o.save(out/'charger-qualified.json',evidence);record('CHARGER_QUALIFIED',measured_interval_ms=evidence['measured_interval_ms'])
    if manifest.get('standalone_charge_shutdown_epoch') is True:
        epoch=shutdown_epoch_logs((out/'charger-evidence/received.bin').read_bytes())
        o.save(out/'shutdown-epoch-loader.json',dict(fields=epoch,limit='One actual restore result before any remote boot'))
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
    require_handoff=manifest.get('standalone_charge_handoff') is True
    require_deadline=manifest.get('standalone_charge_deadline_adoption') is True
    require_epoch=manifest.get('standalone_charge_shutdown_epoch') is True
    require_stop=manifest.get('charge_stop_confirmation') is True
    o.require(not require_deadline or require_handoff,'Deadline adoption requires the original loader record')
    if require_handoff:
        task=out/'returned-xnu-evidence/task-0000'
        o.require((task/'result.json').is_file() and (task/'charge-handoff.bin').is_file(),
            'Returned XNU lacks its actual charger handoff observation')
        charge=json.loads((task/'result.json').read_text(encoding='utf-8')).get('charge',{})
        observed=charge.get('charger_handoff',{})
        raw=(task/'charge-handoff.bin').read_bytes();decoded=h.decode(raw)
        import hashlib
        o.require(decoded.get('valid') is True and observed.get('valid') is True and
            observed.get('root_stable') is True and observed.get('kernel_tag')==tag and
            observed.get('raw_sha256')==hashlib.sha256(raw).hexdigest(),
            'Returned XNU did not prove a complete same-BUILD charger stop record')
        deadline=qualify_inherited_deadline(decoded,charge.get('charger_deadline_adoption')) if require_deadline else None
        shutdown_epoch=qualify_shutdown_epoch((out/'charger-evidence/received.bin').read_bytes(),
            observed.get('shutdown_charge_epoch')) if require_epoch else None
        stop_confirmed=qualify_stop_confirmation(charge) if require_stop else None
        o.save(out/'boot-handoff-verified.json',dict(record=decoded,
            kernel_tag=tag,takeover_observation=charge.get('charger_takeover_observation'),deadline_adoption=deadline,shutdown_epoch=shutdown_epoch,stop_confirmation=stop_confirmed,
            limit='Checked loader stop retained in XNU; first-sample timing is optional and never proves net charging'))
    record('DONE',meaning='Normal shutdown, timed new charger UI/blank records, one remote boot and same XNU BUILD verified',
        native_artwork_verified=require_art,
        charger_handoff_verified=require_handoff,
        charger_deadline_verified=require_deadline,
        shutdown_charge_epoch_verified=require_epoch,
        stop_confirmation_verified=require_stop,
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
    art=manifest.get('standalone_charge_art')
    if art is not None:
        o.require(isinstance(art,dict) and isinstance(art.get('path'),str),'Actual artwork provenance missing')
        file=o.confined(o.ROOT/art['path'],o.ROOT/'assets')
        o.require(file.stat().st_size==art.get('bytes') and o.sha(file)==art.get('sha256'),
            'Local artwork differs before device access')
        o.require(identity['sources'].get('../'+art['path'])==art['sha256'] and
            file.read_bytes() in (package/'zImage').read_bytes(),
            'Exact original artwork is not present in the source identity and loader binary')
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
