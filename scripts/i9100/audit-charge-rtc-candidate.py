#!/usr/bin/env python3
"""Verify the isolated charger candidate, its frozen inputs and actual ARM code."""
import argparse,hashlib,importlib.util,json,os,re,shlex,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];REPO=ROOT/'uniloader-S2I9100'

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def mod(name,file):
    s=importlib.util.spec_from_file_location(name,file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def confined(value):
    p=Path(value).resolve()
    if not p.is_relative_to(ROOT):raise ValueError('Evidence outside project')
    return p
def main():
    if os.name!='posix':raise RuntimeError('Run in WSL')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
            sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--kernel-source',type=Path,required=True);p.add_argument('--plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--expect-kernel-sha256',required=True,help='Exact reviewed isolated kernel, never inferred from the newest file')
    p.add_argument('--power-model',type=Path,required=True,help='Completed RTC/policy model built from these same sources')
    p.add_argument('--timer-model',type=Path,required=True,help='Completed wait policy model built from this loader')
    p.add_argument('--usb-model',type=Path,required=True)
    p.add_argument('--session-model',type=Path,required=True)
    p.add_argument('--gate-model',type=Path,required=True)
    a=p.parse_args();package,kernel_source,plan,out=map(confined,(a.package,a.kernel_source,a.plan,a.output))
    if not package.is_relative_to(REPO/'out') or not kernel_source.is_relative_to(ROOT/'xnu-S2I9100/out') or not out.is_relative_to(REPO/'out') or out.exists():raise ValueError('Use exact candidate and fresh output')
    manifest=json.loads((package/'manifest.json').read_text());snapshot=json.loads((kernel_source/'snapshot.json').read_text());identity=json.loads((package/'charger-identity.json').read_text());planned=json.loads(plan.read_text())
    checks={}
    expected=a.expect_kernel_sha256
    if not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('Exact kernel SHA256 required')
    if snapshot.get('result')!='PASS' or snapshot['kernel_sha256']!=expected or snapshot['objects']!=['iokit/i9100_power_bus.o']:raise ValueError('Not the isolated RTC kernel')
    for name,item in manifest['artifacts'].items():
        file=package/name
        if file.stat().st_size!=item['bytes'] or sha(file)!=item['sha256']:raise ValueError('Artifact changed: '+name)
    if sha(package/'mach_kernel')!=expected or sha(kernel_source/'mach_kernel')!=expected:raise ValueError('Kernel bytes differ')
    for name,value in snapshot['reused_link_inputs'].items():
        if sha(confined(name))!=value:raise ValueError('Reused core input changed')
    for name,value in snapshot['source_inputs'].items():
        if sha(confined(name))!=value:raise ValueError('RTC compile source changed')
    for name,value in identity['sources'].items():
        if sha(confined(REPO/name))!=value:raise ValueError('Loader source/input changed: '+name)
    for name in ('i9100_power.h','i9100_power_bus.c','i9100_rtc_time.h'):
        if (REPO/'board/samsung/charge'/name).read_bytes()!=(ROOT/'xnu-S2I9100/iokit/Drivers/KernelBuiltIn/ARM/AppleARMPlatform'/name).read_bytes():raise ValueError('Paired RTC source differs')
    power_model=confined(a.power_model);power_record=json.loads(power_model.read_text())
    if not power_model.is_relative_to(ROOT/'xnu-S2I9100/out') or power_record.get('result')!='PASS' or power_record.get('hardware') is not False:raise ValueError('Completed offline Power model required')
    for name,value in power_record['source_sha256'].items():
        if sha(confined(ROOT/'xnu-S2I9100'/name))!=value:raise ValueError('Power model used a different source: '+name)
    timer_model=confined(a.timer_model);timer_record=json.loads(timer_model.read_text())
    if not timer_model.is_relative_to(REPO/'out') or timer_record.get('result')!='PASS' or timer_record.get('hardware') is not False:raise ValueError('Completed wait model required')
    for name,value in timer_record['source_sha256'].items():
        if sha(confined(REPO/name))!=value:raise ValueError('Wait model used a different source: '+name)
    extra_models=[]
    for model_arg in (a.usb_model,a.session_model,a.gate_model):
        model=confined(model_arg);model_record=json.loads(model.read_text())
        if not model.is_relative_to(REPO/'out') or model_record.get('result')!='PASS' or model_record.get('hardware') is not False:raise ValueError('Completed loader model required')
        for name,value in model_record['source_sha256'].items():
            if sha(confined(REPO/name))!=value:raise ValueError('Loader model source differs: '+name)
        extra_models.append(str(model.relative_to(ROOT)))
    if planned['partition']!='KERNEL' or planned['files']['zImage']!=manifest['artifacts']['zImage']['sha256'] or (plan.parent/'started.json').exists():raise ValueError('Plan consumed or wrong')
    if manifest['internal_emmc_root'] or manifest['panel_sleep'] or manifest['charge_probe']:raise ValueError('Candidate scope differs')
    elf=package/'loader/uniLoader.o';z=(package/'zImage').read_bytes()
    symbols={}
    for line in (package/'loader-symbols.txt').read_text().splitlines():
        row=line.split()
        if len(row)==3 and re.fullmatch('[0-9a-fA-F]+',row[0]):symbols[row[2]]=int(row[0],16)
    for name,value in (('i9100_lpm_wake_route_version',2),('i9100_charge_usb_poll_version',1),('i9100_lpm_wait_policy_version',1),('i9100_lpm_wfi_enabled',0)):
        if struct.unpack_from('<I',z,symbols[name]-0x48000000)[0]!=value:raise ValueError('Actual ARM version missing')
    timeout=manifest.get('standalone_charge_usb_timeout_seconds')
    if type(timeout) is not int or timeout and not 120<=timeout<=600:raise ValueError('Invalid actual diagnostic timeout')
    for name,value in (('i9100_charge_usb_session_version',1),('i9100_charge_usb_timeout_seconds',timeout)):
        if struct.unpack_from('<I',z,symbols[name]-0x48000000)[0]!=value:raise ValueError('Actual USB session policy differs')
    for tag in (b'I9LV1 ',b'I9RT1 ',b'I9CHC2 READY '):
        if tag not in z:raise ValueError('Actual first-packet record missing')
    out.mkdir()
    wiring=mod('candidate_arm_calls',ROOT/'xnu-S2I9100/tools/audit-i9100-call-wiring.py')
    result,asm=wiring.inspect(package/'mach_kernel','_i9100_power_rtc_seconds',['_i9100_power_rtc_snapshot'])
    if not result['callees']['_i9100_power_rtc_snapshot']['direct_calls']:raise ValueError('RTC actual wrapper not wired')
    (out/'kernel-rtc-calls.json').write_text(json.dumps(result,indent=2)+'\n');(out/'kernel-rtc.s.txt').write_text(asm)
    for caller in ('i9100_standalone_charge_gate','usbcdc_poll','charge_ep1_complete','usbcdc4210_charge_rtc_report','i9100_power_rtc_snapshot'):
        text=subprocess.check_output(['arm-none-eabi-objdump','-d','--disassemble='+caller,str(elf)],text=True)
        if '<'+caller+'>:' not in text:raise ValueError('Actual ARM function missing '+caller)
        (out/(caller+'.s.txt')).write_text(text)
    gate=(out/'i9100_standalone_charge_gate.s.txt').read_text()
    if '1048' not in gate or not re.search(r'#24\b|#0x18\b',gate):raise ValueError('HPPIR register read not visible in actual gate')
    models=[]
    for name in (
        str(timer_model.relative_to(ROOT)),
        str(confined(a.usb_model).relative_to(ROOT)),
        str(power_model.relative_to(ROOT)),
        'uniloader-S2I9100/out/charge-command-check-20261121-085024/result.json',
        'uniloader-S2I9100/out/charge-capture-rtc-check-20261121-0847/result.json'):
        file=ROOT/name;record=json.loads(file.read_text())
        if record.get('result')!='PASS':raise ValueError('Model failed')
        models.append(dict(path=name,sha256=sha(file)))
    models.extend(dict(path=name,sha256=sha(ROOT/name)) for name in extra_models if name not in {r['path'] for r in models})
    summary=dict(result='PASS',hardware=False,kernel_sha256=expected,
        zImage_sha256=sha(package/'zImage'),charger_tag=identity['tag'],plan_sha256=sha(plan),
        reused_kernel_inputs=len(snapshot['reused_link_inputs']),loader_inputs=len(identity['sources']),
        models=models,scope='One RTC bus replacement over the exact charge/SD baseline; no eMMC or physical current proof')
    (out/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    (package/'candidate-origin.json').write_text(json.dumps(dict(summary,status='offline-audited-unflashed',audit=str(out),plan_unconsumed=True),indent=2)+'\n')
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
