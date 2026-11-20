#!/usr/bin/env python3
"""Plan one approved read-only Linux/TWRP acquisition; no reboot, flash or device writes."""
import argparse
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[3];REPO=ROOT/'uniloader-S2I9100';OUT=REPO/'out'
spec=importlib.util.spec_from_file_location('emmc_read_evidence',Path(__file__).with_name('emmc-read-evidence.py'))
evidence=importlib.util.module_from_spec(spec);spec.loader.exec_module(evidence)
REMOTE='/tmp/i9100-emmc-read-linux' # Must have been installed explicitly beforehand.

class UncertainAcquisition(RuntimeError):pass
def save(path,value):
    with Path(path).open('x',encoding='utf8')as f:json.dump(value,f,indent=2,ensure_ascii=False);f.write('\n')
def utc():return datetime.now(timezone.utc).isoformat()
def item(path):return evidence.file_item(path)
def path_in_project(path):return evidence.project_file(path)
def create_plan(build,adb,serial,mode,source_note,inventory=None,output=None,model=False):
    build=Path(build).resolve();adb=path_in_project(adb)
    if not build.is_relative_to(ROOT/'xnu-S2I9100/out')or not re.fullmatch('[A-Za-z0-9._:-]{1,80}',serial)or mode not in ('inventory','backup-user'):
        raise ValueError('Exact retained build, adb serial and fixed acquisition mode required')
    if not source_note.strip()or type(model)is not bool:raise ValueError('Capture provenance note required')
    source=evidence.project_file(build/'manifest.json');built=json.loads(source.read_text())
    if built.get('result')!='PASS'or built.get('device_contacted')is not False:raise ValueError('Require offline ARM executable build proof')
    binary=path_in_project(ROOT/built['linux_arm_executable']['path'])
    actual=item(binary)
    if any(actual[key]!=built['linux_arm_executable'][key]for key in ('path','sha256','bytes')):raise ValueError('Collector binary drift')
    for name,digest in built['collector_sources'].items():
        if evidence.sha(ROOT/name)!=digest:raise ValueError('Collector source changed since ARM build')
    previous=None;expected_cid=None
    if mode=='backup-user':
        if inventory is None:raise ValueError('Whole-user backup must name a prior current-card inventory')
        inv=evidence.verify_acquisition(inventory,require_device=not model)
        if inv['capture_header']['mode']!=1 or inv['model_fixture']!=model:raise ValueError('Inventory mode/model provenance mismatch')
        expected_cid=''.join(f'{v:08x}'for v in inv['capture_header']['cid']);previous=item(Path(inventory)/'manifest.json')
    if mode=='inventory'and inventory is not None:raise ValueError('Inventory has no inherited CID approval')
    folder=Path(output).resolve()if output else OUT/('emmc-acquisition-plan-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    if not folder.is_relative_to(OUT)or folder.exists():raise ValueError('Use a new retained acquisition-plan directory')
    minimum=(evidence.SECTORS*512*2+256*1024*1024)if mode=='backup-user'else 16*1024*1024
    if shutil.disk_usage(folder.parent if folder.parent.exists()else OUT).free<minimum:raise ValueError('Not enough space for stream and independent whole-user image')
    folder.mkdir(parents=True)
    capture_nonce=secrets.token_hex(16)
    argv=[str(adb),'-s',serial,'exec-out',REMOTE,mode,capture_nonce,*([expected_cid]if expected_cid else [])]
    plan=dict(schema=1,kind='i9100-emmc-read-only-plan',created_at=utc(),mode=mode,model_fixture=model,
      collector=item(binary),collector_build=item(source),collector_sources=built['collector_sources'],producer_source_sha256=built['producer_source_sha256'],adb=item(adb),
      serial=serial,remote_path=REMOTE,nonce=capture_nonce,expected_cid=expected_cid,prior_inventory=previous,
      source_note=source_note,argv=argv,timeout_seconds=30 if mode=='inventory'else 7200,
      minimum_free_bytes=minimum,scope='Read-only exclusive mmcblk0 user area; no device/MMC writes, reboot, unmount or flashing; prior manual tool deployment required',
      contacts_device_only_on_execute=True,automatic_retry=False,automatic_kill=False,
      orchestrator_sha256=evidence.sha(__file__),importer_sha256=evidence.sha(Path(__file__).with_name('emmc-read-evidence.py')),
      evidence_checker_sha256=evidence.sha(Path(__file__).with_name('emmc-inventory-evidence.py')))
    save(folder/'plan.json',plan);digest=evidence.sha(folder/'plan.json');(folder/'plan.sha256').write_text(digest+'\n')
    return folder,digest

def execute(plan_path,approval,host=None):
    path=path_in_project(plan_path);folder=path.parent
    if not folder.is_relative_to(OUT)or evidence.sha(path)!=approval:raise ValueError('Exact immutable acquisition plan SHA required')
    plan=json.loads(path.read_text())
    if plan.get('schema')!=1 or plan.get('kind')!='i9100-emmc-read-only-plan' or plan.get('automatic_retry')is not False or plan.get('automatic_kill')is not False:
        raise ValueError('Unknown acquisition plan')
    if plan['orchestrator_sha256']!=evidence.sha(__file__)or plan['importer_sha256']!=evidence.sha(Path(__file__).with_name('emmc-read-evidence.py')):
        raise ValueError('Acquisition tool changed since plan creation')
    if plan.get('evidence_checker_sha256')!=evidence.sha(Path(__file__).with_name('emmc-inventory-evidence.py')):
        raise ValueError('Acquisition table validator changed since approval')
    if plan['model_fixture']and host is None:raise ValueError('Model plan cannot execute against a device')
    if host is not None and not plan['model_fixture']:raise ValueError('Process test facade requires an explicit model plan')
    mode=plan['mode'];expected=plan['expected_cid'];nonce=plan['nonce'];serial=plan['serial']
    if mode not in ('inventory','backup-user')or not re.fullmatch('[A-Za-z0-9._:-]{1,80}',serial):raise ValueError('Altered fixed acquisition mode/serial')
    evidence.nonce(nonce)
    if mode=='backup-user'and not re.fullmatch('[0-9a-f]{32}',expected or ''):raise ValueError('Missing exact current CID')
    if mode=='backup-user'and plan['prior_inventory']is None:raise ValueError('Backup requires its original current-card inventory')
    for thing in ('collector','collector_build','adb'):
        actual=item(ROOT/plan[thing]['path'])
        if any(actual[k]!=plan[thing][k]for k in ('path','bytes','sha256')):raise ValueError('Approved executable/build changed')
    built=json.loads((ROOT/plan['collector_build']['path']).read_text())
    if built.get('producer_source_sha256')!=plan['producer_source_sha256']:raise ValueError('Approved producer build tag changed')
    if mode=='inventory'and (expected is not None or plan['prior_inventory']is not None):raise ValueError('Inventory cannot inherit unrelated backup arguments')
    for name,digest in plan['collector_sources'].items():
        if evidence.sha(ROOT/name)!=digest:raise ValueError('Approved collector source drift')
    if plan['prior_inventory']:
        prior=plan['prior_inventory'];inv=evidence.verify_acquisition((ROOT/prior['path']).parent,require_device=not plan['model_fixture'])
        if item(ROOT/prior['path'])!=prior or ''.join(f'{v:08x}'for v in inv['capture_header']['cid'])!=expected:
            raise ValueError('Current-card inventory changed')
    argv=[str((ROOT/plan['adb']['path']).resolve()),'-s',serial,'exec-out',REMOTE,mode,nonce,*([expected]if expected else [])]
    if plan['argv']!=argv or plan['remote_path']!=REMOTE:raise ValueError('Altered read-only argv')
    if plan['timeout_seconds']!=(30 if mode=='inventory' else 7200):raise ValueError('Altered bounded observation timeout')
    minimum=evidence.SECTORS*512*2+256*1024*1024 if mode=='backup-user' else 16*1024*1024
    if plan['minimum_free_bytes']!=minimum:raise ValueError('Altered required backup space')
    if shutil.disk_usage(folder).free<plan['minimum_free_bytes']:raise ValueError('Insufficient retained backup space')
    if (folder/'started.json').exists():raise FileExistsError('Acquisition plan was already consumed')
    # A second plan must not become a second opener while the first process
    # is still outstanding. Retain the owner receipt on uncertainty; close
    # it by archival rename only after this exact process returns terminal.
    owner_path=(folder.parent/'modeled-owner.json')if host is not None else OUT/'emmc-acquisition-owner.json'
    save(owner_path,dict(plan=str(path.relative_to(ROOT)),plan_sha256=approval,nonce=nonce,serial=serial,started_at=utc(),
      process_record=str((folder/'process.json').relative_to(ROOT)),model_fixture=plan['model_fixture']))
    # One OS-open exclusive receipt consumes the plan before any process can
    # own ADB. Failed or uncertain plans never become executable again.
    save(folder/'started.json',dict(plan_sha256=approval,started_at=utc(),process_not_started_yet=True))
    if host is None:
        # Purpose-built read-only process API, no shell command interpolation.
        with (folder/'acquisition.stream').open('xb')as out,(folder/'acquisition.stderr').open('xb')as err:
            try:proc=subprocess.Popen(argv,stdout=out,stderr=err)
            except OSError as error:
                save(folder/'process-not-started.json',dict(error=str(error),ended_at=utc()))
                owner_path.rename(folder/'owner-not-started.json');raise
            save(folder/'process.json',dict(pid=proc.pid,argv=argv,started_at=utc()))
            deadline=time.monotonic()+plan['timeout_seconds']
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    code=proc.poll()
                    if code is not None:break
                    save(folder/'uncertain.json',dict(pid=proc.pid,observed_at=utc(),reason='Process remains owned; no kill/retry or new opener'))
                    raise UncertainAcquisition('Acquisition process still owns transport; do not retry or kill PID '+str(proc.pid))
                try:code=proc.wait(timeout=min(30,remaining));break
                except subprocess.TimeoutExpired:
                    print('Read-only acquisition still running; PID',proc.pid,'bytes',out.tell(),flush=True)
    else:
        code=host.run(argv,folder/'acquisition.stream',folder/'acquisition.stderr',plan['timeout_seconds'])
    save(folder/'process-exit.json',dict(returncode=code,ended_at=utc()))
    owner_path.rename(folder/'owner-closed.json')
    if code!=0:raise ValueError('Read-only collector exited unsuccessfully; keep partial stream and stop')
    with (folder/'acquisition.stream').open('rb')as f:observed=evidence.header(evidence.exact(f,128))
    if observed['producer_source_sha256']!=plan['producer_source_sha256']:raise ValueError('Remote collector build/source tag does not match approved local build')
    if expected is not None and ''.join(f'{v:08x}'for v in observed['cid'])!=expected:raise ValueError('Remote current CID changed since inventory')
    acquired,record=evidence.import_stream(folder/'acquisition.stream',folder/'validated',nonce,plan['source_note'],code,plan['model_fixture'])
    if plan['prior_inventory'] and record['card']!=inv['card']:
        raise ValueError('Acquired current table differs from the approved inventory; retain evidence without completing this backup plan')
    receipt=dict(result='PASS',plan_sha256=approval,validated_manifest=item(acquired/'manifest.json'),
      model_fixture=record['model_fixture'],device_observed=record['device_observed'],boot_ready=False,write_partitions=[])
    save(folder/'result.json',receipt);return receipt

def main():
    if os.name!='posix':raise RuntimeError('Run acquisition planning/validation inside WSL CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    make=sub.add_parser('plan');make.add_argument('--build',type=Path,required=True);make.add_argument('--adb',type=Path,required=True)
    make.add_argument('--serial',required=True);make.add_argument('--mode',choices=('inventory','backup-user'),default='inventory')
    make.add_argument('--source-note',required=True);make.add_argument('--inventory',type=Path);make.add_argument('--output',type=Path)
    run=sub.add_parser('execute');run.add_argument('--plan',type=Path,required=True);run.add_argument('--approve-read-plan',required=True)
    check=sub.add_parser('verify');check.add_argument('folder',type=Path);check.add_argument('--require-backup',action='store_true');check.add_argument('--require-device',action='store_true')
    a=p.parse_args()
    if a.command=='plan':
        folder,digest=create_plan(a.build,a.adb,a.serial,a.mode,a.source_note,a.inventory,a.output)
        print(json.dumps(dict(plan=str(folder/'plan.json'),sha256=digest,device_contacted=False,boot_ready=False),indent=2))
    elif a.command=='execute':print(json.dumps(execute(a.plan,a.approve_read_plan),indent=2))
    else:
        m=evidence.verify_acquisition(a.folder,a.require_backup,a.require_device)
        print(json.dumps(dict(result='PASS',model=m['model_fixture'],device_observed=m['device_observed'],
          backup=m['whole_user_area'] is not None,boot_ready=False),indent=2))
if __name__=='__main__':main()
