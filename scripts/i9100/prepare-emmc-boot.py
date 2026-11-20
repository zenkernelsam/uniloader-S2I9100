#!/usr/bin/env python3
"""Prepare an offline native eMMC boot profile tied to current evidence and a verified volume pair."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
from datetime import datetime

spec=importlib.util.spec_from_file_location('emmc_contract',Path(__file__).with_name('emmc-boot-contract.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
spec=importlib.util.spec_from_file_location('emmc_inventory',Path(__file__).with_name('emmc-inventory-evidence.py'))
inventory_check=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory_check)
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def prepare(a):
    inventory_raw=c.bounded(a.inventory,65536);inventory=json.loads(inventory_raw)
    required={'schema','soc','machine','model_fixture','profile','evidence','clock_and_pins_reviewed'}
    if set(inventory)!=required or inventory['schema']!=1 or inventory['soc']!='exynos4210' or inventory['machine']!='GT-I9100' or type(inventory['model_fixture'])is not bool:
        raise ValueError('Exact current GT-I9100 native inventory schema required')
    if type(inventory['clock_and_pins_reviewed'])is not bool or not isinstance(inventory['evidence'],dict) or set(inventory['evidence'])!={'cid','gpt-primary','gpt-backup','pit','controller'}:
        raise ValueError('Current CID/two GPT/PIT/controller evidence required')
    if not a.source_note.strip():raise ValueError('Document the independent clock/pin/card evidence source')
    if a.mark_reviewed and (inventory['model_fixture'] or not inventory['clock_and_pins_reviewed']):
        raise ValueError('Models/unverified inherited clocks cannot become hardware reviewed')
    backup_path=getattr(a,'backup_acquisition',None);backup_receipt=None
    if a.mark_reviewed and not backup_path:raise ValueError('Reviewed internal-root profile requires verified original whole-user backup')
    if backup_path:
        spec=importlib.util.spec_from_file_location('emmc_read_evidence',Path(__file__).with_name('emmc-read-evidence.py'))
        backup_check=importlib.util.module_from_spec(spec);spec.loader.exec_module(backup_check)
        captured=backup_check.verify_acquisition(backup_path,require_backup=True,require_device=a.mark_reviewed)
        card=inventory['profile']['card'];observed=captured['card']
        if captured['model_fixture']!=inventory['model_fixture'] or any(observed[name]!=card[name]for name in
            ('cid','sectors','disk_guid','system_guid','data_guid','primary_crc','backup_crc','entries_crc')):
            raise ValueError('Full backup is from another card/table or model source')
        backup_receipt=dict(path=str(Path(backup_path).resolve().relative_to(c.ROOT)),
            manifest_sha256=sha(Path(backup_path)/'manifest.json'),whole_user_area=captured['whole_user_area'],
            model_fixture=captured['model_fixture'],verifier_sha256=sha(Path(__file__).with_name('emmc-read-evidence.py')))
    evidence={};originals={}
    for name,item in inventory['evidence'].items():
        if not isinstance(name,str) or set(item)!= {'path','bytes','sha256'}:raise ValueError('Invalid original evidence item')
        path=(c.ROOT/item['path']).resolve();raw=c.bounded(path,4*1024*1024)
        if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('Current source evidence changed')
        evidence[name]=item;originals[name]=raw
    validated=inventory_check.check(inventory['profile'],originals,inventory['model_fixture'],inventory['clock_and_pins_reviewed'])
    pair_raw=c.bounded(a.pair,256*1024);pair=json.loads(pair_raw)
    if pair.get('schema')!=1 or pair.get('result')!='PASS' or pair.get('hardware_tested')is not False:
        raise ValueError('Require an independently verified offline two-volume manifest')
    volumes=[]
    for role,capacity,journal in (('system',1610612736,False),('data',6442450944,True)):
        item=pair[role];path=(c.ROOT/item['path']).resolve()
        if not path.is_relative_to(c.REPO/'out') or path.stat().st_size!=capacity or item['bytes']!=capacity or item['role']!=role or item['journaled']is not journal:
            raise ValueError('Different role/capacity/image path')
        if sha(path)!=item['sha256']:raise ValueError('Volume bytes changed since pair verification')
        with path.open('rb') as f:f.seek(1024);h=f.read(512)
        if h[:4]!=b'HX\0\5' or struct.unpack_from('>I',h,40)[0]!=8192 or bool(struct.unpack_from('>I',h,4)[0]&0x2000)!=journal:
            raise ValueError('HFSX geometry/journal mismatch')
        volumes.append(dict(create_date=struct.unpack_from('>I',h,16)[0],finder_volume_id=h[104:112].hex()))
    width=getattr(a,'sdr_width',None);transport=None
    if width:
        target=getattr(a,'sdr_clock_hz',None);vcc=getattr(a,'sdr_vcc_mv',None)
        if not target or vcc!=3300:raise ValueError('SDR requires exact clock and separately reviewed3300mV VCC')
        transport=dict(width=width,high_speed=int(getattr(a,'sdr_high_speed',False)),target_hz=target,vcc_mv=vcc)
        if a.mark_reviewed:
            proof_path=getattr(a,'sdr_board_evidence',None)
            if not proof_path:raise ValueError('Reviewed SDR requires original board pad/clock/VCC evidence')
            board_raw=c.bounded(proof_path,65536);board=json.loads(board_raw)
            controller=json.loads(originals['controller'])
            spec=importlib.util.spec_from_file_location('sdr_evidence',Path(__file__).with_name('emmc-sdr-evidence.py'))
            verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
            verifier.check(board,transport,inventory['profile']['card'],controller,True)
            sdr_receipt=dict(path=str(Path(proof_path).resolve().relative_to(c.ROOT)),sha256=hashlib.sha256(board_raw).hexdigest(),
              verifier_sha256=sha(Path(__file__).with_name('emmc-sdr-evidence.py')))
        else:sdr_receipt=None
    else:
        if getattr(a,'sdr_high_speed',False)or getattr(a,'sdr_clock_hz',None)or getattr(a,'sdr_vcc_mv',None)or getattr(a,'sdr_board_evidence',None):
            raise ValueError('SDR parameters require explicit width')
        sdr_receipt=None
    record=c.encode(inventory['profile'],a.mark_reviewed,hashlib.sha256(pair_raw).hexdigest(),*volumes,model=inventory['model_fixture'],transport=transport)
    output=a.output.resolve() if a.output else c.REPO/'out'/('emmc-boot-profile-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    if not output.is_relative_to(c.REPO/'out') or output.exists():raise ValueError('Use a fresh retained loader out directory')
    manifest=dict(schema=1,kind='i9100-emmc-boot-contract',result='PASS',device_contacted=False,hardware_tested=False,
        deployment_authorized=False,boot_ready=False,source_note=a.source_note,record=c.decode(record),record_sha256=hashlib.sha256(record).hexdigest(),
        inventory=dict(path=str(a.inventory.resolve().relative_to(c.ROOT)),sha256=hashlib.sha256(inventory_raw).hexdigest()),
        pair=dict(path=str(a.pair.resolve().relative_to(c.ROOT)),sha256=hashlib.sha256(pair_raw).hexdigest()),evidence=evidence,
        parsed_current_evidence=validated,verified_backup=backup_receipt,sdr_board_evidence=sdr_receipt,
        evidence_checker_sha256=hashlib.sha256(Path(__file__).with_name('emmc-inventory-evidence.py').read_bytes()).hexdigest(),
        contract_tool_sha256=hashlib.sha256(Path(__file__).with_name('emmc-boot-contract.py').read_bytes()).hexdigest(),
        preparer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        requirements='Reviewed current CIU/pins/card/table+full backups and independent deployment review; kernel tests do not approve physical use or initialize other peripherals')
    output.mkdir(parents=True);(output/'emmc-boot.bin').write_bytes(record)
    (output/'inventory.source.json').write_bytes(inventory_raw);(output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
    if c.read_prepared(output)[0]!=record:raise RuntimeError('Retained contract mismatch')
    return output,manifest
def main():
    if os.name!='posix':raise RuntimeError('Run inside the WSL CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inventory',type=Path,required=True);p.add_argument('--pair',type=Path,required=True)
    p.add_argument('--source-note',required=True);p.add_argument('--mark-reviewed',action='store_true');p.add_argument('--backup-acquisition',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--sdr-width',type=int,choices=(4,8));p.add_argument('--sdr-high-speed',action='store_true')
    p.add_argument('--sdr-clock-hz',type=int);p.add_argument('--sdr-vcc-mv',type=int,choices=(3300,));p.add_argument('--sdr-board-evidence',type=Path)
    folder,manifest=prepare(p.parse_args());print(json.dumps(dict(output=str(folder),sha256=manifest['record_sha256'],reviewed=manifest['record']['flags']==1,boot_ready=False,device_contacted=False),indent=2))
if __name__=='__main__':main()
