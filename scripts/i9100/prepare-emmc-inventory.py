#!/usr/bin/env python3
"""Combine actual current-card evidence with the pre-probe512B clock record, unreviewed by default."""
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3];REPO=ROOT/'uniloader-S2I9100'
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
clock=module('emmc_clock','emmc-clock-evidence.py');validator=module('emmc_inventory','emmc-inventory-evidence.py');acquired=module('emmc_read','emmc-read-evidence.py')

def prepare(acquisition,record,source_note,output=None,mark_clock_reviewed=False):
    acquisition=Path(acquisition).resolve();record=Path(record).resolve()
    if not record.is_relative_to(ROOT)or not record.is_file()or record.stat().st_size!=512:raise ValueError('Require exact512B retained clock capture')
    if not source_note.strip():raise ValueError('Describe original device/session/board reference-clock provenance')
    current=acquired.verify_acquisition(acquisition,require_device=mark_clock_reviewed)
    raw=record.read_bytes();observed=clock.decode(raw,True)
    if current['model_fixture']!=observed['model_fixture']:raise ValueError('Current-card and clock evidence provenance mismatch')
    if mark_clock_reviewed and current['model_fixture']:raise ValueError('Model inventory cannot become hardware reviewed')
    controller=clock.controller(raw,mark_clock_reviewed,source_note)
    regs=observed['registers'];host={name:regs[name]&mask for name,mask in
        (('source_mux',0xf0000),('source_divider',0xff0f),('clksel',0xffffffff),('gpk0_mux',65535),('gpk0_pull',255),('gpk0_drive',255))}
    host.update(ciu_clock_hz=observed['ciu_clock_hz'],xxti_hz=observed['xxti_hz'],xusbxti_hz=observed['xusbxti_hz'])
    card={name:current['card'][name]for name in ('cid','sectors','primary_crc','backup_crc','entries_crc','disk_guid','system_guid','data_guid')}
    profile=dict(host=host,card=card);evidence=dict(current['evidence'])
    originals={name:(ROOT/item['path']).read_bytes()for name,item in evidence.items()};originals['controller']=json.dumps(controller,sort_keys=True).encode()
    validator.check(profile,originals,current['model_fixture'],mark_clock_reviewed)
    folder=Path(output).resolve()if output else REPO/'out'/('emmc-inventory-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    if not folder.is_relative_to(REPO/'out')or folder.exists():raise ValueError('Use a new retained inventory directory')
    folder.mkdir(parents=True);controller_path=folder/'controller.json';controller_path.write_bytes(originals['controller'])
    evidence['controller']=dict(path=str(controller_path.relative_to(ROOT)),bytes=len(originals['controller']),sha256=hashlib.sha256(originals['controller']).hexdigest())
    inventory=dict(schema=1,soc='exynos4210',machine='GT-I9100',model_fixture=current['model_fixture'],
      profile=profile,evidence=evidence,clock_and_pins_reviewed=mark_clock_reviewed)
    path=folder/'inventory.json';path.write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf8')
    provenance=dict(schema=1,result='PASS',device_contacted=False,hardware_tested=False,clock_reviewed=mark_clock_reviewed,
      acquisition_manifest=dict(path=str((acquisition/'manifest.json').relative_to(ROOT)),sha256=acquired.sha(acquisition/'manifest.json')),
      clock_record=dict(path=str(record.relative_to(ROOT)),sha256=acquired.sha(record)),source_note=source_note,
      inventory_sha256=acquired.sha(path),tools={name:acquired.sha(Path(__file__).with_name(name))for name in
        ('prepare-emmc-inventory.py','emmc-clock-evidence.py','emmc-inventory-evidence.py','emmc-read-evidence.py')},
      deployment_authorized=False,boot_ready=False,requirements='Explicit actual24MHz board roots and current pre-probe host evidence; original full backup and later deployment are separate')
    (folder/'manifest.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf8');return folder,inventory
def main():
    if os.name!='posix':raise RuntimeError('Run preparation/hashes inside WSL CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--acquisition',type=Path,required=True);p.add_argument('--clock-record',type=Path,required=True)
    p.add_argument('--source-note',required=True);p.add_argument('--mark-clock-reviewed',action='store_true');p.add_argument('--output',type=Path)
    a=p.parse_args();folder,inventory=prepare(a.acquisition,a.clock_record,a.source_note,a.output,a.mark_clock_reviewed)
    print(json.dumps(dict(inventory=str(folder/'inventory.json'),model_fixture=inventory['model_fixture'],clock_reviewed=a.mark_clock_reviewed,boot_ready=False,device_contacted=False),indent=2))
if __name__=='__main__':main()
