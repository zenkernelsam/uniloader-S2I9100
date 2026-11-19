#!/usr/bin/env python3
"""Export separately recorded ROM/patched probe replies for HCD review, offline."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
from datetime import datetime
import sys
REPO=Path(__file__).resolve().parents[2];ROOT=REPO.parent.resolve()
spec=importlib.util.spec_from_file_location('bt_asset_guard',Path(__file__).with_name('prepare-bt-hcd.py'))
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


def report(path):
    raw,meta=guard.source(path,16384);p=json.loads(raw)
    if p.get('schema')!=1 or p.get('kind')!='i9100-bt-rom-probe' or p.get('completed') is not True or p.get('fault') is not False or \
            p.get('error')!=0 or p.get('cleanup_error')!=0 or p.get('valid_fields')!=31 or not p.get('generation'):
        raise ValueError('Require a completed error-free five-read raw probe record')
    sizes={'version':9,'name':249,'address':7,'buffer':8,'features':9};fields={}
    for name,length in sizes.items():
        encoded=p['raw'][name]
        if not isinstance(encoded,str) or len(encoded)!=length*2:raise ValueError('Raw probe length differs from original HCI reply')
        data=bytes.fromhex(encoded)
        if len(data)!=length or data[0]:raise ValueError('Raw HCI command has a failure status')
        fields[name]=data
    v=fields['version'];version=dict(hci_version=v[1],hci_revision=struct.unpack_from('<H',v,2)[0],lmp_version=v[4],
        manufacturer=struct.unpack_from('<H',v,5)[0],lmp_subversion=struct.unpack_from('<H',v,7)[0])
    if version['manufacturer']!=15:raise ValueError('Raw version is not a Broadcom controller')
    return p,fields,version,meta


def export(args):
    rom,rf,rv,rm=report(args.rom);patched,pf,pv,pm=report(args.patched)
    if args.rom.resolve()==args.patched.resolve() or rm['sha256']==pm['sha256']:raise ValueError('ROM and patched evidence must be separate recorded runs')
    if not args.source_note.strip():raise ValueError('Independent original controller/BDADDR provenance note required')
    if rf['address']!=pf['address']:raise ValueError('ROM/patched BDADDR differs; review original customization before exporting')
    value=guard.controller_proof(dict(rom=rv,patched=pv,factory_bdaddr_hci_hex=rf['address'][1:].hex()))
    model=bool(rom.get('model_fixture') or patched.get('model_fixture'))
    if args.mark_reviewed and model:raise ValueError('Model controller replies cannot be marked as hardware reviewed')
    out=args.output.resolve() if args.output else REPO/'out'/('bt-controller-proof-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    if not out.is_relative_to((REPO/'out').resolve()) or out.exists():raise ValueError('Require fresh loader out directory')
    value['model_fixture']=model
    value['probe_sources']=dict(rom_sha256=rm['sha256'],patched_sha256=pm['sha256'])
    out.mkdir(parents=True);target=out/'controller-proof.json';target.write_text(json.dumps(value,indent=2)+'\n')
    summary=dict(result='PASS',device_contacted=False,model_fixture=model,board_data_reviewed=bool(args.mark_reviewed),
        inputs=dict(rom=rm,patched=pm),source_note=args.source_note,proof_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        requirements='Raw replies establish recorded identity, not RAM geometry/HCD compatibility/electrical proof. Keep separate source review before deployment.')
    (out/'manifest.json').write_text(json.dumps(summary,indent=2)+'\n');return out,summary


def main():
    guard.cap();p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rom',type=Path,required=True)
    p.add_argument('--patched',type=Path,required=True);p.add_argument('--source-note',required=True)
    p.add_argument('--mark-reviewed',action='store_true');p.add_argument('--output',type=Path)
    out,m=export(p.parse_args());print(json.dumps(dict(output=str(out),board_data_reviewed=m['board_data_reviewed'],model_fixture=m['model_fixture'],device_contacted=False),indent=2))


if __name__=='__main__':main()
