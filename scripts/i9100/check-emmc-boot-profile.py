#!/usr/bin/env python3
"""Offline cross-language boot record/tree/profile failures; no device contacts."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from datetime import datetime
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=module('emmc_contract','emmc-boot-contract.py');dt=module('payload_dt','prepare-payloads.py');evidence_check=module('emmc_evidence','emmc-inventory-evidence.py')
def rejects(call):
    try:call()
    except (ValueError,RuntimeError):return
    raise AssertionError('Unsafe profile/tree accepted')
def main():
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-proof',type=Path,required=True)
    p.add_argument('--pair',type=Path,help='Also run the real default-unreviewed preparer on these independent raw HFS volumes')
    p.add_argument('--kernel',type=Path,help='Audit real Mach-O definitions and reject historical LPM-disabled deployment')
    a=p.parse_args()
    proof=a.native_proof.resolve()
    if not proof.is_relative_to(c.ROOT/'xnu-S2I9100/out'):raise ValueError('Proof escaped XNU out')
    m=json.loads((proof/'manifest.json').read_text())
    if m.get('result')!='PASS' or m.get('hardware_tested')is not False:raise ValueError('Require actual successful offline C model')
    raw=(proof/'actual-contract.bin').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=m['actual_contract_sha256']:raise ValueError('Actual encoded record changed')
    record=c.decode(raw);assert c.encode(record['profile'],True,record['pair_manifest_sha256'],record['system'],record['data'])==raw
    import copy
    originals={}
    for name,file in (('cid','cid.bin'),('gpt-primary','gpt-primary.bin'),('gpt-backup','gpt-backup.bin'),('pit','pit.bin')):
        item=(proof/file).read_bytes()
        if hashlib.sha256(item).hexdigest()!=m['model_table_evidence_sha256'][file]:raise ValueError('Actual C table output changed')
        originals[name]=item
    host=record['profile']['host']
    controller=dict(schema=1,model_fixture=True,ciu_clock_hz=host['ciu_clock_hz'],clock_and_pins_reviewed=False,
        host_physical=0x12550000,measurement_note='Explicit register facade; 100MHz fixture, no electrical measurement',
        registers=dict(cmu_ip_gate=1<<9,cmu_source_gate=1<<16,gpk0_data=4,gic_enable=0,**{k:v for k,v in host.items() if k!='ciu_clock_hz'}))
    originals['controller']=json.dumps(controller).encode()
    assert evidence_check.check(record['profile'],originals,True,False)['partitions']==12
    for name in ('cid','gpt-primary','gpt-backup','pit'):
        bad=copy.deepcopy(originals);b=bytearray(bad[name]);b[0]^=1;bad[name]=bytes(b);rejects(lambda:evidence_check.check(record['profile'],bad,True,False))
    bad_controller=copy.deepcopy(controller);bad_controller['registers']['source_mux']^=1<<16
    bad=copy.deepcopy(originals);bad['controller']=json.dumps(bad_controller).encode();rejects(lambda:evidence_check.check(record['profile'],bad,True,False))
    rejects(lambda:c.decode(raw[:-1]));bad=bytearray(raw);bad[47]^=1;rejects(lambda:c.decode(bad))
    rejects(lambda:c.encode(record['profile'],True,record['pair_manifest_sha256'],record['system'],record['data'],model=True))
    model=c.encode(record['profile'],False,record['pair_manifest_sha256'],record['system'],record['data'],model=True);assert c.decode(model)['flags']==2
    base=dt.device_tree();tree=c.add_device_tree(base,model);assert len(tree)==len(base)+36+256 and model in tree
    rejects(lambda:c.add_device_tree(tree,model));rejects(lambda:c.add_device_tree(base[:-4],model));rejects(lambda:c.add_device_tree(base+b'junk',model))
    malformed=bytearray(base);malformed[:4]=(10000).to_bytes(4,'little');rejects(lambda:c.add_device_tree(malformed,model))
    output=c.REPO/'out'/('emmc-boot-profile-check-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));output.mkdir()
    folder=output/'model-profile';folder.mkdir();(folder/'emmc-boot.bin').write_bytes(model)
    manifest=dict(schema=1,kind='i9100-emmc-boot-contract',result='PASS',device_contacted=False,record=c.decode(model),
        record_sha256=hashlib.sha256(model).hexdigest(),contract_tool_sha256=hashlib.sha256(Path(__file__).with_name('emmc-boot-contract.py').read_bytes()).hexdigest())
    (folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8');assert c.read_prepared(folder)[0]==model
    rejects(lambda:c.read_prepared(folder,require_reviewed=True))
    (output/'dtb').write_bytes(tree)
    kernel_check=None
    if a.kernel:
        kernel_checker=module('emmc_kernel','check-emmc-kernel.py')
        defs=kernel_checker.definitions(a.kernel.read_bytes())
        for required in ('_i9100_hfs_data_bootstrap','_i9100_storage_shutdown_diag','_i9100_emmc_boot_decode'):
            assert required in defs
        rejects(lambda:kernel_checker.verify(a.kernel))
        kernel_check=dict(path=str(a.kernel.resolve().relative_to(c.ROOT)),sha256=hashlib.sha256(a.kernel.read_bytes()).hexdigest(),
            real_definitions_present=True,historical_deployment_refused=True)
    generated=None
    if a.pair:
        evidence={}
        for name,data in originals.items():
            file=output/(name+'.source');file.write_bytes(data);evidence[name]=dict(path=str(file.relative_to(c.ROOT)),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        inventory=dict(schema=1,soc='exynos4210',machine='GT-I9100',model_fixture=True,clock_and_pins_reviewed=False,profile=record['profile'],evidence=evidence)
        inventory_path=output/'inventory-model.json';inventory_path.write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf8')
        preparer=module('emmc_prepare','prepare-emmc-boot.py')
        from argparse import Namespace
        args=Namespace(inventory=inventory_path,pair=a.pair,source_note='Historical primary/PIT with explicitly synthetic backup, controller and CID from production C model',mark_reviewed=True,output=output/'refused-reviewed')
        rejects(lambda:preparer.prepare(args));assert not args.output.exists()
        args.mark_reviewed=False;args.output=output/'default-unreviewed'
        generated,meta=preparer.prepare(args);assert meta['record']['flags']==2 and not meta['deployment_authorized'] and not meta['boot_ready']
        rejects(lambda:c.read_prepared(generated,require_reviewed=True))
    result=dict(result='PASS',hardware_tested=False,device_contacted=False,model_fixture=True,
        native_proof=str(proof.relative_to(c.ROOT)),native_manifest_sha256=hashlib.sha256((proof/'manifest.json').read_bytes()).hexdigest(),
        actual_c_record_sha256=hashlib.sha256(raw).hexdigest(),model_record_sha256=hashlib.sha256(model).hexdigest(),
        tree_sha256=hashlib.sha256(tree).hexdigest(),kernel_check=kernel_check,prepared_unreviewed=str(generated.relative_to(c.ROOT)) if generated else None,
        sources={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in
        ('emmc-boot-contract.py','emmc-inventory-evidence.py','check-emmc-boot-profile.py','check-emmc-kernel.py','prepare-emmc-boot.py','prepare-payloads.py')},requirements='Model record refused by production packer/boot; current card/clock/backups and deployment approval still required')
    (output/'manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print('PASS exact actual C record/Python decode+encode, structuredDT/duplicate/truncation/model-refusal; EVIDENCE',output)
if __name__=='__main__':main()
