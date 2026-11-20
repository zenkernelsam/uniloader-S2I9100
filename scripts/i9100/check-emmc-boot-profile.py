#!/usr/bin/env python3
"""Offline cross-language boot record/tree/profile failures; no device contacts."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import zlib
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
    p.add_argument('--clock-proof',type=Path,help='Actual model-marked512B capture for original IDMAC evidence refusal tests')
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
    sdr=None
    if m.get('sdr_boot_path'):
        sdr_raw=(proof/'actual-contract-sdr.bin').read_bytes()
        if hashlib.sha256(sdr_raw).hexdigest()!=m['actual_sdr_contract_sha256']:raise ValueError('Actual SDR contract output changed')
        sdr=c.decode(sdr_raw)
        assert sdr['transport']==dict(width=8,high_speed=1,target_hz=50000000,vcc_mv=3300)
        assert c.encode(sdr['profile'],True,sdr['pair_manifest_sha256'],sdr['system'],sdr['data'],transport=sdr['transport'])==sdr_raw
        bad=bytearray(sdr_raw);bad[220]^=1
        import zlib
        bad[252:256]=zlib.crc32(bad[:252]).to_bytes(4,'little');rejects(lambda:c.decode(bad))
    idmac_records={}
    for key,file,digest in (('idmac_boot_path','actual-contract-idmac.bin','actual_idmac_contract_sha256'),
                            ('idmac_sdr_boot_path','actual-contract-idmac-sdr.bin','actual_idmac_sdr_contract_sha256')):
        if not m.get(key):continue
        encoded=(proof/file).read_bytes()
        if hashlib.sha256(encoded).hexdigest()!=m[digest]:raise ValueError('Actual IDMAC C contract changed')
        item=c.decode(encoded);assert item['idmac']is True
        assert c.encode(item['profile'],True,item['pair_manifest_sha256'],item['system'],item['data'],transport=item.get('transport'),idmac=True)==encoded
        import zlib
        for offset in (236,240,244,251):
            bad=bytearray(encoded);bad[offset]^=1;bad[252:256]=zlib.crc32(bad[:252]).to_bytes(4,'little');rejects(lambda:c.decode(bad))
        unreviewed=c.encode(item['profile'],False,item['pair_manifest_sha256'],item['system'],item['data'],model=True,transport=item.get('transport'),idmac=True)
        assert c.decode(unreviewed)['flags']==2 and c.decode(unreviewed)['idmac']
        rejects(lambda:c.encode(item['profile'],True,item['pair_manifest_sha256'],item['system'],item['data'],model=True,transport=item.get('transport'),idmac=True))
        idmac_records[file]=dict(raw_sha256=hashlib.sha256(encoded).hexdigest(),unreviewed=unreviewed)
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
    for key in ('xxti_hz','xusbxti_hz'):controller['registers'].pop(key,None)
    originals['controller']=json.dumps(controller).encode()
    assert evidence_check.check(record['profile'],originals,True,False)['partitions']==12
    idmac_board=None;clock_source=None
    if a.clock_proof:
        clock_folder=a.clock_proof.resolve()
        if not clock_folder.is_relative_to(c.ROOT/'xnu-S2I9100/out'):raise ValueError('Clock proof escaped project')
        cm=json.loads((clock_folder/'manifest.json').read_text());clock_raw=(clock_folder/'clock-mpll.bin').read_bytes()
        if cm.get('result')!='PASS' or cm.get('hardware_tested')is not False or cm['record_outputs']['clock-mpll.bin']!=hashlib.sha256(clock_raw).hexdigest():
            raise ValueError('Original clock model evidence changed')
        clock=module('clock_evidence','emmc-clock-evidence.py');controller=clock.controller(clock_raw,False,'Actual production512B capture with explicit register facade')
        originals['controller']=json.dumps(controller).encode();assert evidence_check.check(record['profile'],originals,True,False)['clock_record_verified']
        idmac_checker=module('idmac_evidence','emmc-idmac-evidence.py')
        idmac_board=dict(schema=1,kind='GT-I9100-IDMAC32',model_fixture=True,board_reviewed=False,cid=record['profile']['card']['cid'],
            host_physical=0x12550000,clock_record_sha256=hashlib.sha256(clock_raw).hexdigest(),source_note='Actual production clock model output; no physical controller claim',descriptor_bits=32,dma_interface=0)
        assert idmac_checker.check(idmac_board,record['profile']['card'],controller)['result']=='PASS'
        rejects(lambda:idmac_checker.check(idmac_board,record['profile']['card'],controller,True))
        for field,value in (('host_physical',0x12530000),('descriptor_bits',64),('dma_interface',1),('board_reviewed',True),('clock_record_sha256','0'*64),('source_note','')):
            bad=copy.deepcopy(idmac_board);bad[field]=value;rejects(lambda:idmac_checker.check(bad,record['profile']['card'],controller))
        bad=copy.deepcopy(idmac_board);bad['cid'][0]^=1;rejects(lambda:idmac_checker.check(bad,record['profile']['card'],controller))
        for field,value in (('host_bmod',1),('host_idsts',1<<13),('host_hcon',controller['registers']['host_hcon']|(1<<16))):
            forged=bytearray(clock_raw);index=clock.FIELDS.index(field)
            for at in (64,224):forged[at+index*4:at+index*4+4]=value.to_bytes(4,'little')
            forged[508:512]=zlib.crc32(forged[:508]).to_bytes(4,'little')
            bad_control=clock.controller(bytes(forged),False,'Explicit negative engine/register fixture')
            bad=copy.deepcopy(idmac_board);bad['clock_record_sha256']=hashlib.sha256(forged).hexdigest()
            rejects(lambda:idmac_checker.check(bad,record['profile']['card'],bad_control))
        bad_control=copy.deepcopy(controller);bad_control['registers']['host_hcon']^=1;rejects(lambda:idmac_checker.check(idmac_board,record['profile']['card'],bad_control))
        clock_source=dict(path=str(clock_folder.relative_to(c.ROOT)),manifest_sha256=hashlib.sha256((clock_folder/'manifest.json').read_bytes()).hexdigest(),record_sha256=hashlib.sha256(clock_raw).hexdigest())
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
    for file,receipt in idmac_records.items():
        sub=output/(file[:-4]+'-unreviewed');sub.mkdir();wire=receipt['unreviewed'];(sub/'emmc-boot.bin').write_bytes(wire)
        meta=dict(manifest,record=c.decode(wire),record_sha256=hashlib.sha256(wire).hexdigest());(sub/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
        assert c.read_prepared(sub)[0]==wire;rejects(lambda:c.read_prepared(sub,True))
    (output/'dtb').write_bytes(tree)
    kernel_check=None
    if a.kernel:
        kernel_checker=module('emmc_kernel','check-emmc-kernel.py')
        defs=kernel_checker.definitions(a.kernel.read_bytes())
        for required in ('_i9100_hfs_data_bootstrap','_i9100_storage_shutdown_diag','_i9100_emmc_boot_decode'):
            assert required in defs
        for required,method in (('IOS6I9100EMMCBlockDriver','instantiateDesiredMediaObject'),
                                ('IOS6I9100EMMCMedia','matchPropertyTable')):
            assert any(name.startswith('__ZN'+str(len(required))+required) and method in name for name in defs)
        # This test's kernel is explicitly a historical offline freeze; do
        # not let a missing new storage object/provenance error masquerade as
        # the intended deployment refusal.
        try:kernel_checker.verify(a.kernel)
        except ValueError as error:
            if 'Historical LPM-disabled offline fixture' not in str(error):raise
        else:raise AssertionError('Historical fixture was accepted for deployment')
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
        args.idmac=True;args.output=output/'idmac-unreviewed';idmac_generated,idmeta=preparer.prepare(args)
        assert idmeta['record']['flags']==2 and idmeta['record']['idmac']is True and not idmeta['deployment_authorized']
        assert c.read_prepared(idmac_generated)[0]==(idmac_generated/'emmc-boot.bin').read_bytes();rejects(lambda:c.read_prepared(idmac_generated,True))
        args.mark_reviewed=True;args.output=output/'idmac-model-review-refused';rejects(lambda:preparer.prepare(args));assert not args.output.exists()
    result=dict(result='PASS',hardware_tested=False,device_contacted=False,model_fixture=True,
        native_proof=str(proof.relative_to(c.ROOT)),native_manifest_sha256=hashlib.sha256((proof/'manifest.json').read_bytes()).hexdigest(),
        actual_c_record_sha256=hashlib.sha256(raw).hexdigest(),model_record_sha256=hashlib.sha256(model).hexdigest(),
        idmac_contracts={file:{k:v for k,v in receipt.items()if k!='unreviewed'}for file,receipt in idmac_records.items()},clock_proof=clock_source,
        sdr_contract_sha256=hashlib.sha256(sdr_raw).hexdigest()if sdr else None,
        tree_sha256=hashlib.sha256(tree).hexdigest(),kernel_check=kernel_check,prepared_unreviewed=str(generated.relative_to(c.ROOT)) if generated else None,
        sources={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in
        ('emmc-boot-contract.py','emmc-inventory-evidence.py','emmc-idmac-evidence.py','emmc-clock-evidence.py','check-emmc-boot-profile.py','check-emmc-kernel.py','prepare-emmc-boot.py','prepare-payloads.py')},requirements='Model record refused by production packer/boot; current card/clock/backups and deployment approval still required')
    (output/'manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print('PASS exact actual C record/Python decode+encode, structuredDT/duplicate/truncation/model-refusal; EVIDENCE',output)
if __name__=='__main__':main()
