#!/usr/bin/env python3
"""Verify actual C clock record/native boot wire, full controller provenance and inventory preparation."""
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import zlib

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
clock=module('emmc_clock','emmc-clock-evidence.py');contract=module('emmc_contract','emmc-boot-contract.py');validator=module('emmc_inventory','emmc-inventory-evidence.py')
read=module('emmc_read','emmc-read-evidence.py');prepare=module('emmc_inventory_prepare','prepare-emmc-inventory.py')
def rejects(call):
    try:call()
    except (ValueError,RuntimeError):return
    raise AssertionError('Unsafe clock/controller evidence accepted')
def proof(path):
    path=Path(path).resolve()
    if not path.is_relative_to(contract.ROOT/'xnu-S2I9100/out'):raise ValueError('Proof outside retained XNUout')
    m=json.loads((path/'manifest.json').read_text())
    if m.get('result')!='PASS'or m.get('hardware_tested')is not False:raise ValueError('Require successful actual offline source model')
    platform=contract.ROOT/'xnu-S2I9100/iokit/Drivers/KernelBuiltIn/ARM/AppleARMPlatform'
    for name,expected in m.get('sources',{}).items():
        if hashlib.sha256((platform/name).read_bytes()).hexdigest()!=expected:raise ValueError('Offline proof source drift: '+name)
    if m.get('models')and hashlib.sha256((contract.ROOT/'xnu-S2I9100/port-tests'/m['models']).read_bytes()).hexdigest()!=m['models_sha256']:
        raise ValueError('Clock model fixture drift')
    if m.get('native_model')and hashlib.sha256((contract.ROOT/'xnu-S2I9100/port-tests'/m['native_model']).read_bytes()).hexdigest()!=m['native_model_sha256']:
        raise ValueError('Boot model fixture drift')
    if m.get('model_artifact_sha256')and hashlib.sha256((path/'models').read_bytes()).hexdigest()!=m['model_artifact_sha256']:
        raise ValueError('Clock model executable changed')
    if m.get('native_model_artifact_sha256')and hashlib.sha256((contract.ROOT/m['native_model_artifact']).read_bytes()).hexdigest()!=m['native_model_artifact_sha256']:
        raise ValueError('Boot model executable changed')
    for name,expected in m.get('nested_fixtures',{}).items():
        if hashlib.sha256((contract.ROOT/'xnu-S2I9100/port-tests'/name).read_bytes()).hexdigest()!=expected:raise ValueError('Nested model fixture drift')
    return path,m
def main():
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--clock-proof',type=Path,required=True);p.add_argument('--boot-proof',type=Path,required=True)
    p.add_argument('--acquisition-stream',type=Path,required=True);a=p.parse_args()
    cp,cm=proof(a.clock_proof);bp,bm=proof(a.boot_proof)
    wire=(bp/'actual-contract.bin').read_bytes();decoded=contract.decode(wire)
    if hashlib.sha256(wire).hexdigest()!=bm['actual_contract_sha256']:raise ValueError('Actual C contract changed')
    assert decoded['profile']['host']['xxti_hz']==24000000 and decoded['profile']['host']['xusbxti_hz']==24000000
    assert contract.encode(decoded['profile'],True,decoded['pair_manifest_sha256'],decoded['system'],decoded['data'])==wire
    raws={}
    for name,file in (('cid','cid.bin'),('gpt-primary','gpt-primary.bin'),('gpt-backup','gpt-backup.bin'),('pit','pit.bin')):
        raw_table=(bp/file).read_bytes()
        if hashlib.sha256(raw_table).hexdigest()!=bm['model_table_evidence_sha256'][file]:raise ValueError('C-produced current-card table changed')
        raws[name]=raw_table
    raw=(cp/'clock-mpll.bin').read_bytes();assert hashlib.sha256(raw).hexdigest()==cm['record_outputs']['clock-mpll.bin']
    controller=clock.controller(raw,False,'Explicit C model clock registers, no actual device frequency measurement')
    raws['controller']=json.dumps(controller).encode();result=validator.check(decoded['profile'],raws,True,False);assert result['clock_record_verified']
    for key in ('ciu_clock_hz','model_fixture','clock_record_hex','clock_decoder_sha256'):
        bad=json.loads(raws['controller']);bad[key]=bad[key]^1 if type(bad[key])is int else not bad[key]if type(bad[key])is bool else 'f'+bad[key][1:]
        wrong=dict(raws,controller=json.dumps(bad).encode());rejects(lambda:validator.check(decoded['profile'],wrong,True,False))
    old=json.loads(raws['controller']);old['schema']=1;old.pop('clock_record_hex');old.pop('clock_decoder_sha256')
    old['model_fixture']=False;old['clock_and_pins_reviewed']=True
    old['registers']={name:old['registers'][name]for name in ('cmu_ip_gate','cmu_source_gate','source_mux','source_divider','clksel','gpk0_mux','gpk0_pull','gpk0_drive','gpk0_data','gic_enable')}
    rejects(lambda:validator.check(decoded['profile'],dict(raws,controller=json.dumps(old).encode()),False,True))
    legacy=bytearray(wire);struct.pack_into('<I',legacy,4,1);legacy[188:196]=bytes(8)
    struct.pack_into('<I',legacy,252,zlib.crc32(legacy[:252]));rejects(lambda:contract.decode(legacy))
    wrong_roots=json.loads(json.dumps(decoded['profile']));wrong_roots['host']['xxti_hz']=26000000
    rejects(lambda:contract.encode(wrong_roots,False,decoded['pair_manifest_sha256'],decoded['system'],decoded['data'],True))
    output=contract.REPO/'out'/('emmc-clock-profile-check-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'));output.mkdir()
    acquired,im=read.import_stream(a.acquisition_stream,output/'model-acquisition','0102030405060708090a0b0c0d0e0f10',
      'Actual C inventory stream; rawLinux/card/table boundaries are explicitly modeled',0,True)
    inventory,iv=prepare.prepare(acquired,cp/'clock-mpll.bin','Actual C pre-probe registers + current-card model; no device',output/'prepared')
    assert iv['model_fixture']and not iv['clock_and_pins_reviewed']and iv['profile']['host']['ciu_clock_hz']==100000000
    rejects(lambda:prepare.prepare(acquired,cp/'clock-mpll.bin','Model cannot become reviewed',output/'refused-reviewed',True))
    report=dict(result='PASS',hardware_tested=False,device_contacted=False,contract_version=2,clock_and_controller_derived=True,
      clock_record_sha256=hashlib.sha256(raw).hexdigest(),boot_record_sha256=hashlib.sha256(wire).hexdigest(),
      clock_proof_manifest_sha256=hashlib.sha256((cp/'manifest.json').read_bytes()).hexdigest(),boot_proof_manifest_sha256=hashlib.sha256((bp/'manifest.json').read_bytes()).hexdigest(),
      prepared_inventory=str(inventory.relative_to(contract.ROOT)),prepared_manifest_sha256=hashlib.sha256((inventory/'manifest.json').read_bytes()).hexdigest(),
      source_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()for name in
        ('check-emmc-clock-profile.py','emmc-clock-evidence.py','emmc-inventory-evidence.py','emmc-boot-contract.py','prepare-emmc-inventory.py','emmc-read-evidence.py')})
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actual clock/C-Pythonv2record/controller/derivedinventory/provenance/malformed/modelreview refusal; EVIDENCE',output)
if __name__=='__main__':main()
