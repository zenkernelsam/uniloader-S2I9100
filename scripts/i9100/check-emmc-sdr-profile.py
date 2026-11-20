#!/usr/bin/env python3
"""Verify C/Python SDR boot wire and original board evidence without device contact."""
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
c=module('sdr_contract','emmc-boot-contract.py');checker=module('sdr_board','emmc-sdr-evidence.py');clock=module('sdr_clock','emmc-clock-evidence.py')
def refuses(call):
    try:call()
    except (ValueError,RuntimeError):return
    raise AssertionError('Invalid SDR evidence accepted')
def proof(path):
    path=Path(path).resolve()
    if not path.is_relative_to(c.ROOT/'xnu-S2I9100/out'):raise ValueError('Require retained XNU model')
    m=json.loads((path/'manifest.json').read_text());platform=c.ROOT/'xnu-S2I9100/iokit/Drivers/KernelBuiltIn/ARM/AppleARMPlatform'
    if m.get('result')!='PASS'or m.get('hardware_tested')is not False:raise ValueError('Successful actual offline proof required')
    for name,expected in m.get('sources',{}).items():
        if hashlib.sha256((platform/name).read_bytes()).hexdigest()!=expected:raise ValueError('Current model source drift')
    for name,expected in m.get('nested_fixtures',{}).items():
        if hashlib.sha256((c.ROOT/'xnu-S2I9100/port-tests'/name).read_bytes()).hexdigest()!=expected:raise ValueError('Model fixture drift')
    if m.get('native_model')and hashlib.sha256((c.ROOT/'xnu-S2I9100/port-tests'/m['native_model']).read_bytes()).hexdigest()!=m['native_model_sha256']:
        raise ValueError('Native model drift')
    return path,m
def main():
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--boot-proof',type=Path,required=True);p.add_argument('--clock-proof',type=Path,required=True);a=p.parse_args()
    boot,bm=proof(a.boot_proof);cp,cm=proof(a.clock_proof)
    raw=(boot/'actual-contract-sdr.bin').read_bytes()
    if not bm.get('sdr_boot_path')or hashlib.sha256(raw).hexdigest()!=bm['actual_sdr_contract_sha256']:raise ValueError('Actual SDR C wire required')
    decoded=c.decode(raw);t=decoded['transport'];assert struct.unpack_from('<I',raw,4)[0]==3
    assert c.encode(decoded['profile'],True,decoded['pair_manifest_sha256'],decoded['system'],decoded['data'],transport=t)==raw
    model=c.encode(decoded['profile'],False,decoded['pair_manifest_sha256'],decoded['system'],decoded['data'],True,t)
    assert c.decode(model)['flags']==2
    for offset in (196,200,204,208,212,216,220,224,228,232,236):
        wrong=bytearray(raw);wrong[offset]^=0x40;struct.pack_into('<I',wrong,252,zlib.crc32(wrong[:252]));refuses(lambda:c.decode(wrong))
    output=c.REPO/'out'/('emmc-sdr-profile-check-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'));output.mkdir()
    voltage=output/'modeled-voltage.txt';voltage.write_text('Explicit model fixture 3300mV; no measurement or device contact\n')
    clockraw=(cp/'clock-mpll.bin').read_bytes()
    if hashlib.sha256(clockraw).hexdigest()!=cm['record_outputs']['clock-mpll.bin']:raise ValueError('Clock fixture record changed')
    controller=clock.controller(clockraw,False,'Original C clock fixture, model only')
    vendor=c.ROOT/'research/vendor-linux-u1-a0346556/android_kernel_samsung_smdk4210-a0346556698e62405a04b010c4f4197bdc9fec06'
    wanted=('arch/arm/mach-exynos/mach-u1.c','arch/arm/mach-exynos/setup-mshci-gpio.c','drivers/mmc/host/mshci.c','include/linux/mmc/mmc.h')
    board=dict(schema=1,kind='GT-I9100-SDR',model_fixture=True,board_reviewed=False,cid=decoded['profile']['card']['cid'],**t,
     clock_record_sha256=hashlib.sha256(clockraw).hexdigest(),source_note='Actual C SDR/clock model, not hardware',
     voltage_observation=dict(millivolts=3300,method='Explicit model fixture',path=str(voltage.relative_to(c.ROOT)),sha256=hashlib.sha256(voltage.read_bytes()).hexdigest()),
     board_sources={n:hashlib.sha256((vendor/n).read_bytes()).hexdigest()for n in wanted})
    assert checker.check(board,t,decoded['profile']['card'],controller)['result']=='PASS'
    refuses(lambda:checker.check(board,t,decoded['profile']['card'],controller,True))
    wrong=json.loads(json.dumps(board));wrong['model_fixture']=False;wrong['board_reviewed']=True
    refuses(lambda:checker.check(wrong,t,decoded['profile']['card'],controller,True))
    for key in ('cid','width','high_speed','target_hz','vcc_mv','clock_record_sha256'):
        wrong=json.loads(json.dumps(board))
        if key=='cid':wrong[key][0]^=1
        elif type(wrong[key])is int:wrong[key]^=1
        else:wrong[key]='f'+wrong[key][1:]
        refuses(lambda:checker.check(wrong,t,decoded['profile']['card'],controller))
    wrong=json.loads(json.dumps(board));wrong['voltage_observation']['sha256']='0'*64;refuses(lambda:checker.check(wrong,t,decoded['profile']['card'],controller))
    wrong=json.loads(json.dumps(board));wrong['voltage_observation']['millivolts']=2800;refuses(lambda:checker.check(wrong,t,decoded['profile']['card'],controller))
    wrong=json.loads(json.dumps(board));wrong['board_sources'][wanted[0]]='0'*64;refuses(lambda:checker.check(wrong,t,decoded['profile']['card'],controller))
    folder=output/'model-profile';folder.mkdir();(folder/'emmc-boot.bin').write_bytes(model)
    manifest=dict(schema=1,kind='i9100-emmc-boot-contract',result='PASS',device_contacted=False,record=c.decode(model),record_sha256=hashlib.sha256(model).hexdigest(),contract_tool_sha256=hashlib.sha256(Path(__file__).with_name('emmc-boot-contract.py').read_bytes()).hexdigest())
    (folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');assert c.read_prepared(folder)[0]==model
    refuses(lambda:c.read_prepared(folder,True))
    report=dict(result='PASS',device_contacted=False,hardware_tested=False,wire_version=3,model_fixture=True,
      boot_proof=str(boot.relative_to(c.ROOT)),boot_manifest_sha256=hashlib.sha256((boot/'manifest.json').read_bytes()).hexdigest(),
      clock_record_sha256=hashlib.sha256(clockraw).hexdigest(),sdr_record_sha256=hashlib.sha256(raw).hexdigest(),
      sources={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest()for n in ('check-emmc-sdr-profile.py','emmc-boot-contract.py','emmc-sdr-evidence.py','prepare-emmc-boot.py')},
      limitations='C/Python wire, exact prior evidence bytes, voltage/source integrity and model-review refusal only; no device, VCC measurement or deployment')
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actualv3SDR C/Python/currentABI/modelreview/11badwire/9badevidence; EVIDENCE',output)
if __name__=='__main__':main()
