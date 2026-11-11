#!/usr/bin/env python3
"""Decode production-observer fixtures without opening a serial handle."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture',type=Path,required=True)
args=parser.parse_args()
repo=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('observations',Path(__file__).with_name('inspect-mdns.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
out=repo/'out'/('vm-slab-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_backboard_vm_diag':0x1000,'_i9100_ios6_slab_payload':0x2000,
            '_i9100_ios6_slab_vm_diag':0x3000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,vm,payload):self.data={0x1000:vm,0x2000:payload,0x3000:slab_vm}
    def read(self,address,size):
        data=self.data[address];assert len(data)==size;return data
def decode(label,vm,payload):
    directory=out/label;directory.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):
        return module.capture_ui_observations(Memory(vm,payload),Symbols(),directory)
vm=(args.fixture/'vm.bin').read_bytes();payload=(args.fixture/'payload.bin').read_bytes()
slab_vm=(args.fixture/'slab-vm.bin').read_bytes()
result=decode('actual-production-fixture',vm,payload)
assert result['backboard_vm']['owner_pid']==8 and result['backboard_vm']['sealed']==1
assert len(result['backboard_vm']['rows'])==3 and result['backboard_vm']['unpublished']==[3]
first=result['backboard_vm']['rows'][0]
assert first['length_low']==4096 and first['flags']==0x1002 and first['result_low']==0x1a9000
page=result['slab_payload']['rows'][0]
assert page['pid']==8 and page['candidate']==0x1a9000 and page['bytes']==4096
assert page['magic_in_payload']==0 and page['nonzero_bytes']==4032
dedicated=result['slab_vm']
assert dedicated['count']==3 and dedicated['unpublished']==[2]
assert dedicated['rows'][0]['result_low']==0x10b000 and dedicated['rows'][1]['error']==12
for index,replacement in ((0,257),(3,2)):
    bad=bytearray(vm);struct.pack_into('<I',bad,index*4,replacement)
    try:decode('bad-vm-'+str(index),bytes(bad),payload);raise AssertionError('bad VM bounds accepted')
    except ValueError:pass
bad=bytearray(payload);struct.pack_into('<I',bad,(12+1024)*4+7*4,4097)
try:decode('bad-payload-bound',vm,bytes(bad));raise AssertionError('bad payload bounds accepted')
except ValueError:pass
bad=bytearray(slab_vm);struct.pack_into('<I',bad,0,65)
slab_vm=bytes(bad)
try:decode('bad-dedicated-limit',vm,payload);raise AssertionError('bad dedicated bounds accepted')
except ValueError:pass
print('PASS production VM/slab fixtures and malformed limits; memory transport modeled')
print('EVIDENCE',out)
