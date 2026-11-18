#!/usr/bin/env python3
"""Exercise optional setup diagnostics against a real retained charger fixture.

No device access. Keep the evidence directory; never delete test artifacts.
"""
import argparse, importlib.util, json, struct
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('charge_capture',here/'inspect-charge-health.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
repo=here.parents[1];out=a.output.resolve();fixture=a.fixture.resolve()
assert fixture.is_relative_to(repo/'out') and out.is_relative_to(repo/'out') and not out.exists()
raw=fixture.read_bytes();version,count,stride,capacity=struct.unpack_from('<4I',raw)
assert version==2 and stride==40 and capacity==16
out.mkdir(parents=True)
class Symbols:
    values={'_i9100_charge_diag':0x1000,'_i9100_setup_dev_finish_diag':0x3000}
    def __getitem__(self,name):return self.values[name]
class Kernel:
    def __init__(self,setup_version):self.calls=[];self.setup_version=setup_version;self.header_reads=0
    def read(self,address,size):
        self.calls.append((address,size))
        if address==0x1000:
            if size==16:
                self.header_reads+=1
                return struct.pack('<4I',version,count+(self.header_reads>1),stride,capacity)
            assert size==len(raw);return raw
        if address==0x3000 and size==48:
            return struct.pack('<12I',self.setup_version,2,88,0x19000,88,0,0,0,0,0,0x1b76c,0x1af84)
        if address==0x3030 and size==16 and self.setup_version==2:
            return struct.pack('<4I',0x98000,132,0x79068,0x78430)
        raise AssertionError((address,size))
for setup_version in (1,2):
    target=out/f'setup-v{setup_version}';target.mkdir();kernel=Kernel(setup_version)
    result=m.capture(kernel,Symbols(),target)
    assert kernel.calls[-1]==(0x1000,16),'Optional diagnostics replaced the original charger address'
    assert result['version']==version and result['producer_count_after']==count+1
    assert result['producer_advanced_after_snapshot'] and not result['net_charging_verified']
    assert ((0x3030,16) in kernel.calls)==(setup_version==2)
    assert result['setup_development_finish']['version']==setup_version
    if setup_version==2:assert result['setup_development_finish']['code_bytes']==132
(out/'result.json').write_text(json.dumps(dict(result='PASS',cases=2,fixture=str(fixture),
    evidence='Real charger snapshot, separate optional addresses, v1/v2 decoding and later producer advancement'),indent=2)+'\n')
print('PASS real charger fixture; v1/v2 setup address isolation; final charger header and producer advancement')
