#!/usr/bin/env python3
"""Parse the production fault fixture without opening a serial port."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture',type=Path,required=True)
a=p.parse_args()
spec=importlib.util.spec_from_file_location('observations',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('quartz-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_quartz_fault_payload':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and len(self.data)==size;return self.data
def decode(label,data):
    directory=out/label;directory.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):
        return m.capture_ui_observations(Memory(data),Symbols(),directory)['quartz_fault']
data=(a.fixture/'quartz.bin').read_bytes()
r=decode('production-fixture',data)
assert r['pid']==57 and r['object']==0x374fa0 and r['page']==0x374000
assert r['magic']==0xdeafbe03 and r['vtable']==0 and r['nonzero_bytes']==4092
assert r['object_prefix_hex'].startswith('0000000041414141')
for index,value in ((8,4097),(10,2),(14,4093)):
    bad=bytearray(data);struct.pack_into('<I',bad,index*4,value)
    try:decode('bad-'+str(index),bad);raise AssertionError('bad schema accepted')
    except ValueError:pass
print('PASS production QuartzCore page fixture and malformed layouts; memory transport modeled')
print('EVIDENCE',out)
