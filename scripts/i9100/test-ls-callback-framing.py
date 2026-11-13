#!/usr/bin/env python3
"""Decode production callback ring fixtures without USB access."""
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
spec=importlib.util.spec_from_file_location('callback_decoder',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('ls-callback-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_ls_callback_diag':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):
        assert address==0x1000 and size==len(self.data)
        return self.data
data=a.fixture.read_bytes()
def decode(label,data):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):
        return m.capture_ui_observations(Memory(data),Symbols(),target)['ls_callback']
actual=decode('production',data)
assert actual['sequence']==70 and [row['sequence'] for row in actual['rows']]==list(range(7,71))
assert all(row['kind']==1 and row['request_bundle']=='com.apple.Preferences' for row in actual['rows'])
for label,word,value in [('schema',1,2),('stage',2,5),('kind',13,4),('size',11,351)]:
    bad=bytearray(data);struct.pack_into('<I',bad,(1+word)*4,value)
    try:decode(label,bad);raise AssertionError('Malformed layout accepted')
    except ValueError:pass
print('PASS original C ring, schema/size/kind bounds; transport modeled')
print(out)
