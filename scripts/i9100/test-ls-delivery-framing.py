#!/usr/bin/env python3
"""Decode the production message-delivery fixture without device access."""
import argparse,contextlib,importlib.util,io,struct
from pathlib import Path
from datetime import datetime
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('delivery_obs',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('ls-delivery-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_ls_delivery_diag':0x1000,'_i9100_ls_reply_alloc_diag':0x2000,'_i9100_ls_delivery_stride':0x3000}
    def __getitem__(self,k):return self.values[k]
class Memory:
    def __init__(self,d):self.data={0x1000:d,0x2000:(a.fixture/'allocate.bin').read_bytes(),0x3000:struct.pack('<I',848)}
    def u32(self,address):return struct.unpack('<I',self.data[address])[0]
    def read(self,address,size):assert len(self.data[address])==size;return self.data[address]
def decode(label,data):
    folder=out/label;folder.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),Symbols(),folder)
data=(a.fixture/'delivery.bin').read_bytes();r=decode('production',data)
rows=r['ls_delivery']['rows'];assert len(rows)==5
assert rows[0]['mismatch']==0 and rows[0]['source_sha']==rows[0]['user_sha']
assert rows[1]['mismatch']==1 and rows[1]['source_sha']!=rows[1]['user_sha']
assert rows[2]['read_error']==14 and rows[3]['result']==0x1000400f
assert rows[4]['id']==14014 and rows[4]['bytes']==1664 and not rows[4]['mismatch']
assert r['ls_reply_alloc']['rows'][0]['result']==3 and r['ls_reply_alloc']['rows'][1]['result']==0
for word,value in ((0,9),(1+6,1665),(1+10,3)):
    bad=bytearray(data);struct.pack_into('<I',bad,word*4,value)
    try:decode('bad-'+str(word),bad);raise AssertionError('unknown layout accepted')
    except ValueError:pass
print('PASS actual production delivery/allocator fixtures and invalid limits; transport modeled')
print('EVIDENCE',out)
