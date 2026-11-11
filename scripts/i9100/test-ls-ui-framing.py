#!/usr/bin/env python3
"""Decode the production budget fixture without accessing the phone."""
import argparse,contextlib,importlib.util,io,struct
from datetime import datetime
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('observations',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('ls-ui-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_ls_ui_diag':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and len(self.data)==size;return self.data
def decode(label,data):
    directory=out/label;directory.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):
        return m.capture_ui_observations(Memory(data),Symbols(),directory)['ls_ui_budget']
data=(a.fixture/'ui.bin').read_bytes();r=decode('actual-production',data)
assert r['sequence']==5 and len(r['rows'])==5
assert r['rows'][2]['phase']==3 and r['rows'][2]['result']==0x10004003
assert r['rows'][4]['phase']==2 and r['rows'][4]['result']==0x10000003
for word,value in ((3,4),(6,4999),(7,14112)):
    bad=bytearray(data);struct.pack_into('<I',bad,(1+word)*4,value)
    try:decode('bad-'+str(word),bad);raise AssertionError('unknown record accepted')
    except ValueError:pass
print('PASS actual production receive/error record fixture and malformed schema; transport modeled')
print('EVIDENCE',out)
