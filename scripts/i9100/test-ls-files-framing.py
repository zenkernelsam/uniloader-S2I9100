#!/usr/bin/env python3
"""Parse original LS file observer output without opening the device."""
import argparse,contextlib,io,importlib.util,struct
from pathlib import Path
from datetime import datetime
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('obs',Path(__file__).with_name('inspect-mdns.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('ls-files-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
 values={'_i9100_ls_file_diag':0x1000}
 def __getitem__(self,k):return self.values[k]
class Memory:
 def __init__(self,d):self.data=d
 def read(self,address,size):assert address==0x1000 and size==len(self.data);return self.data
def decode(label,data):
 folder=out/label;folder.mkdir()
 with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),Symbols(),folder)['ls_files']
data=(a.fixture/'files.bin').read_bytes();r=decode('production',data);rows=r['rows']
assert r['sequence']==5 and len(rows)==5 and rows[1]['error']==28
assert rows[1]['path'].endswith('/_temp') and rows[2]['path2'].endswith('/AppStore')
assert rows[4]['error']==13 and rows[3]['code']==6
for word,value in ((1+14,2),(1+15,2)):
 b=bytearray(data);struct.pack_into('<I',b,word*4,value)
 try:decode('bad-'+str(word),b);raise AssertionError('unknown layout accepted')
 except ValueError:pass
print('PASS production LS file fixture/errors and malformed schema; transport modeled')
print('EVIDENCE',out)
