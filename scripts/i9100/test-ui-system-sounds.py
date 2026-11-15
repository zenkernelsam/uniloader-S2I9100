#!/usr/bin/env python3
"""Decode real production unavailable-sound fixture; reject unknown layouts."""
import argparse,contextlib,importlib.util,io,struct
from datetime import datetime
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--diag',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('sound_parser',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('ui-sounds-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_ui_sounds_unavailable_diag':0x1000}
    def __getitem__(self,k):return self.values[k]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and size==128;return self.data
def decode(name,data):
    target=out/name;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),Symbols(),target)['ui_system_sounds']
raw=a.diag.read_bytes();r=decode('production',raw)
assert r['state']==2 and r['declared_error']==-1500 and r['sequence']==9 and all(n==1 for n in r['calls'].values())
for name,word,value in [('version',0,2),('state',1,4),('attempt',6,9),('installed',10,9),('stage',11,5)]:
    bad=bytearray(raw);struct.pack_into('<I',bad,word*4,value)
    try:decode(name,bytes(bad));raise AssertionError('Corrupt schema accepted')
    except ValueError:pass
off=bytearray(128);struct.pack_into('<I',off,0,1);assert decode('off',bytes(off))['state']==0
print('PASS actual production sound-unavailability/error/call framing, disabled mode and unknown schema refusal')
print('EVIDENCE',out)
