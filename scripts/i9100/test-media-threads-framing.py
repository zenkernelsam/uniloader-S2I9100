#!/usr/bin/env python3
"""Parse production first-media peer registers/handlers and reject bad sizes."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('peers_parser',Path(__file__).with_name('inspect-mdns.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('media-threads-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_media_threads':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and size==len(self.data);return self.data
def decode(label,data):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),Symbols(),target)['media_first_threads']
raw=a.fixture.read_bytes();r=decode('production',raw);assert r['count']==3 and r['pid']==33 and r['callback_stage']==2
first=r['rows'][0];assert first['tid_low']==578 and first['registers'][12]==301 and first['mutex_words'][8]==578
assert first['frame_rows'][0]['lr']==0x310fdd65 and first['handler_args'][0]==0x5500 and first['handler_args_observed']==1
for label,word,value in [('version',1,2),('count',4,17),('sequence',16,2),('frames',16+23,7)]:
    changed=bytearray(raw);struct.pack_into('<I',changed,word*4,value)
    try:decode(label,bytes(changed));raise AssertionError('Unknown peer layout accepted')
    except ValueError:pass
print('PASS production peer identities, saved registers/handler args/owner/frame layout; unknown schemas rejected')
print('EVIDENCE',out)
