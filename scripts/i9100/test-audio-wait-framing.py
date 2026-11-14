#!/usr/bin/env python3
"""Parse actual production mutex-wait fixture and reject unknown layouts."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);args=p.parse_args()
s=importlib.util.spec_from_file_location('wait_parser',Path(__file__).with_name('inspect-mdns.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('audio-wait-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_audio_wait_diag':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and size==len(self.data);return self.data
def decode(label,data):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),Symbols(),target)['audio_waits']
raw=args.fixture.read_bytes();r=decode('production',raw);first=r['rows'][0]
assert r['count']==8 and first['pid']==33 and first['runtime_words'][1]==2
assert first['mutex_words'][0]==0x4d555458 and first['mutex_words'][8]==112
assert first['frame_rows'][0]['lr']==0x3169e85d and first['frame_rows'][1]['lr']==0x30affdd3
for label,word,value in [('capacity',0,9),('version',14,2),('frames',11,9),('code',5,305)]:
    changed=bytearray(raw);struct.pack_into('<I',changed,word*4,value)
    try:decode(label,bytes(changed));raise AssertionError('Unknown audio wait accepted: '+label)
    except ValueError:pass
print('PASS original production wait runtime, mutex owner and frames; corrupt layouts rejected')
print('EVIDENCE',out)
