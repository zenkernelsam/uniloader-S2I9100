#!/usr/bin/env python3
"""Decode the production ARM/Thumb restart scalars and reject wrong rewind."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('restart_parser',Path(__file__).with_name('inspect-mdns.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('syscall-restart-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_syscall_restart_diag':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and size==len(self.data);return self.data
def decode(label,data):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),Symbols(),target)['syscall_restarts']
raw=a.fixture.read_bytes();r=decode('production',raw)
assert r['count']==2 and r['rows'][0]['restart_pc']==0x392cd0f8 and r['rows'][1]['width']==2
assert r['rows'][0]['r0']==0x1100 and not r['rows'][0]['cpsr']&(1<<29)
for label,word,value in [('capacity',0,17),('width',6,3),('pc',5,0x392cd0f6),('carry',7,0xa0000010)]:
    changed=bytearray(raw);struct.pack_into('<I',changed,word*4,value)
    try:decode(label,bytes(changed));raise AssertionError('Unknown restart accepted')
    except ValueError:pass
print('PASS original ARM/Thumb restart fields; unknown width/PC/carry rejected')
print('EVIDENCE',out)
