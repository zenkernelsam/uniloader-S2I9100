#!/usr/bin/env python3
"""Decode production Fig RPC fixture and reject corrupt identity/size fields."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);args=p.parse_args()
spec=importlib.util.spec_from_file_location('fig_parser',Path(__file__).with_name('inspect-mdns.py'))
parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('fig-rpc-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_fig_rpc_diag':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and size==len(self.data);return self.data
def decode(label,data):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):
        return parser.capture_ui_observations(Memory(data),Symbols(),target)['fig_rpc']
raw=args.fixture.read_bytes();result=decode('production',raw);rows=result['rows']
assert result['count']==8 and len(rows)==8
assert rows[0]['id']==9393 and rows[0]['header'][5]=='0x24b1'
assert rows[1]['receive_result']==0x10004003 and rows[1]['request_token']==2
assert rows[3]['user_bytes_observed'] and rows[3]['stage']==6
assert rows[5]['stage']==6 and rows[5]['result']==14 and not rows[5]['user_bytes_observed']
assert rows[6]['completion_result']==0x1000400f and rows[7]['role']==2
for label,word,value in [('capacity',0,65),('sequence',1,2),('version',2,2),('stage',3,7),('role',7,0),('id',8,9394),('size',9,129),('captured',10,23),('completion',16,2)]:
    changed=bytearray(raw);struct.pack_into('<I',changed,word*4,value)
    try:decode(label,bytes(changed));raise AssertionError('Malformed Fig history accepted: '+label)
    except ValueError:pass
assert '_i9100_signal_exit' in parser.ABORT_SYMBOLS and '_i9100_springboard_kill_payload' in parser.ABORT_SYMBOLS
print('PASS production Fig RPC bytes/timeout/read-error and corrupt identity/schema rejection; no phone')
print('EVIDENCE',out)
