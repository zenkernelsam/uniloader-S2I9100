#!/usr/bin/env python3
"""Parse production first-media peer registers/handlers and reject bad sizes."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--owner-fixture',type=Path);p.add_argument('--dispatch-fixture',type=Path);a=p.parse_args()
s=importlib.util.spec_from_file_location('peers_parser',Path(__file__).with_name('inspect-mdns.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('media-threads-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_media_threads':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):assert address==0x1000 and size==len(self.data);return self.data
def decode(label,data,symbols=None,key='media_first_threads'):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),symbols or Symbols(),target)[key]
raw=a.fixture.read_bytes();r=decode('production',raw);assert r['count']==3 and r['pid']==33 and r['callback_stage']==2
first=r['rows'][0];assert first['tid_low']==578 and first['registers'][12]==301 and first['mutex_words'][8]==578
assert first['frame_rows'][0]['lr']==0x310fdd65 and first['handler_args'][0]==0x5500 and first['handler_args_observed']==1
assert r['version']==2 and first['instruction_error']==0 and first['instruction_hex']=='0000a0e11eff2fe14433221188776655'
legacy=bytearray(raw);struct.pack_into('<I',legacy,4,1)
old=decode('legacy',bytes(legacy));assert old['rows'][0]['instruction_error'] is None and old['rows'][0]['instruction_hex'] is None
for label,word,value in [('version',1,3),('count',4,17),('sequence',16,2),('frames',16+23,7)]:
    changed=bytearray(raw);struct.pack_into('<I',changed,word*4,value)
    try:decode(label,bytes(changed));raise AssertionError('Unknown peer layout accepted')
    except ValueError:pass
if a.owner_fixture:
    owner_symbols=Symbols();owner_symbols.values={'_i9100_audio_owner_diag':0x1000}
    owner_raw=a.owner_fixture.read_bytes();owners=decode('owners',owner_raw,owner_symbols,'audio_owners')
    assert owners['count']==2 and owners['rows'][0]['sequence']==1 and owners['rows'][0]['owner_low']==579
    assert owners['rows'][0]['registers'][0]==0x12040 and owners['rows'][0]['frame_rows'][0]['lr']==0x310fdd65
    assert owners['rows'][1]['error']==2 and owners['rows'][1]['frame_count']==0
    for label,word,value in [('owner-version',1,2),('owner-cap',2,9),('owner-row-version',4+13,2),('owner-frames',4+10,7)]:
        changed=bytearray(owner_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),owner_symbols,'audio_owners');raise AssertionError('Unknown owner layout accepted')
        except ValueError:pass
if a.dispatch_fixture:
    dispatch_symbols=Symbols();dispatch_symbols.values={'_i9100_media_dispatch_diag':0x1000}
    dispatch_raw=a.dispatch_fixture.read_bytes();q=decode('dispatch',dispatch_raw,dispatch_symbols,'media_dispatch')
    assert q['pid']==33 and q['slot']==0x39594dd0 and q['queue']==0x25000 and q['bytes']==256
    assert b'com.apple.coremedia.fixture' in bytes.fromhex(q['raw_hex'])
    for label,word,value in [('dispatch-version',1,2),('dispatch-bytes',9,257),('dispatch-error',8,14)]:
        changed=bytearray(dispatch_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),dispatch_symbols,'media_dispatch');raise AssertionError('Unknown dispatch layout accepted')
        except ValueError:pass
print('PASS production peer identities, saved registers/handler args/owner/frame layout; unknown schemas rejected')
print('EVIDENCE',out)
