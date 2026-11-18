#!/usr/bin/env python3
"""Check bounded live GS binding decoding, current nonresidency and bad inputs.

Pure memory model; no serial opener, target writes or test file deletion.
"""
import importlib.util, struct
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('density_bindings',here/'inspect-ui-density.py')
d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
class User:
    def __init__(self,missing=False,bad=False):self.missing=missing;self.bad=bad;self.reads=[]
    def translate(self,address):return address+0x10000000
    def read(self,address,size):
        self.reads.append((address,size))
        if address in (0x3339f094,0x3339f084):
            if self.missing:raise d.b.m.MappingError(f'Unmapped L2 VA {address:08x}')
            if self.bad:return b'\0'*16
            offset=0x063aa640 if address==0x3339f094 else 0x063aa64c
            return bytes.fromhex('04c09fe50cc08fe000f09ce5')+struct.pack('<I',offset)
        if address in (0x397496e0,0x397496dc):return struct.pack('<I',0x34c34f81)
        if address==0x34c34f80 and size==32:return b'\0'*32
        raise AssertionError((address,size))
r=d.read_gs_bindings(User(),0)
assert r['scale']['slot']=='0x397496e0' and r['points']['slot']=='0x397496dc'
assert r['scale']['target']=='0x34c34f81' and r['scale']['available']
r=d.read_gs_bindings(User(missing=True),0)
assert all(not x['available'] for x in r.values())
assert all('does not prove' in x['limit'] for x in r.values())
try:d.read_gs_bindings(User(bad=True),0)
except Exception as error:assert 'stub differs' in str(error)
else:raise AssertionError('Unknown original stub accepted')
print('PASS isolated binding scope, original literal addressing, nonresidency retained and unknown code rejected')
