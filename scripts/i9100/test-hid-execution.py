#!/usr/bin/env python3
"""Decode actual production HID trace fixtures and retain v1 compatibility."""
import argparse,contextlib,importlib.util,io,struct
from datetime import datetime
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--code',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('hid_parser',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('hid-execution-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_hid_execution_diag':0x1000,'_i9100_hid_execution_rows':0x4000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,diag,rows):self.ranges=((0x1000,diag),(0x4000,rows))
    def read(self,address,size):
        for start,data in self.ranges:
            if start<=address and address+size<=start+len(data):return data[address-start:address-start+size]
        raise ValueError('Unexpected fixture read')
def decode(name,diag,rows):
    target=out/name;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(diag,rows),Symbols(),target)
diag=Path(str(a.code)+'.diag').read_bytes()
rows=Path(str(a.code)+'.initial.rows').read_bytes()
r=decode('production-v2',diag,rows)
probe=r['hid_execution'];records=r['hid_execution_rows']['rows']
assert probe['version']==2 and probe['self_test_count']==1 and probe['create_with_data_count']==1
assert [x['phase'] for x in records]==list(range(1,9))
assert all(x['current_installation'] for x in records)
assert records[0]['arguments'][2]==0x55 and records[0]['pointer']==0x20000 and records[0]['event']['type']==11
assert records[3]['event']['type']==11 and records[4]['event']['type']==11 and records[5]['event']['type']==11
assert records[6]['bytes']==32 and 'event' not in records[6]
assert records[7]['node']=='self_test' and records[7]['bytes']==0
old_diag=bytearray(diag[:96]);struct.pack_into('<I',old_diag,0,1);struct.pack_into('<I',old_diag,19*4,3)
old_rows=bytearray(rows);struct.pack_into('<2I',old_rows,0,3,1);old_rows[(4+3*64)*4:]=b'\0'*(len(old_rows)-(4+3*64)*4)
assert len(decode('production-v1',bytes(old_diag),bytes(old_rows))['hid_execution_rows']['rows'])==3
for name,at,value in [('version',4,3),('phase',(4+4)*4,9),('site',(4+5)*4,0xdead),
                      ('self-data',(4+7*64+14)*4,1),('cfdata-size',(4+6*64+14)*4,31)]:
    bad=bytearray(rows);struct.pack_into('<I',bad,at,value)
    try:decode(name,diag,bytes(bad));raise AssertionError('Corrupt HID evidence accepted')
    except ValueError:pass
bad=bytearray(rows);struct.pack_into('<I',bad,4,1)
try:decode('mixed-version',diag,bytes(bad));raise AssertionError('Mixed version accepted')
except ValueError:pass
print('PASS actual production v2 upstream/self-test framing, five-argument event identity, v1 compatibility and corrupt schema/site refusal')
print('EVIDENCE',out)
