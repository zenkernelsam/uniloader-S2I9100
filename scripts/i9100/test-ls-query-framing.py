#!/usr/bin/env python3
"""Parse production query evidence, including original corrupted bytes/errors.

No phone access; the memory transport is modeled with actual C fixture data.
"""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture',type=Path,required=True)
a=p.parse_args()
s=importlib.util.spec_from_file_location('query_observations',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('ls-query-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_ls_query_diag':0x1000,'_i9100_ls_query_alloc_diag':0x2000,'_i9100_ls_query_alloc_failure_diag':0x3000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,query,alloc,failures):self.data={0x1000:query,0x2000:alloc,0x3000:failures}
    def read(self,address,size):assert size==len(self.data[address]);return self.data[address]
data=[(a.fixture/file).read_bytes() for file in ('query.bin','alloc.bin','failures.bin')]
def decode(label,values):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):
        return m.capture_ui_observations(Memory(*values),Symbols(),target)
r=decode('production',data)
rows=r['ls_query']['rows']
assert r['ls_query']['sequence']==8 and [row['sequence'] for row in rows]==list(range(1,9))
assert rows[0]['completion_seen']==1 and rows[0]['completion_result']==0x1000000c
assert rows[2]['stage']==6 and rows[2]['user_bytes_observed'] and rows[2]['header_id']==14012
assert rows[4]['stage']==6 and rows[4]['user_bytes_observed'] and rows[4]['id']==14012 and rows[4]['header_id']==0xdeadbeef
assert rows[6]['result']==14 and not rows[6]['user_bytes_observed']
assert rows[7]['completion_result']==0x1000400f
assert r['ls_query_alloc']['sequence']==81 and len(r['ls_query_alloc']['rows'])==32
assert len(r['ls_query_alloc_failure']['rows'])==8 and r['ls_query_alloc_failure']['rows'][0]['result']==3
for label,index,word,value in [('query-version',0,1+15,2),('query-stage',0,1+3,7),
                              ('query-size',0,1+6,353),('allocation-size',1,1+5,4096),
                              ('failure-zero',2,1+8,0),('failure-capacity',2,0,9)]:
    bad=list(data);b=bytearray(bad[index]);struct.pack_into('<I',b,word*4,value);bad[index]=bytes(b)
    # Allocation slot0 belongs to an old overwritten sequence but is still
    # one of the last32 in the produced81-entry ring.
    try:decode(label,bad);raise AssertionError('Malformed observer accepted: '+label)
    except ValueError:pass
# A stale slot must not appear as current data.
b=bytearray(data[0]);struct.pack_into('<I',b,4,0xffffff00)
stale=decode('stale-query-slot',[bytes(b),data[1],data[2]])
assert len(stale['ls_query']['rows'])==7
print('PASS actual production query/error/mutated-byte fixtures and bounded schema rejection; no phone access')
print('EVIDENCE',out)
