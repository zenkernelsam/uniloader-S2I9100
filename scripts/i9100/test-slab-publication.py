#!/usr/bin/env python3
"""Decode bytes emitted by the production C fixture; reject malformed framing."""
import argparse
import importlib.util
from pathlib import Path
import struct

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('mdns',here/'inspect-mdns.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--evidence',type=Path,required=True)
a=p.parse_args()
diag=(a.evidence/'code.bin.diag').read_bytes()
rows=(a.evidence/'code.bin.rows').read_bytes()
failure=(a.evidence/'code.bin.failure').read_bytes()
r=m.decode_slab_publications(diag,rows,failure)
assert r['diagnostic']['state']==2 and r['diagnostic']['site']==0x32ce2460
assert r['count']==1 and len(r['rows'])==1 and r['rows'][0]['magic_matches']
assert r['rows'][0]['candidate']==0x20000 and r['rows'][0]['expected']==0xdeafbe03
assert r['rows'][0]['mapping_stable_during_copy'] and not r['failure']['mapping_stable_during_copy']
for kind,offset,value in (('diag',0,2),('rows',0,65),('rows',4,2),('rows',16,2),('rows',16+13*4,0x1111),('failure',0,2)):
    bad=bytearray(dict(diag=diag,rows=rows,failure=failure)[kind]);struct.pack_into('<I',bad,offset,value)
    blobs=dict(diag=diag,data=rows,failure=failure);blobs['data' if kind=='rows' else kind]=bytes(bad)
    try:m.decode_slab_publications(**blobs)
    except ValueError:pass
    else:raise AssertionError('Malformed framing accepted: '+kind)
print('PASS production C publication bytes, aligned site/identity, mapping snapshot interpretation and malformed framing refusal')
