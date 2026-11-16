#!/usr/bin/env python3
"""Decode the production observer fixture and reject malformed native framing."""
import argparse,importlib.util,struct
from pathlib import Path
here=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('ui_decode',here/'inspect-mdns.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
diag=(a.evidence/'code.bin.diag').read_bytes();rows=(a.evidence/'code.bin.rows').read_bytes()
r=m.decode_ui_execution(diag,rows);modern=r['diagnostic']['version']==2
assert r['diagnostic']['state']==2 and r['sequence']==(90 if modern else 44) and len(r['rows'])==(64 if modern else 32)
assert all(x['phase']==2 and x['actor_bytes']==80 and x['current_installation'] for x in r['rows'])
for kind,at,v in (('diag',0,3),('rows',4,3),('rows',12,64),('rows',(4+11*96+4)*4,10),('rows',(4+11*96+5)*4,0x9999)):
    blob=bytearray(diag if kind=='diag' else rows);struct.pack_into('<I',blob,at,v)
    try:m.decode_ui_execution(bytes(blob) if kind=='diag' else diag,bytes(blob) if kind=='rows' else rows)
    except ValueError:pass
    else:raise AssertionError('Invalid native framing accepted')
if modern:
    bg=bytearray(diag);struct.pack_into('<I',bg,26*4,1);struct.pack_into('<I',bg,28*4,1)
    header=struct.unpack_from('<I',bg,4*4)[0];struct.pack_into('<I',bg,29*4,header+0x22b4)
    decoded=m.decode_ui_execution(bytes(bg),rows)['diagnostic']
    assert decoded['background_fit_enabled']==1 and decoded['background_fit_site']==header+0x22b4
    for at,value in ((26*4,0),(28*4,2),(29*4,0x9999)):
        bad=bytearray(bg);struct.pack_into('<I',bad,at,value)
        try:m.decode_ui_execution(bytes(bad),rows)
        except ValueError:pass
        else:raise AssertionError('Invalid background scope accepted')
print('PASS production Setup UI ring bytes, wrap/identity binding and malformed schema/site rejection')
