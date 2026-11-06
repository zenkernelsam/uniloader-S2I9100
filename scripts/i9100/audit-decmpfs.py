#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import struct
p=argparse.ArgumentParser();p.add_argument('image',type=Path);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
with a.image.open('rb') as f:
    f.seek(1024);vh=f.read(512);bs=struct.unpack_from('>I',vh,40)[0]
    attr=bytearray()
    for i in range(8):
        start,count=struct.unpack_from('>II',vh,352+16+i*8)
        f.seek(start*bs);attr+=f.read(count*bs)
ns=struct.unpack_from('>H',attr,32)[0];leaf=struct.unpack_from('>I',attr,24)[0]
seen=set();types={};stored=[]
while leaf:
    assert leaf not in seen;seen.add(leaf)
    node=attr[leaf*ns:(leaf+1)*ns];assert node[8]==255
    count=struct.unpack_from('>H',node,10)[0]
    for i in range(count):
        off=struct.unpack_from('>H',node,ns-2*(i+1))[0]
        kl=struct.unpack_from('>H',node,off)[0];fid=struct.unpack_from('>I',node,off+4)[0]
        nl=struct.unpack_from('>H',node,off+12)[0]
        if node[off+14:off+14+2*nl].decode('utf-16be')!='com.apple.decmpfs':continue
        rec=off+kl+2
        if struct.unpack_from('>I',node,rec)[0]!=0x10:continue
        size=struct.unpack_from('>I',node,rec+12)[0];val=node[rec+16:rec+16+size]
        magic,ctype,usize=struct.unpack_from('<4sIQ',val)
        assert magic==b'fpmc';types[ctype]=types.get(ctype,0)+1
        if ctype==3 and len(val)>16 and val[16]==0xff:
            assert len(val)-17==usize
            stored.append({'file_id':fid,'bytes':usize})
            if usize and not (a.output/'stored-type3.bin').exists():
                (a.output/'stored-type3.bin').write_bytes(val[16:])
    leaf=struct.unpack_from('>I',node)[0]
report={'compression_types':types,'stored_type3_count':len(stored),'examples':stored[:12]}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
