#!/usr/bin/env python3
from pathlib import Path
import struct
import sys
import zlib
source,target=map(Path,sys.argv[1:3])
with source.open('rb') as f:
    assert f.readline().strip()==b'P6'
    line=f.readline()
    while line.startswith(b'#'):line=f.readline()
    width,height=map(int,line.split());assert f.readline().strip()==b'255'
    data=f.read();assert len(data)==width*height*3
def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
rows=b''.join(b'\0'+data[y*width*3:(y+1)*width*3] for y in range(height))
target.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+
    chunk(b'IDAT',zlib.compress(rows))+chunk(b'IEND',b''))
print('PNG',width,height,str(target))
