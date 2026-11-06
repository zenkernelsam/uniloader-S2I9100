#!/usr/bin/env python3
"""Add two ordinary capability plist files to a disposable, grown HFSX copy.
Only inserts that fit existing leaves are allowed; every index separator
stays unchanged. The caller runs fsck before using the result.
"""
import bisect
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys

image=Path(sys.argv[1]).resolve()
assert image.is_relative_to(Path(__file__).resolve().parents[2]/'out')
content=subprocess.check_output(['icat',str(image),'40806'])
assert isinstance(plistlib.loads(content),dict)
with image.open('r+b') as f:
    f.seek(1024);vh=bytearray(f.read(512));bs=struct.unpack_from('>I',vh,40)[0]
    assert vh[:2]==b'HX' and len(content)<=bs
    def pos(field,logical):
        for i in range(8):
            start,count=struct.unpack_from('>II',vh,field+16+i*8)
            if logical<count*bs:return start*bs+logical,count*bs-logical
            logical-=count*bs
        raise ValueError('Fork overflow unsupported')
    def read(field,logical,n):
        result=bytearray()
        while n:
            off,remain=pos(field,logical);take=min(n,remain)
            f.seek(off);data=f.read(take);assert len(data)==take
            result+=data;logical+=take;n-=take
        return result
    def write(field,logical,data):
        while data:
            off,remain=pos(field,logical);take=min(len(data),remain)
            f.seek(off);f.write(data[:take]);logical+=take;data=data[take:]
    header=read(272,0,512)
    ns=struct.unpack_from('>H',header,32)[0]
    first=struct.unpack_from('>I',header,24)[0]
    def key(record):
        parent=struct.unpack_from('>I',record,2)[0]
        length=struct.unpack_from('>H',record,6)[0]
        return parent,record[8:8+2*length].decode('utf-16be')
    def body(record):return struct.unpack_from('>H',record)[0]+2
    nodes=[];seen=set();n=first;template=None;folder=None
    while n:
        assert n not in seen;seen.add(n)
        data=read(272,n*ns,ns);assert data[8]==255
        count=struct.unpack_from('>H',data,10)[0];rows=[]
        for i in range(count):
            start=struct.unpack_from('>H',data,ns-2*(i+1))[0]
            end=struct.unpack_from('>H',data,ns-2*(i+2))[0]
            row=bytearray(data[start:end]);rows.append(row)
            off=body(row);typ=struct.unpack_from('>H',row,off)[0]
            if key(row)==(40800,'N90AP.plist'):
                assert typ==2;template=bytearray(row[off:off+248])
            if typ==1 and struct.unpack_from('>I',row,off+8)[0]==40800:
                folder=row
        nodes.append({'number':n,'header':data[:14],'rows':rows})
        n=struct.unpack_from('>I',data)[0]
    assert template is not None and folder is not None
    def insert(record):
        k=key(record)
        starts=[key(node['rows'][0]) for node in nodes]
        index=bisect.bisect_right(starts,k)-1;assert index>=0
        rows=nodes[index]['rows'];keys=[key(r) for r in rows]
        at=bisect.bisect_left(keys,k)
        assert at>0 and (at==len(rows) or keys[at]!=k)
        rows.insert(at,record)
        assert 14+sum(len(r) for r in rows)+2*(len(rows)+1)<=ns, 'Catalog leaf has no safe insertion room'
    bitmap=read(112,0,struct.unpack_from('>Q',vh,112)[0])
    total=struct.unpack_from('>I',vh,44)[0]
    free=struct.unpack_from('>I',vh,48)[0]
    nextid=struct.unpack_from('>I',vh,64)[0]
    assert nextid>max(key(row)[0] for node in nodes for row in node['rows'])
    blocks=[];names=('default~iphone.plist','samsung,i9100.plist')
    for name in names:
        block=next(b for b in range(1,total-1) if not(bitmap[b//8]&(1<<(7-(b&7)))))
        bitmap[block//8]|=1<<(7-(block&7));blocks.append(block)
        encoded=name.encode('utf-16be')
        record=bytearray(struct.pack('>HIH',6+len(encoded),40800,len(name))+encoded)
        data=bytearray(template)
        struct.pack_into('>H',data,2,2) # thread exists; no inherited xattr/hardlink flags
        struct.pack_into('>I',data,4,0)
        struct.pack_into('>I',data,8,nextid)
        data[41]&=~32 # plain data fork, not UF_COMPRESSED
        struct.pack_into('>I',data,44,0)
        data[88:248]=b'\0'*160
        struct.pack_into('>QIIII',data,88,len(content),0,1,block,1)
        record+=data;insert(record)
        thread=bytearray(struct.pack('>HIH',6,nextid,0))
        thread+=struct.pack('>HHIH',4,0,40800,len(name))+encoded
        insert(thread);nextid+=1
    off=body(folder)
    struct.pack_into('>I',folder,off+4,struct.unpack_from('>I',folder,off+4)[0]+len(names))
    # All capacity/index checks have passed; now write the new records/data.
    for node in nodes:
        rows=node['rows'];data=bytearray(ns);data[:14]=node['header']
        struct.pack_into('>H',data,10,len(rows));cursor=14
        for i,row in enumerate(rows):
            struct.pack_into('>H',data,ns-2*(i+1),cursor)
            data[cursor:cursor+len(row)]=row;cursor+=len(row)
        struct.pack_into('>H',data,ns-2*(len(rows)+1),cursor)
        write(272,node['number']*ns,data)
    headnode=read(272,0,ns)
    struct.pack_into('>I',headnode,20,struct.unpack_from('>I',headnode,20)[0]+2*len(names))
    write(272,0,headnode);write(112,0,bitmap)
    for block in blocks:
        f.seek(block*bs);f.write(content+b'\0'*(bs-len(content)))
    struct.pack_into('>I',vh,32,struct.unpack_from('>I',vh,32)[0]+len(names))
    struct.pack_into('>I',vh,48,free-len(names));struct.pack_into('>I',vh,64,nextid)
    f.seek(1024);f.write(vh);f.seek(total*bs-1024);f.write(vh)
print(json.dumps({'files':names,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}))
