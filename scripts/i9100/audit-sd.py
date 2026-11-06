#!/usr/bin/env python3
"""Read-only FAT32/HFS geometry audit of the prepared SD image."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('image',type=Path)
p.add_argument('--rootfs',type=Path)
p.add_argument('--extract-rootfs',type=Path)
p.add_argument('--hash-rootfs',action='store_true')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()

def hfs(header):
    return {'signature':header[:2].decode('ascii','replace'),
        'version':struct.unpack_from('>H',header,2)[0],
        'attributes':hex(struct.unpack_from('>I',header,4)[0]),
        'block_size':struct.unpack_from('>I',header,40)[0],
        'total_blocks':struct.unpack_from('>I',header,44)[0],
        'free_blocks':struct.unpack_from('>I',header,48)[0]}

with a.image.open('rb') as f:
    def read(offset,size):
        f.seek(offset); d=f.read(size)
        if len(d)!=size: raise ValueError('Short image read')
        return d
    mbr=read(0,512)
    assert mbr[510:]==b'\x55\xaa'
    part,sectors=struct.unpack_from('<II',mbr,454)
    boot=read(part*512,512)
    bps=struct.unpack_from('<H',boot,11)[0]
    spc=boot[13]; reserved=struct.unpack_from('<H',boot,14)[0]; nf=boot[16]
    fat_sectors=struct.unpack_from('<I',boot,36)[0]
    root=struct.unpack_from('<I',boot,44)[0]
    assert bps==512 and spc and not (spc&(spc-1))
    hidden=struct.unpack_from('<I',boot,28)[0]
    assert hidden==part, 'FAT hidden-sector count must match the MBR partition'
    fat=read((part+reserved)*512,fat_sectors*512)
    data_lba=part+reserved+nf*fat_sectors
    def offset(c): return (data_lba+(c-2)*spc)*512
    def chain(c):
        seen=set()
        while 2<=c<0xffffff8:
            assert c not in seen and c*4+4<=len(fat)
            seen.add(c); yield c
            c=struct.unpack_from('<I',fat,c*4)[0]&0xfffffff
        assert c>=0xffffff8
    def directory(c):
        out={}
        for cluster in chain(c):
            d=read(offset(cluster),spc*512)
            for n in range(0,len(d),32):
                ent=d[n:n+32]
                if ent[0]==0: return out
                if ent[0]==0xe5 or ent[11]==0x0f or ent[11]&8: continue
                name=ent[:11].decode('ascii','replace')
                head=(struct.unpack_from('<H',ent,20)[0]<<16)|struct.unpack_from('<H',ent,26)[0]
                out[name]={'cluster':head,'bytes':struct.unpack_from('<I',ent,28)[0]}
        return out
    entries=directory(root)
    ios=directory(entries['IOS7       ']['cluster'])
    rf=ios['ROOTFS  HFS']; clusters=list(chain(rf['cluster']))
    assert len(clusters)*spc*512>=rf['bytes']
    extents=1+sum(b!=aa+1 for aa,b in zip(clusters,clusters[1:]))
    hv=hfs(read(offset(clusters[0])+1024,512))
    assert hv['block_size']*hv['total_blocks']==rf['bytes']
    result={'image':str(a.image),'image_bytes':a.image.stat().st_size,
        'partition_lba':part,'partition_sectors':sectors,'hidden_sectors':hidden,'data_lba':data_lba,
        'cluster_sectors':spc,'root_entries':entries,
        'rootfs':dict(rf,extents=extents,volume=hv)}
    if a.hash_rootfs:
        digest=hashlib.sha256();remaining=rf['bytes'];ranges=[]
        for c in clusters:
            if ranges and c==ranges[-1][0]+ranges[-1][1]:ranges[-1][1]+=1
            else:ranges.append([c,1])
        for first,count in ranges:
            size=min(remaining,count*spc*512);cursor=offset(first)
            while size:
                take=min(size,4*1024*1024);digest.update(read(cursor,take))
                size-=take;remaining-=take;cursor+=take
        assert remaining==0
        result['rootfs']['sha256']=digest.hexdigest()
    if a.extract_rootfs:
        ranges=[]
        for c in clusters:
            if ranges and c==ranges[-1][0]+ranges[-1][1]:
                ranges[-1][1]+=1
            else: ranges.append([c,1])
        remaining=rf['bytes']
        with a.extract_rootfs.open('xb') as dst:
            for first,count in ranges:
                size=min(remaining,count*spc*512)
                cursor=offset(first)
                while size:
                    chunk=min(size,4*1024*1024)
                    dst.write(read(cursor,chunk)); cursor+=chunk
                    size-=chunk; remaining-=chunk
        assert remaining==0
        result['extracted_rootfs']=str(a.extract_rootfs)
if a.rootfs:
    with a.rootfs.open('rb') as f:
        f.seek(1024); result['standalone_rootfs']=dict(hfs(f.read(512)),bytes=a.rootfs.stat().st_size)
    if a.hash_rootfs:
        digest=hashlib.sha256()
        with a.rootfs.open('rb') as f:
            for chunk in iter(lambda:f.read(4*1024*1024),b''):digest.update(chunk)
        result['standalone_rootfs']['sha256']=digest.hexdigest()
        assert result['rootfs']['sha256']==digest.hexdigest(), 'FAT payload differs from checked HFS image'
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
