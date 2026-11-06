#!/usr/bin/env python3
"""Create a matched i9100 SD image; preserve the original SD and HFS sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zlib


def main():
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
            sys.executable,__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
    repo=Path(__file__).resolve().parents[2]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-rootfs',type=Path,required=True)
    p.add_argument('--source-sd',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); out=a.output.resolve()
    if not out.is_relative_to(repo/'out') or out.exists(): p.error('Use a new loader out directory')
    out.mkdir(parents=True)
    root=out/'ROOTFS.HFS'
    # The supplied extraction may be padded beyond its declared HFS
    # geometry. Copy only the volume, then grow it coherently below.
    with a.source_rootfs.open('rb') as src:
        src.seek(1024);header=src.read(512)
        block_size,total=struct.unpack_from('>II',header,40)
        source_bytes=block_size*total
        assert source_bytes<=a.source_rootfs.stat().st_size
        src.seek(0)
        with root.open('xb') as dst:
            remaining=source_bytes
            while remaining:
                data=src.read(min(remaining,4*1024*1024))
                assert data;dst.write(data);remaining-=len(data)
    report={}
    with root.open('r+b') as f:
        def read(off,n):
            f.seek(off); data=f.read(n)
            if len(data)!=n: raise ValueError('Short HFS read')
            return data
        f.seek(1024); vh=bytearray(f.read(512))
        assert vh[:2] in (b'H+',b'HX')
        bs,old_total,old_free=struct.unpack_from('>III',vh,40)
        assert bs==8192 and old_total*bs==root.stat().st_size
        # A checked, immutable base plus volatile kernel COW does not
        # need a persistent journal. Keep the journal files themselves.
        attrs=struct.unpack_from('>I',vh,4)[0]
        assert attrs&0x100, 'Source HFS volume must be cleanly unmounted'
        struct.pack_into('>I',vh,4,attrs&~0x2000)
        struct.pack_into('>I',vh,12,0)
        def fork_pos(field,logical):
            for i in range(8):
                start,count=struct.unpack_from('>II',vh,field+16+i*8)
                if logical<count*bs: return start*bs+logical,count*bs-logical
                logical-=count*bs
            raise ValueError('Fork overflow extents are not supported')
        def fork_read(field,logical,size):
            result=bytearray()
            while size:
                off,remain=fork_pos(field,logical); take=min(size,remain)
                result+=read(off,take);size-=take;logical+=take
            return result
        def fork_write(field,logical,data):
            while data:
                off,remain=fork_pos(field,logical);take=min(len(data),remain)
                f.seek(off);f.write(data[:take]);data=data[take:];logical+=take
        # Locate the live inline compression record in the attribute B-tree.
        head=fork_read(352,0,512)
        node_size=struct.unpack_from('>H',head,32)[0]
        leaf=struct.unpack_from('>I',head,24)[0]
        seen=set(); matches=[]
        while leaf:
            assert leaf not in seen;seen.add(leaf)
            node=fork_read(352,leaf*node_size,node_size)
            assert node[8]==255
            records=struct.unpack_from('>H',node,10)[0]
            for i in range(records):
                off=struct.unpack_from('>H',node,node_size-2*(i+1))[0]
                end=struct.unpack_from('>H',node,node_size-2*(i+2))[0]
                keylen=struct.unpack_from('>H',node,off)[0]
                fileid=struct.unpack_from('>I',node,off+4)[0]
                length=struct.unpack_from('>H',node,off+12)[0]
                name=node[off+14:off+14+length*2].decode('utf-16be')
                if fileid==47556 and name=='com.apple.decmpfs':
                    record=off+keylen+2
                    assert struct.unpack_from('>I',node,record)[0]==0x10
                    size=struct.unpack_from('>I',node,record+12)[0]
                    value=record+16
                    assert value+size<=end
                    magic,ctype,usize=struct.unpack_from('<4sIQ',node,value)
                    assert magic==b'fpmc' and ctype==3
                    content=zlib.decompress(node[value+16:value+size])
                    assert content.startswith(b'/dev/disk0s1 / hfs ro 0 1\n') and len(content)==usize
                    replacement=b'/dev/disk1 / hfs rw 0 1\n'
                    replacement+=b'#'+b' '*(usize-len(replacement)-2)+b'\n'
                    compressed=zlib.compress(replacement,9)
                    assert len(compressed)<=size-16
                    patch=compressed+b'\0'*(size-16-len(compressed))
                    fork_write(352,leaf*node_size+value+16,patch)
                    assert zlib.decompress(fork_read(352,leaf*node_size+value+16,size-16))==replacement
                    matches.append({'old':content.decode(),'new':replacement.decode(),'file_id':fileid})
            leaf=struct.unpack_from('>I',node,0)[0]
        assert len(matches)==1
        report['fstab']=matches[0]
        # Grow within the already allocated 64KiB allocation bitmap.
        # Move the reserved backup-header block to the new volume end.
        new_total=(1536*1024*1024)//bs
        bitmap_bytes=struct.unpack_from('>Q',vh,112)[0]
        assert old_total<new_total<=bitmap_bytes*8
        bitmap=fork_read(112,0,bitmap_bytes)
        def bit(n,value):
            mask=1<<(7-(n&7))
            if value: bitmap[n//8]|=mask
            else: bitmap[n//8]&=255-mask
        assert bitmap[(old_total-1)//8]&(1<<(7-((old_total-1)&7)))
        report['source_backup_header_valid']=read(old_total*bs-1024,2)==vh[:2]
        for n in range(old_total,new_total): bit(n,0)
        bit(old_total-1,0);bit(new_total-1,1)
        for n in range(new_total,bitmap_bytes*8): bit(n,1)
        fork_write(112,0,bitmap)
        new_free=old_free+new_total-old_total
        struct.pack_into('>II',vh,44,new_total,new_free)
        struct.pack_into('>I',vh,68,struct.unpack_from('>I',vh,68)[0]+1)
        f.truncate(new_total*bs)
        f.seek(1024);f.write(vh)
        f.seek(new_total*bs-1024);f.write(vh)
        report['volume']={'old_bytes':old_total*bs,'new_bytes':new_total*bs,
            'old_free_blocks':old_free,'new_free_blocks':new_free,'block_size':bs}
    aliases=subprocess.run([sys.executable,repo/'scripts/i9100/add-ios6-capabilities.py',root],
        capture_output=True,text=True)
    (out/'capabilities.log').write_text(aliases.stdout+aliases.stderr)
    if aliases.returncode:
        print(aliases.stderr[-2000:],file=sys.stderr)
        raise RuntimeError('Capability file insertion failed')
    report['capabilities']=json.loads(aliases.stdout)
    with root.open('rb') as check:
        check.seek(1024+48)
        report['volume']['new_free_blocks']=struct.unpack('>I',check.read(4))[0]
    result=subprocess.run(['fsck.hfsplus','-n',str(root)],capture_output=True,text=True)
    (out/'hfs-check.log').write_text(result.stdout+result.stderr)
    if result.returncode:
        print((result.stdout+result.stderr)[-2500:],file=sys.stderr)
        raise RuntimeError('HFS validation failed; sources are untouched')
    image=out/'sd-ios6-oneshot.img'
    with a.source_sd.open('rb') as f: mbr=f.read(512)
    assert mbr[510:]==b'\x55\xaa' and struct.unpack_from('<I',mbr,454)[0]==2048
    with image.open('xb') as f: f.truncate(2147483648);f.seek(0);f.write(mbr)
    def run(argv,name):
        r=subprocess.run(list(map(str,argv)),capture_output=True,text=True)
        (out/name).write_text(r.stdout+r.stderr)
        if r.returncode: raise RuntimeError(str(argv)+' failed; see '+name)
    run(['mkfs.fat','--offset=2048','-h','2048','-F','32','-n','I9100IOS6',image],'fat-format.log')
    spec=str(image)+'@@1048576'
    run(['mmd','-i',spec,'::/IOS7'],'fat-directory.log')
    run(['mcopy','-i',spec,root,'::/IOS7/ROOTFS.HFS'],'fat-copy.log')
    marker=out/'ios6';marker.write_text('ios6\n')
    run(['mcopy','-i',spec,marker,'::/ios6'],'fat-marker.log')
    report['image']=str(image)
    (out/'preparation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
