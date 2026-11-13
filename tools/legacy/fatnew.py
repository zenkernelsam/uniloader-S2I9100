#!/usr/bin/env python3
# Create a tiny new file in the SD image's FAT32 root dir.
# Usage: fatnew.py <sd.img> <fat-name> <local-file>
import sys, struct

PART_OFF = 0x100000
def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]

img, name, local = sys.argv[1:4]
data = open(local, 'rb').read()

with open(img, 'r+b') as f:
    f.seek(PART_OFF); bpb = f.read(512)
    assert bpb[510:512] == b'\x55\xaa'
    sec_size = u16(bpb, 11); sec_clus = bpb[13]; rsvd = u16(bpb, 14)
    nfats = bpb[16]; fat_secs = u32(bpb, 36); root_clu = u32(bpb, 44)
    fat_off = PART_OFF + rsvd * sec_size
    data_off = PART_OFF + (rsvd + nfats * fat_secs) * sec_size
    clus_size = sec_clus * sec_size
    def coff(c): return data_off + (c - 2) * clus_size

    # FAT scan for a free cluster
    f.seek(fat_off); fatb = bytearray(f.read(fat_secs * sec_size))
    free = next(c for c in range(2, len(fatb)//4) if u32(fatb, c*4) == 0)

    # chain the needed clusters
    need = -(-len(data) // clus_size) or 1
    chain = list(range(free, free + need))
    assert all(u32(fatb, c*4) == 0 for c in chain), 'clusters not free'
    for i, c in enumerate(chain):
        nxt = chain[i+1] if i+1 < len(chain) else 0x0FFFFFF8
        for nf in range(nfats):
            o = fat_off + nf * fat_secs * sec_size + c * 4
            f.seek(o); f.write(struct.pack('<I', nxt))

    # root dir walk -> first free slot (cluster chain from root_clu)
    slot_off = None
    c = root_clu
    while slot_off is None:
        base = coff(c)
        for i in range(clus_size // 32):
            o = base + i * 32
            f.seek(o); e = f.read(32)
            if e[0] in (0x00, 0xE5):
                slot_off = o; break
        else:
            nxt = u32(fatb, c*4)
            if nxt >= 0x0FFFFFF8: sys.exit('root dir full')
            c = nxt
    # build dir entry (8.3 upper-case)
    n8 = name.upper().encode()
    if b'.' in n8: nm, ext = n8.split(b'.', 1)
    else: nm, ext = n8, b''
    ent = bytearray(32)
    ent[0:8] = nm.ljust(8, b' ')[0:8]
    ent[8:11] = ext.ljust(3, b' ')[0:3]
    ent[11] = 0x20  # archive
    struct.pack_into('<H', ent, 26, chain[0])
    struct.pack_into('<I', ent, 28, len(data))
    f.seek(slot_off); f.write(ent)

    # payload
    pos = 0
    for c in chain:
        chunk = data[pos:pos+clus_size]
        f.seek(coff(c)); f.write(chunk); pos += len(chunk)
    f.flush()
    print(f"{name}: clus={chain[0]:#x} size={len(data)} dir@{slot_off:#x}")
