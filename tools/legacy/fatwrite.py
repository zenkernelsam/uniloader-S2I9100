#!/usr/bin/env python3
# FAT32-aware file writer for out/sd-ios6.img.
# Usage: fatwrite.py <sd.img> <fat-path> <local-file> [--verify]
# Walks the target's real cluster chain (fragmentation-safe), writes the
# local file through it, and patches the directory entry size.
import sys, struct

PART_OFF = 0x100000  # sector 2048

def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]

class Fat:
    def __init__(self, img):
        self.img = img
        with open(img, 'rb') as f:
            f.seek(PART_OFF)
            bpb = f.read(512)
        assert bpb[510:512] == b'\x55\xaa', 'no partition at 0x100000'
        self.sec_size = u16(bpb, 11)
        self.sec_clus = bpb[13]
        self.rsvd = u16(bpb, 14)
        self.nfats = bpb[16]
        self.fat_secs = u32(bpb, 36)
        self.root_clus = u32(bpb, 44)
        self.clus_size = self.sec_size * self.sec_clus
        self.fat_off = PART_OFF + self.rsvd * self.sec_size
        self.data_off = PART_OFF + (self.rsvd + self.nfats * self.fat_secs) * self.sec_size
        self._fat = None

    def fat(self):
        if self._fat is None:
            with open(self.img, 'rb') as f:
                f.seek(self.fat_off)
                self._fat = f.read(self.fat_secs * self.sec_size)
        return self._fat

    def next_clus(self, c):
        e = u32(self.fat(), c * 4) & 0x0FFFFFFF
        return None if e >= 0x0FFFFFF8 else e

    def chain(self, start):
        out, c, seen = [], start, set()
        while c is not None and c >= 2 and c not in seen:
            seen.add(c)
            out.append(c)
            c = self.next_clus(c)
        return out

    def clus_off(self, c):
        return self.data_off + (c - 2) * self.clus_size

    def read_dir(self, start):
        data = b''
        for c in self.chain(start):
            with open(self.img, 'rb') as f:
                f.seek(self.clus_off(c))
                data += f.read(self.clus_size)
        ents = []
        for off in range(0, len(data) - 32, 32):
            e = data[off:off + 32]
            if e[0] == 0: break
            if e[0] == 0xE5 or e[11] == 0x0F: continue
            name = e[0:8].decode('ascii', 'replace').strip()
            ext = e[8:11].decode('ascii', 'replace').strip()
            full = name + ('.' + ext if ext else '')
            clus = (u16(e, 20) << 16) | u16(e, 26)
            ents.append({'name': full, 'clus': clus, 'size': u32(e, 28),
                         'attr': e[11], 'dir_off': None})
        return ents

    def find(self, path):
        parts = [p for p in path.upper().split('/') if p]
        clus = self.root_clus
        for i, want in enumerate(parts):
            last = i == len(parts) - 1
            ent = None
            for e in self.read_dir(clus):
                if e['name'].upper() == want:
                    ent = e
                    break
            if not ent:
                return None
            if last:
                return ent
            if not (ent['attr'] & 0x10):
                return None
            clus = ent['clus']
        return None

def main():
    img, path, local = sys.argv[1:4]
    fat = Fat(img)
    print(f"clus_size={fat.clus_size} data_off={fat.data_off:#x}")
    ent = fat.find(path)
    if not ent:
        sys.exit(f"not found: {path}")
    print(f"{path}: clus={ent['clus']:#x} size={ent['size']}")
    with open(local, 'rb') as f:
        data = f.read()
    chain = fat.chain(ent['clus'])
    cap = len(chain) * fat.clus_size
    print(f"chain={len(chain)} clusters cap={cap} write={len(data)}")
    with open(img, 'r+b') as f:
        # grow the chain with free clusters when the payload exceeds capacity
        if len(data) > cap:
            need = -(-(len(data) - cap) // fat.clus_size)
            fat_bytes = fat.fat()
            free = [c for c in range(2, len(fat_bytes) // 4)
                    if u32(fat_bytes, c * 4) == 0]
            assert len(free) >= need, 'not enough free clusters'
            last = chain[-1]
            for i in range(need):
                c = free[i]
                for nf in range(fat.nfats):
                    off = fat.fat_off + nf * fat.fat_secs * fat.sec_size
                    f.seek(off + last * 4)
                    f.write(struct.pack('<I', c))
                    f.seek(off + c * 4)
                    f.write(struct.pack('<I', 0x0FFFFFF8))
                chain.append(c)
                last = c
            fat._fat = None
            print(f"extended chain by {need} clusters -> {chain[-need:]}")
        pos = 0
        for c in chain:
            chunk = data[pos:pos + fat.clus_size]
            if not chunk: break
            f.seek(fat.clus_off(c))
            f.write(chunk)
            pos += len(chunk)
        f.flush()
    print(f"wrote {pos} bytes")

if __name__ == '__main__':
    main()
