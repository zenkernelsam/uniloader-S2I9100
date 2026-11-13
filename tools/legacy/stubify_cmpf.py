#!/usr/bin/env python3
# Rewrite the cmpf (Type4) body inside a file's resource fork in ROOTFS.HFS
# so it decompresses to a given stub binary padded with zeros to the
# original uncompressed size. The catalog/attrs stay untouched.
import struct, sys, zlib

BS = 8192

def rsrc_range(img, blk_line):
    # blk_line like "152809-152823" or "152671"
    a, _, b = blk_line.partition("-")
    start = int(a) * BS
    end = (int(b or a) + 1) * BS
    return start, end

def patch(img_path, rsrc_start, rsrc_size, usize, stub_path):
    img = open(img_path, "r+b")
    img.seek(rsrc_start)
    rsrc = bytearray(img.read(rsrc_size))
    data_off = struct.unpack(">I", rsrc[0:4])[0]
    body_start = data_off + 4
    assert data_off < len(rsrc) - 16, "bad rsrc header"

    stub = open(stub_path, "rb").read()
    assert len(stub) <= usize
    content = stub + b"\x00" * (usize - len(stub))

    CH = 65536
    n = (usize + CH - 1) // CH
    chunks = [zlib.compress(content[i*CH:(i+1)*CH], 9) for i in range(n)]

    data_start = 8 + 4 * (2 * n - 1)
    body = struct.pack("<II", n, data_start)
    off = data_start
    for i, c in enumerate(chunks):
        body += struct.pack("<I", len(c))
        if i < n - 1:
            off += len(c)
            body += struct.pack("<I", off)  # absolute end rel. to body? fetcher ignores
    for c in chunks:
        body += c
    print("usize=%d nchunks=%d newbody=%d" % (usize, n, len(body)))

    if body_start + len(body) > len(rsrc):
        raise SystemExit("new body doesn't fit in rsrc fork")
    rsrc[body_start:body_start+len(body)] = body
    # zero-pad to the original declared data len region so no stale bytes confuse anything
    img.seek(rsrc_start)
    img.write(rsrc)
    img.close()

if __name__ == "__main__":
    img, blocks, rsrc_size, usize, stub = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
    s, e = rsrc_range(img, blocks)
    print("rsrc @ %#x len %#x" % (s, e - s))
    patch(img, s, rsrc_size, usize, stub)
