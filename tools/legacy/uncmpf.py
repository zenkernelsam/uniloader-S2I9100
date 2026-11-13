#!/usr/bin/env python3
# Extract the uncompressed content of a decmpfs Type4 file from ROOTFS.HFS
# usage: uncmpf.py <image> <rsrc_block_range> <rsrc_size> <usize> <out>
import struct, sys, zlib

BS = 8192
img_path, blocks, rsrc_size, usize, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
a, _, b = blocks.partition("-")
start = int(a) * BS

img = open(img_path, "rb")
img.seek(start)
rsrc = img.read(rsrc_size)
data_off = struct.unpack(">I", rsrc[0:4])[0]
body = data_off + 4
count, data_start = struct.unpack("<II", rsrc[body:body+8])
sizes = []
for i in range(2 * count - 1):
    sizes.append(struct.unpack("<I", rsrc[body + 8 + 4*i : body + 12 + 4*i])[0])
pos = body + data_start
buf = b""
for i in range(count):
    csz = sizes[2 * i]
    buf += zlib.decompress(rsrc[pos:pos+csz])
    pos += csz
open(out, "wb").write(buf[:usize])
print("wrote", out, len(buf[:usize]))
