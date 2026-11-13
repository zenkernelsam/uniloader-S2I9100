#!/usr/bin/env python3
# Patch a Type3 (inline-in-xattr) decmpfs file in ROOTFS.HFS so it
# decompresses to a stub binary padded with zeros to the original usize.
# usage: stubify_type3.py <image> <fileid> <usize> <stub>
import struct, sys, zlib

img_path, fileid, usize, stub_path = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
name = "com.apple.decmpfs".encode("utf-16-be")
key = struct.pack(">I", fileid) + b"\x00\x00\x00\x00" + struct.pack(">H", 17) + name

img = open(img_path, "r+b")
data = img.read()
p = data.find(key)
assert p >= 0, "attr record not found"
rec = p + len(key)
rt_, rsv1, rsv2, asize = struct.unpack(">IIII", data[rec:rec+16])
print("record @ %#x type=%#x attrSize=%d" % (rec, rt_, asize))
hdr = data[rec+16:rec+32]
magic, ctype, usize_lo, usize_hi = struct.unpack("<4sIII", hdr)
assert magic == b"fpmc" and ctype == 3, (magic, ctype)
assert usize_lo == usize, (usize_lo, usize)

stub = open(stub_path, "rb").read()
assert len(stub) <= usize
content = stub + b"\x00" * (usize - len(stub))
z = zlib.compress(content, 9)
zoff = rec + 16 + 16
print("zlib %dB @ %#x" % (len(z), zoff))
img.seek(zoff)
img.write(z)
img.close()
print("patched")
