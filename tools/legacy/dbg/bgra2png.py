#!/usr/bin/env python3
"""Convert a raw BGRA8888 framebuffer dump to PNG (stdlib only).

Usage: bgra2png.py in.bin out.png [width height [stride]]
Defaults match the i9100 scanout: 480x800, stride=width*4.
Rows are top-to-bottom, pixels are little-endian B,G,R,A.
"""
import struct, sys, zlib

def png(width, height, rgba_rows):
    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + row for row in rgba_rows)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))

def main():
    if len(sys.argv) < 3:
        sys.exit("usage: bgra2png.py in.bin out.png [w h [stride]]")
    src, dst = sys.argv[1], sys.argv[2]
    w = int(sys.argv[3]) if len(sys.argv) > 3 else 480
    h = int(sys.argv[4]) if len(sys.argv) > 4 else 800
    stride = int(sys.argv[5]) if len(sys.argv) > 5 else w * 4
    data = open(src, "rb").read()
    need = stride * h
    if len(data) < need:
        sys.exit("short read: %d < %d" % (len(data), need))
    rows = []
    for y in range(h):
        row = bytearray()
        base = y * stride
        for x in range(w):
            b, g, r, _a = data[base + x * 4:base + x * 4 + 4]
            row += bytes((r, g, b, 255))
        rows.append(bytes(row))
    open(dst, "wb").write(png(w, h, rows))
    print("wrote %s (%dx%d)" % (dst, w, h))

if __name__ == "__main__":
    main()
