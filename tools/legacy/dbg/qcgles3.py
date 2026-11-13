import struct, sys
D = open("assets/ios6-extract/dyld_cache6_armv7", "rb").read()
mo, mc, io, ic = struct.unpack_from("<IIII", D, 16)
maps = [struct.unpack_from("<QQQII", D, mo + i * 32) for i in range(mc)]
imgs = []
for i in range(ic):
    a, _, _, p, _ = struct.unpack_from("<QQQII", D, io + i * 32)
    e = D.find(b"\0", p)
    imgs.append((a, D[p:e].decode()))

def imgof(va):
    c = [n for a, n in imgs if a <= va < a + 0x4000000]
    return c[0] if c else "?"

TARGET = 0x396512a4
print("string owner:", imgof(TARGET))
for s, z, o, fl, mx in maps:
    if mx != 5: continue
    seg = D[o:o+z]
    for i in range(0, z - 4, 4):
        v = struct.unpack_from("<I", seg, i)[0]
        if v == TARGET:
            va = s + i
            print("ref at %x in %s" % (va, imgof(va)))
