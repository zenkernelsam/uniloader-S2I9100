import struct, bisect, sys
D = open("assets/ios6-extract/dyld_cache6_armv7", "rb").read()
mo, mc, io, ic = struct.unpack_from("<IIII", D, 16)
maps = [struct.unpack_from("<QQQII", D, mo + i * 32) for i in range(mc)]
imgs = []
for i in range(ic):
    a, _, _, p, _ = struct.unpack_from("<QQQII", D, io + i * 32)
    e = D.find(b"\0", p)
    imgs.append((a, D[p:e].decode()))

def foff(va):
    for s, z, o, _, _ in maps:
        if s <= va < s + z:
            return o + va - s

def rd32(va):
    return struct.unpack_from("<I", D, foff(va))[0]

# find QuartzCore text range
qc = [a for a, n in imgs if "QuartzCore" in n]
print([hex(x) for x in qc], [n for a, n in imgs if "QuartzCore" in n])

# locate IOGLESBundleName string
sv = D.find(b"IOGLESBundleName\0")
print("str fileoff", hex(sv), "va", hex(next(s + (sv - o) for s, z, o, _, _ in maps if o <= sv < o + z)))
svva = next(s + (sv - o) for s, z, o, _, _ in maps if o <= sv < o + z)

# scan all executable mapping words for refs to the string va
for s, z, o, fl, mx in maps:
    if mx != 5: continue  # r-x only
    seg = D[o:o+z]
    hits = []
    for i in range(0, z - 4, 4):
        v = struct.unpack_from("<I", seg, i)[0]
        if v == svva:
            hits.append(s + i)
    if hits:
        print("map %x hits %s" % (s, [hex(h) for h in hits[:20]]))
