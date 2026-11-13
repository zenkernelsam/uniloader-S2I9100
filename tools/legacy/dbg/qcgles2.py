import struct, sys
D = open("assets/ios6-extract/dyld_cache6_armv7", "rb").read()
mo, mc, io, ic = struct.unpack_from("<IIII", D, 16)
maps = [struct.unpack_from("<QQQII", D, mo + i * 32) for i in range(mc)]

def foff(va):
    for s, z, o, _, _ in maps:
        if s <= va < s + z:
            return o + va - s

STRVA = 0x325a3f98
# find cfstring objects: [isa, flags, strva, len]
for s, z, o, fl, mx in maps:
    seg = D[o:o+z]
    for i in range(0, z - 16, 4):
        if struct.unpack_from("<I", seg, i + 8)[0] == STRVA:
            va = s + i
            ln = struct.unpack_from("<I", seg, i + 12)[0]
            if ln == 16:
                print("cfstring at va %x (map %x)" % (va, s))
