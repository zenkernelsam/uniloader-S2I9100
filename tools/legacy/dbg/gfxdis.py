import struct, sys
from capstone import *
D = open("assets/ios6-extract/dyld_cache6_armv7", "rb").read()
mo, mc, io, ic = struct.unpack_from("<IIII", D, 16)
maps = [struct.unpack_from("<QQQII", D, mo + i * 32) for i in range(mc)]

def foff(va):
    for s, z, o, _, _ in maps:
        if s <= va < s + z:
            return o + va - s

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
start = int(sys.argv[1], 16)
size = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x600
data = D[foff(start):foff(start) + size]
for ins in md.disasm(data, start):
    print("%x: %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))
