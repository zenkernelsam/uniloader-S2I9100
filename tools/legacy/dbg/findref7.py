import struct
from capstone import *

import sys
d = open(sys.argv[1] if len(sys.argv) > 1 else "/root/i9100d/research/ios6-bin/backboardd", "rb").read()
code = d[0x1328:0x1328 + 0x2ab08]

# cstring file offset -> VA: file-0x3217d + 0x3317d
targets = {
    0x392DB: "framebuffer service",
    0x392FD: "Could-not-open-fb",
    0x34D69: "No window server display",
    0x34D04: "BKDisplayStartWindowServer",
}

pools = {}
for off in range(0, len(code) - 4, 2):
    v = struct.unpack_from("<I", code, off)[0]
    if v in targets:
        pools[0x2328 + off] = v
print("pools:", {hex(k): targets[v] for k, v in pools.items()})

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
for i in md.disasm(code, 0x2328):
    if i.mnemonic == "ldr" and "[pc" in i.op_str:
        la = ((i.address + 4) & ~3) + i.operands[1].mem.disp
        if la in pools:
            print(hex(i.address), "->", targets[pools[la]])
