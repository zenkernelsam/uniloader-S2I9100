import struct
import sys
from capstone import *
from capstone.arm import *

d = open(sys.argv[1] if len(sys.argv) > 1 else "/root/i9100d/research/ios6-bin/backboardd", "rb").read()
code = d[0x1328:0x1328 + 0x2ab08]

targets = {
    0x33BEF: "cstr display",
    0x33BF7: "cstr IODeviceTree:/chosen",
    0x33ED0: "cstr IODeviceTree:/",
    0x33D88: "cstr display-scale",
    0x33C0C: "cstr display-rotation",
    0x392DB: "cstr framebuffer service",
    0x392FD: "cstr Could-not-open-fb",
    0x34D69: "cstr No window server display",
    0x34D04: "cstr BKDisplayStartWindowServer",
    0x41FB0: "cfstr display",
    0x41FC0: "cfstr display-rotation",
    0x42060: "cfstr display-scale",
}

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

# track 16-bit halves per reg; emit when lo|hi16 completes a target VA
lo = {}
hi = {}
for i in md.disasm(code, 0x2328):
    if i.mnemonic == "movw":
        lo[i.operands[0].reg] = (i.operands[1].imm, i.address)
    elif i.mnemonic == "movt":
        r = i.operands[0].reg
        if r in lo:
            v = (i.operands[1].imm << 16) | lo[r][0]
            if v in targets:
                print("PAIR ref", targets[v], "at", hex(lo[r][1]), "-", hex(i.address))
            hi[r] = (i.operands[1].imm, i.address)
            lo.pop(r, None)
    elif i.mnemonic == "movw":
        pass
    # also movw AFTER movt
    if i.mnemonic == "movw" and i.operands[0].reg in hi:
        r = i.operands[0].reg
        v = (hi[r][0] << 16) | i.operands[1].imm
        if v in targets:
            print("REV-PAIR ref", targets[v], "at", hex(hi[r][1]), "-", hex(i.address))
    # addw/subw rx, pc forms
    if i.mnemonic in ("addw", "subw") and "pc" in i.op_str.lower():
        r = i.operands[0].reg
        imm = i.operands[2].imm
        base = (i.address + 4) & ~3
        v = base + imm if i.mnemonic == "addw" else base - imm
        if v in targets:
            print("PC-REL", i.mnemonic, "ref", targets[v], "at", hex(i.address))
    if i.mnemonic == "adr":
        v = i.operands[1].imm
        if v in targets:
            print("ADR ref", targets[v], "at", hex(i.address))
