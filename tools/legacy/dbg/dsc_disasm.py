import struct, bisect, sys
from capstone import *

D = open("/root/i9100d/assets/ios6-extract/dyld_cache6_armv7", "rb").read()
mo, mc, io, ic = struct.unpack_from("<IIII", D, 16)
maps = [struct.unpack_from("<QQQII", D, mo + i * 32) for i in range(mc)]

def foff(va):
    for s, z, o, _, _ in maps:
        if s <= va < s + z:
            return o + va - s

def rdo(o):
    return struct.unpack_from("<I", D, o)[0]

def rd(va):
    return rdo(foff(va))

def csv(va):
    o = foff(va)
    e = D.find(b"\0", o)
    return D[o:e].decode("utf8", "replace")

def imgbase(pathpart):
    for i in range(ic):
        a, _, _, p, _ = struct.unpack_from("<QQQII", D, io + i * 32)
        e = D.find(b"\0", p)
        if pathpart in D[p:e].decode():
            return a
    return None

def symtab(base):
    hdr = foff(base)
    nc = rdo(hdr + 16)
    cur = hdr + 28
    for _ in range(nc):
        cmd, sz = rdo(cur), rdo(cur + 4)
        if cmd == 2:
            so, sn, st, ss = rdo(cur + 8), rdo(cur + 12), rdo(cur + 16), rdo(cur + 20)
            def cst(o):
                e = D.find(b"\0", st + o)
                return D[st + o:e].decode()
            syms = []
            for n in range(sn):
                si, typ, sec, desc, val = struct.unpack_from("<IBBHI", D, so + n * 12)
                if si < ss and val:
                    syms.append((val, cst(si)))
            syms.sort()
            return syms
        cur += sz
    return []

_symcache = {}
def symof(va):
    best = (0, "?")
    for i in range(ic):
        a, _, _, p, _ = struct.unpack_from("<QQQII", D, io + i * 32)
        if a <= va and a > best[0]:
            best = (a, p)
    if not best[0]:
        return hex(va)
    e = D.find(b"\0", best[1])
    path = D[best[1]:e].decode()
    if path not in _symcache:
        _symcache[path] = symtab(best[0])
    syms = _symcache[path]
    vs = [v for v, _ in syms]
    j = bisect.bisect_right(vs, va) - 1
    if j >= 0:
        return path.split("/")[-1] + ":" + syms[j][1] + "+" + hex(va - syms[j][0])
    return path.split("/")[-1] + "+" + hex(va - best[0])

def stub_target(st):
    off = rdo(foff(st) + 12)
    return rd(st + 12 + off)

def disasm_range(base, size):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    code = D[foff(base):foff(base) + size]
    for i in md.disasm(code, base):
        extra = ""
        if i.mnemonic == "blx":
            t = i.operands[0].imm
            extra = " ; -> " + hex(t)
            try:
                extra += " " + symof(stub_target(t))
            except Exception:
                pass
        elif i.mnemonic == "bl":
            extra = " ; -> " + hex(i.operands[0].imm)
        elif i.mnemonic == "add" and "pc" in i.op_str and len(i.operands) > 2:
            v = ((i.address + 4) & ~3) + i.operands[2].imm
            try:
                extra = " ; " + hex(v) + " " + repr(csv(v)[:60])
            except Exception:
                pass
        print("%x %-8s %-24s%s" % (i.address, i.mnemonic, i.op_str, extra))

if __name__ == "__main__":
    disasm_range(int(sys.argv[1], 16), int(sys.argv[2], 16))
