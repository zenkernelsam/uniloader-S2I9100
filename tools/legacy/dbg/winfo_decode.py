#!/usr/bin/env python3
"""Annotate `threads <proc>` winfo lines: map pc/lr to dyld-cache symbols.

Build once:   winfo_decode.py --build      (writes dyld6_syms.bin next to cache)
Decode:       winfo_decode.py threads.txt  (or stdin)
Each uth= line gains  pc=<sym+off>  lr=<sym+off>  annotations.
ith_state 0x10004001 => blocked in mach_msg receive (rnam = port name).
"""
import struct, sys, bisect, os

CACHE = "/root/i9100d/assets/ios6-extract/dyld_cache6_armv7"
IDX   = "/root/i9100d/assets/ios6-extract/dyld6_syms.bin"
BBD   = "/root/i9100d/research/ios6-bin/backboardd"
SBD   = "/root/i9100d/research/ios6-bin/SpringBoard"
EXTRA = [BBD, SBD]

def build():
    D = open(CACHE, "rb").read()
    mo, mc, io, ic = struct.unpack_from("<IIII", D, 16)
    maps = [struct.unpack_from("<QQQII", D, mo + i * 32) for i in range(mc)]
    def foff(va):
        for s, z, o, _, _ in maps:
            if s <= va < s + z:
                return o + va - s
    def rdo(o): return struct.unpack_from("<I", D, o)[0]
    def cst(tab, o):
        e = D.find(b"\0", tab + o)
        return D[tab + o:e].decode("utf8", "replace")
    out = []
    for i in range(ic):
        a, _, _, p, _ = struct.unpack_from("<QQQII", D, io + i * 32)
        e = D.find(b"\0", p)
        lib = os.path.basename(D[p:e].decode("utf8", "replace"))
        hdr = foff(a)
        if hdr is None: continue
        nc = rdo(hdr + 16); cur = hdr + 28
        for _ in range(nc):
            cmd, sz = rdo(cur), rdo(cur + 4)
            if cmd == 2:
                so, sn, st, ss = rdo(cur+8), rdo(cur+12), rdo(cur+16), rdo(cur+20)
                for n in range(sn):
                    si, ty, sc, dc, v = struct.unpack_from("<IBBHI", D, so + n*12)
                    if si < ss and v:
                        out.append((v, cst(st, si), lib))
                break
            cur += sz
    # standalone binaries (non-PIE preferred base)
    for path in EXTRA:
        try:
            b = open(path, "rb").read()
        except OSError:
            continue
        lib = os.path.basename(path)
        nc = struct.unpack_from("<I", b, 16)[0]; cur = 28
        base = None
        for _ in range(nc):
            cmd, sz = struct.unpack_from("<II", b, cur)
            if cmd == 1:  # LC_SEGMENT first __TEXT gives preferred base
                seg = b[cur+8:cur+24].split(b"\0")[0].decode("utf8","replace")
                if seg == "__TEXT" and base is None:
                    base = struct.unpack_from("<I", b, cur+24)[0]
            if cmd == 2:
                so, sn, st, ss = struct.unpack_from("<IIII", b, cur+8)
                for n in range(sn):
                    si, ty, sc, dc, v = struct.unpack_from("<IBBHI", b, so + n*12)
                    if si < ss and v:
                        e = b.find(b"\0", st + si)
                        out.append((v, b[st+si:e].decode("utf8","replace"), lib))
                break
            cur += sz
    out.sort()
    W = open(IDX, "wb")
    W.write(struct.pack("<I", len(out)))
    names = []
    for v, nm, lib in out:
        tag = lib + ":" + nm
        names.append(tag)
        W.write(struct.pack("<II", v, len(tag)))
    blob = b"\0".join(t.encode() for t in names)
    W.write(blob)
    print("wrote", IDX, len(out), "symbols")

_tab = None
def load():
    global _tab
    if _tab: return _tab
    d = open(IDX, "rb").read()
    n = struct.unpack_from("<I", d, 0)[0]
    addrs = []; lens = []
    for i in range(n):
        v, l = struct.unpack_from("<II", d, 4 + i * 8)
        addrs.append(v); lens.append(l)
    blob = d[4 + n * 8:]
    tags = blob.split(b"\0")
    _tab = (addrs, [t.decode("utf8", "replace") for t in tags])
    return _tab

def sym(addr):
    addrs, tags = load()
    i = bisect.bisect_right(addrs, addr) - 1
    if i < 0: return None
    off = addr - addrs[i]
    if off > 0x400: return None
    return "%s+0x%x" % (tags[i], off) if off else tags[i]

for path in sys.argv[1:]:
    if path == "--build":
        build(); sys.exit(0)
src = open(sys.argv[1], "rb").read().decode("utf8","replace") if len(sys.argv)>1 else sys.stdin.read()
import re
for line in src.splitlines():
    m = dict(re.findall(r"(\w+)=([0-9a-fA-Fx]+|\S+)", line))
    note = []
    for k in ("pc", "lr", "cont"):
        if k in m:
            try: s = sym(int(m[k], 16))
            except ValueError: s = None
            if s: note.append("%s->%s" % (k, s))
    ist = m.get("ist")
    if ist and int(ist, 16) == 0x10004001:
        note.append("MACH_MSG_RECEIVE port=%s" % m.get("rnam", "?"))
    print(line + ("   ; " + " ".join(note) if note else ""))
