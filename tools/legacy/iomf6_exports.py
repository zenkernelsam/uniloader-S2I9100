import struct
d = open("assets/ios6-extract/dyld_cache6_armv7", "rb").read()
mo, mc, io, ic = struct.unpack_from("<IIII", d, 0x10)
maps = [struct.unpack_from("<QQQII", d, mo + i * 32) for i in range(mc)]
def va2off(va):
    for a, s, fo, mp, ip in maps:
        if a <= va < a + s:
            return fo + (va - a)
    return None
base = 0x34f7b000
o = va2off(base)
ncmds = struct.unpack_from("<I", d, o + 16)[0]
pos = o + 28
exp = None
for i in range(ncmds):
    cmd, csz = struct.unpack_from("<II", d, pos)
    if cmd == 0x80000022:
        exp = struct.unpack_from("<10I", d, pos + 8)[8:10]
    pos += csz
eo, es = exp
root = va2off(0x30000000 + eo)
print("export off", hex(eo), "size", es, "file", hex(root))
def uleb(p):
    r = 0; s = 0
    while True:
        b = d[p]; p += 1; r |= (b & 0x7f) << s
        if not b & 0x80: break
        s += 7
    return r, p
out = {}
seen = set()
stack = [(root, b"")]
while stack:
    p, prefix = stack.pop()
    if p in seen or not (root <= p < root + es):
        continue
    seen.add(p)
    sz = d[p]; p += 1
    if sz:
        flags, p = uleb(p)
        addr, p = uleb(p)
        if flags & 8:
            _, p = uleb(p)
        out[prefix] = (addr, flags)
    n = d[p]; p += 1
    for i in range(n):
        e = d.index(b"\x00", p)
        label = d[p:e]
        p = e + 1
        p2, p = uleb(p)
        stack.append((root + p2, prefix + label))
print(len(out), "symbols")
for k in sorted(out):
    if b"Swap" in k or b"VSync" in k or b"vsync" in k or b"Framebuffer" in k:
        print(k.decode(), hex(base + out[k][0]))
