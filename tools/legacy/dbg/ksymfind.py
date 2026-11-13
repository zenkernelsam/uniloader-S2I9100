import struct, sys
d = open(sys.argv[1], "rb").read()
pos = 28
strtab = None
for i in range(struct.unpack_from("<I", d, 16)[0]):
    cmd, sz = struct.unpack_from("<II", d, pos)
    if cmd == 2:
        strtab = struct.unpack_from("<IIII", d, pos + 8)
    pos += sz
so, ns, st, ss = strtab
want = sys.argv[2].split(",")
for n in range(ns):
    si, ty, sc, dc, v = struct.unpack_from("<IBBHI", d, so + n * 12)
    e = d.find(b"\0", st + si)
    nm = d[st + si:e].decode()
    if v and any(w in nm.lower() for w in want):
        print(nm, hex(v))
