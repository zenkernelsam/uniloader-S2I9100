import struct, sys
d = open("assets/ios6-extract/dyld_cache6_armv7","rb").read()
mo,mc,io,ic=struct.unpack_from("<IIII",d,16)
maps=[struct.unpack_from("<QQQII",d,mo+i*32) for i in range(mc)]
def foff(va):
    for start,size,off,_,_ in maps:
        if start<=va<start+size: return off+va-start
    raise ValueError(hex(va))
def rd32(va): return struct.unpack_from("<I",d,foff(va))[0]
def cstr_va(va):
    o=foff(va); return d[o:d.find(b"\0",o)].decode("utf8","replace")
pairs = {
 "loadplist_1c178->symA": (0x2fa57, 0x31d1c1a2),
 "loadplist_1c1c8->symB": (0x2fa15, 0x31d1c1f6),
 "loadplist_1bf38->symC": (0x2fbaf, 0x31d1bf66),
 "loadplist_1bf90->symD": (0x2fb72, 0x31d1bfb8),
 "copyprofiles arg plistkey": (0x78866a6, 0x31d1526e),
 "copyprofiles arg arrkey": (0x788678e, 0x31d15288),
 "unabridged arg1": (0x7886c02, 0x31d14406),
 "unabridged arg2": (0x7887370, 0x31d1440a),
 "unabridged arg3": (0x7887378, 0x31d14418),
 "unabridged arg4": (0x7887346, 0x31d1445a),
 "unabridged arg5": (0x7887338, 0x31d1447a),
 "unabridged arg6": (0x7887396, 0x31d143da),
 "active arg1": (0x7886d70, 0x31d142a4),
 "active arg2": (0x7886d72, 0x31d142a6),
 "active arg3": (0x7886d12, 0x31d142f6),
}
for name,(imm,pc) in pairs.items():
    a=(imm+pc)&0xffffffff
    try: s=cstr_va(a)
    except Exception as e: s="<err>"
    info=s
    try:
        dp=rd32(a+8); o=foff(dp); cs=d[o:o+80].split(b"\0")[0]
        if all(32<=b<127 for b in cs[:min(len(cs),40)]) and len(cs)>2:
            info="cfstr %r | raw %r" % (cs.decode(), s)
    except Exception: pass
    try:
        p=rd32(a); dp=rd32(p+8); o=foff(dp); cs=d[o:o+80].split(b"\0")[0]
        if all(32<=b<127 for b in cs[:min(len(cs),40)]) and len(cs)>2:
            info+=" | ptr->cfstr %r" % cs.decode()
    except Exception: pass
    print("%-34s %08x %s" % (name,a,info))
