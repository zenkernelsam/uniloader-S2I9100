import struct, sys
# Resolve iOS6 dyld_shared_cache pointers to image+symbol.
# Usage: python3 resolve_ptrs.py 0x31098e01 0x312d9705 ...
d = open("assets/ios6-extract/dyld_cache6_armv7","rb").read()
mo,mc,io,ic=struct.unpack_from("<IIII",d,16)
maps=[struct.unpack_from("<QQQII",d,mo+i*32) for i in range(mc)]
def foff(va):
    for start,size,off,_,_ in maps:
        if start<=va<start+size: return off+va-start
    raise ValueError(hex(va))
def rd32(va): return struct.unpack_from("<I",d,foff(va))[0]
def cstr(off): return d[off:d.find(b"\0",off)].decode("utf8","replace")
images=[]
for i in range(ic):
    addr,_,_,path,_=struct.unpack_from("<QQQII",d,io+i*32)
    images.append((addr,cstr(path)))
images.sort()
def symof(va):
    start,path=max((x for x in images if x[0]<=va),key=lambda x:x[0])
    header=foff(start)
    ncmds=struct.unpack_from("<I",d,header+16)[0]
    cur=header+28; best=(start,"?")
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",d,cur)
        if cmd==2:
            so,sn,st,ss=struct.unpack_from("<IIII",d,cur+8)
            for n in range(sn):
                si,typ,sec,desc,value=struct.unpack_from("<IBBHI",d,so+n*12)
                if typ&0xe0==0 and typ&0x0e==0x0e and start<=value<=va and si<ss:
                    if value>best[0]: best=(value,cstr(st+si))
        cur+=size
    return path.split("/")[-1], best[1], best[0]
for a in sys.argv[1:]:
    va=int(a,16)
    try:
        img,sym,base=symof(va & ~1)
        print("%s %s %s+0x%x" % (a,img,sym,(va&~1)-base))
    except Exception as e:
        print("%s <unmapped>" % a)
