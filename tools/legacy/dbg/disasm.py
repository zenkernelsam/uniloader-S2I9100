import struct, sys
from capstone import *
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
    return best[1], va-best[0]
def resolve_stub(x):
    try:
        if rd32(x)==0xe59fc004 and rd32(x+4)==0xe08fc00c and rd32(x+8)==0xe59cf000:
            return rd32(x+12+rd32(x+12))
    except Exception: pass
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB); md.detail=False
base=int(sys.argv[1],16); end=int(sys.argv[2],16)
off=foff(base)
for i in md.disasm(d[off:off+(end-base)],base):
    line="%08x  %-20s %s" % (i.address,i.mnemonic,i.op_str)
    if i.mnemonic=="blx" and i.op_str.startswith("#0x"):
        t=int(i.op_str[1:],16); rt=resolve_stub(t)
        if rt:
            s,disp=symof(rt&~1); line+="   ; %s+0x%x"%(s,disp)
    elif i.mnemonic in ("bl","b.w","b") and i.op_str.startswith("#0x"):
        t=int(i.op_str[1:],16); s,disp=symof(t&~1); line+="   ; %s+0x%x"%(s,disp)
    print(line)
