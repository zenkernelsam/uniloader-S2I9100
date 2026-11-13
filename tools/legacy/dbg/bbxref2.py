import struct
from capstone import *
d=open("/root/i9100d/research/ios6-bin/backboardd","rb").read()
nc=struct.unpack_from("<I",d,16)[0]; cur=28
so=sn=st=ss=None; ds=None
for _ in range(nc):
    cmd,sz=struct.unpack_from("<II",d,cur)
    if cmd==2: so,sn,st,ss=struct.unpack_from("<IIII",d,cur+8)
    if cmd==0xb: ds=cur
    cur+=sz
print("symtab",hex(so),sn,"str",hex(st),"dysymtab@",hex(ds) if ds else None)
# dysymtab fields
f=struct.unpack_from("<18I",d,ds+8)
names=["ilocalsym","nlocalsym","iextdefsym","nextdefsym","iundefsym","nundefsym","tocoff","ntoc","modtaboff","nmodtab","extrefsymoff","nextrefsyms","indirectsymoff","nindirectsyms","extreloff","nextrel","locreloff","nlocrel"]
for i,(n,v) in enumerate(zip(names,f)): print(" ",n,hex(v))
def cs(o):
    e=d.find(b"\0",st+o); return d[st+o:e].decode()
# indirect symbol table: each entry u32 sym index
ioff,nind=f[12],f[13]
iu,nu=f[4],f[5]
# section order for __symbolstub1: indirect syms indexed by (sect.addr - first_indirect_addr)/stride
# lazy symbols start at iundefsym..iundefsym+nundefsym in symtab = undefined imports in order
def stubname(idx):
    si=struct.unpack_from("<I",d,ioff+idx*4)[0]
    if si==0x80000000 or si==0x40000000: return "local?"
    s,ty,se,de,va=struct.unpack_from("<IBBHI",d,so+si*12)
    return cs(s) if s<ss else hex(si)
# stubs: 12B each at 0x3ba9c
for i in range(0x558//12):
    print(i,hex(0x3ba9c+i*12),stubname(i))
