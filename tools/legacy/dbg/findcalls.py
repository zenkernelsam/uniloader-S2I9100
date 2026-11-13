import struct, sys
d = open("assets/ios6-extract/dyld_cache6_armv7","rb").read()
mo,mc,io,ic=struct.unpack_from("<IIII",d,16)
maps=[struct.unpack_from("<QQQII",d,mo+i*32) for i in range(mc)]
def foff(va):
    for start,size,off,_,_ in maps:
        if start<=va<start+size: return off+va-start
    raise ValueError(hex(va))
tgt=int(sys.argv[1],16)
lo=int(sys.argv[2],16); hi=int(sys.argv[3],16)
hits=[]
for va in range(lo&~3, hi, 4):
    off=foff(va); w=struct.unpack_from("<I",d,off)[0]
    hw1=w&0xffff; hw2=w>>16
    if (hw1&0xF800)!=0xF000: continue
    if (hw2&0xD000)!=0xC000 and (hw2&0xD000)!=0xD000: continue
    s=(hw1>>10)&1; imm10=hw1&0x3ff
    j1=(hw2>>13)&1; j2=(hw2>>11)&1; imm11=hw2&0x7ff
    i1=1^(j1^s); i2=1^(j2^s)
    v=(s<<24)|(i1<<23)|(i2<<22)|(imm10<<12)|(imm11<<1)
    if s: v-=1<<25
    pc=(va+4)&~3
    t=pc+v
    t&=~1
    if t==tgt: hits.append(va)
print("\n".join(hex(h) for h in hits))
