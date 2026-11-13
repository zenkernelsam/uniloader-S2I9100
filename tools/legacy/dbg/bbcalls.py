import struct
from capstone import *
d=open("/root/i9100d/research/ios6-bin/backboardd","rb").read()
code=d[0x1328:0x1328+0x2ab08]
targets={0x3be38:"CreateCFProperty",0x3be44:"FromPath",0x3be5c:"SearchCFProp",0x3be50:"GetParentEntry",0x3be68:"GetMatchingService",0x3be8c:"IOServiceOpen",0x3bb08:"IOMFBOpen",0x3bd60:"HIDEvSysCopyMatching",0x3be74:"GetMatchingServices",0x3be80:"IOServiceMatching"}
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB); md.detail=True
for i in md.disasm(code,0x2328):
    if i.mnemonic in("bl","blx"):
        t=i.operands[0].imm
        if t in targets:
            print(hex(i.address),i.mnemonic,"->",targets[t])
