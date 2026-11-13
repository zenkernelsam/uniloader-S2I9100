import struct
from capstone import *
d=open("/root/i9100d/research/ios6-bin/backboardd","rb").read()
base=0x1000
# entry file off 0x1329 -> VA 0x2329
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
code=d[0x1328:0x1328+0x2ab08]
# main = entry: disasm first 400 insns, print calls/targets and CFString/imp loads
for i in md.disasm(code[1:1+1400],0x2329):
    out=hex(i.address)+"\t"+i.mnemonic+"\t"+i.op_str
    print(out)
