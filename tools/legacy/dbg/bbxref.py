import struct
from capstone import *
d=open("/root/i9100d/research/ios6-bin/backboardd","rb").read()
# lazy_symbol section: VA 0x3c000 file 0x3b000 size 0x558
# __symbolstub1 VA 0x3ba9c file 0x3aa9c size 0x558 -> each stub 12? measure
# resolve stub addr -> lazy ptr -> symbol name via dysymtab? use indirect sym index
# Lazy ptr order == lazy stub order; names via symtab undefined section order = indirect symbol table.
# Simpler: stubs at __symbolstub1 are ARM(12B) or thumb(8B)? inspect first bytes
import binascii
print("stub head:",d[0x3aa9c:0x3aa9c+24].hex())
# dysymtab load cmd: cmd=0xb: parse for indirectsym index
nc=struct.unpack_from("<I",d,16)[0]; cur=28
ds=None
for _ in range(nc):
    cmd,sz=struct.unpack_from("<II",d,cur)
    if cmd==0xb: ds=cur
    cur+=sz
# dysymtab: iundefsym, nundefsym, indirectsymoff, nindirectsym
iu,nu,ioff,ni=struct.unpack_from("<IIII",d,ds+40)
print("undef",iu,nu,"indirect",hex(ioff),ni)
so,sn,st,ss=struct.unpack_from("<IIII",d,0x3b000) # wrong — symtab was LC_SYMTAB cmd2
