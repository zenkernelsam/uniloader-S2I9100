import struct,bisect,sys
sys.path.insert(0,"/mnt/d/Desktop/Git/ios-samsung-i9100/tools/dbg")
from dsc_disasm import *
base=imgbase("/IOKit.framework")
syms=symtab(base)
for v,n in syms:
    if "IOServiceMatching" in n or "NameMatching" in n or "ClassMatching" in n or "GetMatchingServ" in n:
        print(hex(v),n)
