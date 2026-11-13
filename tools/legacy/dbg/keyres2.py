import sys
sys.path.insert(0,"/mnt/d/Desktop/Git/ios-samsung-i9100/tools/dbg")
from dsc_disasm import *
for va in [0x31d4ad89,0x31d4ae35,0x31d4ae45,0x31d4ae51]:
    print(hex(va),repr(csv(va)))
