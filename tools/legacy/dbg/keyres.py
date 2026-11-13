import sys
sys.path.insert(0,"/mnt/d/Desktop/Git/ios-samsung-i9100/tools/dbg")
from dsc_disasm import *
# slots near 0x3959b6a0-0x3959b6c0 -> CFString objects -> inspect cstring field
for s in range(0x3959b698,0x3959b6d0,4):
    v=rd(s)
    print(hex(s),"->",hex(v))
    # CFString: [isa,flags,cstr,len]
    try:
        isa,fl,cs,ln=struct.unpack_from("<IIII",D,foff(v))
        if 0x30000000<cs<0x3a000000 and ln<80:
            print("     CFString:",repr(csv(cs)))
    except Exception as e: pass
