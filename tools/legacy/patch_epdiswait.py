# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# wait for EPDISBLD after disabling each endpoint in soft init -
# arming while the ep is still disabling gets the EPENA write dropped
old = ("\tfor (i = 0; i < 4; i++) {" + N +
       "\t\tDOEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;" + N +
       "\t\tDIEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;" + N +
       "\t}")
new = ("\tfor (i = 0; i < 4; i++) {" + N +
       "\t\tDOEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;" + N +
       "\t\tDIEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;" + N +
       "\t\tif (DIEPCTL(i) & DXEPCTL_EPENA)" + N +
       "\t\t\tbounded_wait(&DIEPCTL(i), DXEPCTL_EPDIS, 0, 100000);" + N +
       "\t\tDIEPINT(i) = 0x3ff;" + N +
       "\t\tDOEPINT(i) = 0x3ff;" + N +
       "\t}")
assert old in s; s = s.replace(old, new, 1)

# revert the experimental DOEPCTL CNAK in the STUP handler - it moved
# the timing just enough to lose the disable race
old = ("\t\t\t\tjust_setup = 1;" + N +
       "\t\t\t\tDOEPCTL(0) |= DXEPCTL_CNAK;" + N +
       "\t\t\t\tep0_setup();")
new = ("\t\t\t\tjust_setup = 1;" + N +
       "\t\t\t\tep0_setup();")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
