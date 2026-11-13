# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# init disable loop: only stamp EPDIS when the ep was actually
# enabled - an absolute EPDIS write to a never-enabled endpoint can
# leave bit30 latched, and every |= arm then carries EPDIS|EPENA
# which cancels itself (EPENA dropped, EPDISBLD, NAKSTS stuck).
old = ("\tfor (i = 0; i < 4; i++) {" + N +
       "\t\tDOEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;" + N +
       "\t\tDIEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;" + N +
       "\t\tif (DIEPCTL(i) & DXEPCTL_EPENA)" + N +
       "\t\t\tbounded_wait(&DIEPCTL(i), DXEPCTL_EPDIS, 0, 100000);" + N +
       "\t\tDIEPINT(i) = 0x3ff;" + N +
       "\t\tDOEPINT(i) = 0x3ff;" + N +
       "\t}")
new = ("\tfor (i = 0; i < 4; i++) {" + N +
       "\t\tuint32_t de = DIEPCTL(i), oe = DOEPCTL(i);" + N +
       "\t\tDOEPCTL(i) = (oe & DXEPCTL_EPENA ? DXEPCTL_EPDIS : 0) |" + N +
       "\t\t\tDXEPCTL_SNAK;" + N +
       "\t\tDIEPCTL(i) = (de & DXEPCTL_EPENA ? DXEPCTL_EPDIS : 0) |" + N +
       "\t\t\tDXEPCTL_SNAK;" + N +
       "\t\tif (de & DXEPCTL_EPENA)" + N +
       "\t\t\tbounded_wait(&DIEPCTL(i), DXEPCTL_EPDIS, 0, 100000);" + N +
       "\t\tDIEPINT(i) = 0x3ff;" + N +
       "\t\tDOEPINT(i) = 0x3ff;" + N +
       "\t}")
assert old in s; s = s.replace(old, new, 1)

# every arm: explicitly clear EPDIS|SNAK|STALL so no stale bit can
# ride the |=
old = ("\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);")
new = ("\tDIEPCTL(0) = (DIEPCTL(0) & ~(DXEPCTL_EPDIS | DXEPCTL_SNAK |" + N +
       "\t\tDXEPCTL_STALL)) | DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);")
assert old in s; s = s.replace(old, new, 1)

# ep0_arm_setup (OUT): same stale-bit scrub
old = "\tDOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;\n}\r\n\r\n/* push a chunk"
if old not in s:
    # try crlf variant
    old = "\tDOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;" + N + "}"
    new = ("\tDOEPCTL(0) = (DOEPCTL(0) & ~(DXEPCTL_EPDIS | DXEPCTL_SNAK |" + N +
           "\t\tDXEPCTL_STALL)) | DXEPCTL_EPENA | DXEPCTL_CNAK;" + N + "}")
    assert old in s, "arm_setup not found"
    s = s.replace(old, new, 1)

# ep0_status_in: scrub too
old = "\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK | (usb_dma ? 0 : DXEPCTL_SETD1PID);"
new = ("\tDIEPCTL(0) = (DIEPCTL(0) & ~(DXEPCTL_EPDIS | DXEPCTL_SNAK |" + N +
       "\t\tDXEPCTL_STALL)) | DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(usb_dma ? 0 : DXEPCTL_SETD1PID);")
assert old in s; s = s.replace(old, new, 1)

# ep1 probe + ep1_kick arms: scrub
old = "\tDIEPCTL(1) |= DXEPCTL_EPENA | DXEPCTL_CNAK;"
new = ("\tDIEPCTL(1) = (DIEPCTL(1) & ~(DXEPCTL_EPDIS | DXEPCTL_SNAK |" + N +
       "\t\tDXEPCTL_STALL)) | DXEPCTL_EPENA | DXEPCTL_CNAK;")
assert s.count(old) >= 1
s = s.replace(old, new)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
