# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# DTHRCTL define (device threshold control - TX thresholding can gate
# the DMA fetch on dedicated-fifo cores)
i = s.find("#define DCTL\t\tDREG(0x004)")
assert i > 0
j = s.find(N, i) + len(N)
s = s[:j] + "#define DTHRCTL\t\tDREG(0x030)" + N + s[j:]

# dev_soft_init: zero DTHRCTL too
old = "\tDCTL |= DCTL_PWRONPRGDONE;"
new = "\tDCTL |= DCTL_PWRONPRGDONE;" + N + "\tDTHRCTL = 0;"
assert old in s; s = s.replace(old, new, 1)

# ep0_tx_start: absolute control write, CNAK always, no stale bits
old = ("\t/* s3c-hsotg: \"clearing the NAK here causes problems with" + N +
       "\t * transmit on the S3C6400 ending up with the TXFIFO becoming" + N +
       "\t * full\" - the arm right after a setup skips CNAK on this" + N +
       "\t * silicon family. */" + N +
       "\tDIEPCTL(0) |= DXEPCTL_EPENA |" + N +
       "\t\t(just_setup ? 0 : DXEPCTL_CNAK) |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);" + N +
       "\tjust_setup = 0;")
new = ("\t/* absolute write: |= can carry a stale EPDIS left by the" + N +
       "\t * init disable loop, which cancels the arm (EPENA dropped," + N +
       "\t * NAKSTS stuck - seen as diepint EPDISBLD on real hw). */" + N +
       "\tDIEPCTL(0) = DXEPCTL_USBACTEP | DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);" + N +
       "\tjust_setup = 0;")
assert old in s; s = s.replace(old, new, 1)

# tx print: add DTHRCTL + GNPTXSTS queue field
old = "\"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x\\n\","
new = "\"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x thr%08x\\n\","
assert old in s; s = s.replace(old, new, 1)
old = "len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0));"
new = "len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0), DTHRCTL);"
assert old in s; s = s.replace(old, new, 1)

# hw print: add dthrctl
old = "usbcdc: hw ahb=%08x ghw2=%08x ghw3=%08x ghw4=%08x dctl=%08x\\n\","
new = "usbcdc: hw ahb=%08x ghw2=%08x ghw3=%08x ghw4=%08x dctl=%08x thr=%08x\\n\","
assert old in s; s = s.replace(old, new, 1)
old = "GAHBCFG, GHWCFG2, GHWCFG3, GHWCFG4, DCTL);"
new = "GAHBCFG, GHWCFG2, GHWCFG3, GHWCFG4, DCTL, DTHRCTL);"
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
