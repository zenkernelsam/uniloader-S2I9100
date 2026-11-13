# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# revert ep0_tx_start to u-boot setdma_tx order: diepdma -> dieptsiz
# -> diepctl, no per-arm flush.  On this core writing DIEPTSIZ while
# DIEPDMA still holds a stale pointer seems to trip the engine on the
# garbage descriptor and lock the endpoint (EPENA rejected, EPDISBLD).
old = ("\tfifo_flush_tx(0);\t/* EP0-IN uses the shared NPTX fifo; upstream" + N +
       "\t * flushes the ep fifo before every DMA arm to drop stale state. */" + N +
       "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
       "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
       "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
       "\ttsiz0 = DIEPTSIZ(0);")
new = ("\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
       "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
       "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
       "\ttsiz0 = DIEPTSIZ(0);")
assert old in s; s = s.replace(old, new, 1)

# absolute write -> back to |= so no latent field gets dropped
old = ("\t/* absolute write: |= can carry a stale EPDIS left by the" + N +
       "\t * init disable loop, which cancels the arm (EPENA dropped," + N +
       "\t * NAKSTS stuck - seen as diepint EPDISBLD on real hw). */" + N +
       "\tDIEPCTL(0) = DXEPCTL_USBACTEP | DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);" + N +
       "\tjust_setup = 0;")
new = ("\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);" + N +
       "\tjust_setup = 0;")
assert old in s; s = s.replace(old, new, 1)

# drop the DTHRCTL write - the register reads back 0x04000000 after a
# 0 write, so bits are RO/mixed; keep the read-only probe only
old = "\tDTHRCTL = 0;"
new = ""
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
