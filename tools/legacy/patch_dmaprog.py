# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# upstream order for dma: DIEPDMA -> DIEPTSIZ -> DIEPCTL
old = ("\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
 "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
 "\tfor (i = 0; i < words; i++) {")
new = ("\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
 "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
 "\tfor (i = 0; i < words; i++) {")
assert old in s; s = s.replace(old, new, 1)

# DMA progress probe: while a DATA_IN transfer is armed, DIEPDMA is
# the engine's live fetch pointer - if it stays at ep0_dma_in the
# engine never ran; if it advanced the bytes really left on the wire.
old = ("\t\tif (d & 1) {" + N +
 "\t\t\tuint32_t ei = DIEPINT(0);" + N +
 "\t\t\tDIEPINT(0) = ei;" + N +
 "\t\t\tif (ei & DXEPINT_XFERCOMPL)" + N +
 "\t\t\t\tep0_in_done();" + N +
 "\t\t}")
new = ("\t\tif (d & 1) {" + N +
 "\t\t\tuint32_t ei = DIEPINT(0);" + N +
 "\t\t\tDIEPINT(0) = ei;" + N +
 "\t\t\tif (ei & DXEPINT_XFERCOMPL)" + N +
 "\t\t\t\tep0_in_done();" + N +
 "\t\t\telse if (ei)" + N +
 "\t\t\t\tprintk(KERN_INFO, \"ep0i: diepint %08x dma %08x\\n\"," + N +
 "\t\t\t\t       ei, DIEPDMA(0));" + N +
 "\t\t}")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
