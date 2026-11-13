# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# In DMA mode the fifo push is not the data path at all - the pushed
# words just sit at the NPTX head and can confuse the engine's fill
# accounting.  Gate the push to non-DMA (slave) cores only.
old = ("\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
 "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
 "\tfor (i = 0; i < words; i++) {" + N +
 "\t\tmemcpy(&w, ep0_buf + i * 4, 4);" + N +
 "\t\tFIFO(0) = w;" + N +
 "\t}")
new = ("\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
 "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
 "\tif (!usb_dma) {" + N +
 "\t\tfor (i = 0; i < words; i++) {" + N +
 "\t\t\tmemcpy(&w, ep0_buf + i * 4, 4);" + N +
 "\t\t\tFIFO(0) = w;" + N +
 "\t\t}" + N +
 "\t}")
assert old in s; s = s.replace(old, new, 1)

# readback TSIZ+DMA in the tx line too
old = ("printk(KERN_INFO, \"ep0i: tx %uB sp%u>%u dctl%08x\\n\"," + N +
 "\t       len, space, GNPTXSTS & 0xffff, DIEPCTL(0));")
new = ("printk(KERN_INFO, \"ep0i: tx %uB sp%u tsiz%08x dma%08x dctl%08x\\n\"," + N +
 "\t       len, space, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0));")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
