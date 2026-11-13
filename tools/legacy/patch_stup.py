# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# 1) usb_dma flag
old = "static int usb_ok;"
new = ("static int usb_ok;" + N +
 "static int usb_dma;\t/* GAHBCFG.DMA_EN: payloads + setup data move via" + N +
 "\t\t\t * DIEPDMA/DOEPDMA buffers, not the fifo port */")
assert old in s; s = s.replace(old, new, 1)

old = "#define DXEPINT_XFERCOMPL"
new = "#define DXEPINT_STUP\t\t(1u << 3)" + N + old
assert old in s; s = s.replace(old, new, 1)

# 2) OEPINT service: on STUP the setup bytes live in ep0_dma_out
old = ("\t\tuint32_t oi = DOEPINT(0);" + N +
 "\t\t\tDOEPINT(0) = oi;" + N +
 "\t\t\tif (oi)" + N +
 "\t\t\t\tprintk(KERN_INFO, \"ep0o: %08x\\n\", oi);")
new = (old + N +
 "\t\t\t/* internal-DMA core: setup bytes land in the DOEPDMA" + N +
 "\t\t\t * buffer, not the RX fifo - STUP is the only doorbell. */" + N +
 "\t\t\tif (usb_dma && (oi & DXEPINT_STUP)) {" + N +
 "\t\t\t\tmemcpy(setup_pkt, ep0_dma_out, 8);" + N +
 "\t\t\t\tep0_setup();" + N +
 "\t\t\t}")
assert old in s; s = s.replace(old, new, 1)

# 3) RXFLVL: in dma mode the fifo carries no setup data - drain but
#    don't decode, so stale/phantom entries can't re-run ep0_setup
old = ("\t\tif (ps == PKTSTS_SETUPRX) {" + N +
 "\t\t\t/* each GRXSTSP read POPS the fifo \u2014 two statements," + N +
 "\t\t\t * strict order, don't fold into one declaration */" + N +
 "\t\t\tuint32_t lo = GRXSTSP;" + N +
 "\t\t\tuint32_t hi = GRXSTSP;" + N +
 "\t\t\tmemcpy(setup_pkt, &lo, 4);" + N +
 "\t\t\tmemcpy(setup_pkt + 4, &hi, 4);" + N +
 "\t\t} else if (ps == PKTSTS_SETUPDONE) {" + N +
 "\t\t\tep0_setup();")
new = ("\t\tif (ps == PKTSTS_SETUPRX) {" + N +
 "\t\t\t/* each GRXSTSP read POPS the fifo \u2014 two statements," + N +
 "\t\t\t * strict order, don't fold into one declaration */" + N +
 "\t\t\tuint32_t lo = GRXSTSP;" + N +
 "\t\t\tuint32_t hi = GRXSTSP;" + N +
 "\t\t\tif (!usb_dma) {" + N +
 "\t\t\t\tmemcpy(setup_pkt, &lo, 4);" + N +
 "\t\t\t\tmemcpy(setup_pkt + 4, &hi, 4);" + N +
 "\t\t\t}" + N +
 "\t\t} else if (ps == PKTSTS_SETUPDONE) {" + N +
 "\t\t\tif (!usb_dma)" + N +
 "\t\t\t\tep0_setup();")
assert old in s; s = s.replace(old, new, 1)

# 4) latch usb_dma right after GAHBCFG is programmed
old = ("\tGAHBCFG = GAHBCFG_GLBL_INTR_EN | GAHBCFG_DMA_EN |" + N +
 "\t\t  GAHBCFG_HBSTLEN_INCR4 | GAHBCFG_NPTXEMPLVL |" + N +
 "\t\t  GAHBCFG_PTXEMPLVL;")
new = old + N + "\tusb_dma = (GAHBCFG & GAHBCFG_DMA_EN) != 0;"
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
