# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# defines: GHWCFG3 + DCTL.PWRONPRGDONE + just_setup flag
anchor = "#define GHWCFG4"
if anchor in s:
    i = s.find(anchor)
    s = s[:i] + "#define GHWCFG3\t\tGREG(0x04C)" + N + s[i:]

i = s.find("#define DCTL_SFTDISCON")
i = s.find(N, i) + len(N)
s = s[:i] + "#define DCTL_PWRONPRGDONE\t(1u << 11)" + N + s[i:]

i = s.find("static int usb_dma;")
j = s.find(N, i) + len(N)
s = s[:j] + "static int just_setup;\t/* s3c quirk: skip CNAK on the arm" + N + \
            "\t\t\t\t * right after a setup stage */" + N + s[j:]

# ep0_tx_start: linux order (tsiz then dma), skip CNAK after setup
old = ("\tfifo_flush_tx(0);\t/* EP0-IN uses the shared NPTX fifo; upstream" + N +
       "\t * flushes the ep fifo before every DMA arm to drop stale state. */" + N +
       "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
       "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
       "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
       "\ttsiz0 = DIEPTSIZ(0);")
new = ("\tfifo_flush_tx(0);\t/* EP0-IN uses the shared NPTX fifo; upstream" + N +
       "\t * flushes the ep fifo before every DMA arm to drop stale state. */" + N +
       "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
       "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
       "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
       "\ttsiz0 = DIEPTSIZ(0);")
assert old in s; s = s.replace(old, new, 1)

old = ("\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);")
new = ("\t/* s3c-hsotg: \"clearing the NAK here causes problems with" + N +
       "\t * transmit on the S3C6400 ending up with the TXFIFO becoming" + N +
       "\t * full\" - the arm right after a setup skips CNAK on this" + N +
       "\t * silicon family. */" + N +
       "\tDIEPCTL(0) |= DXEPCTL_EPENA |" + N +
       "\t\t(just_setup ? 0 : DXEPCTL_CNAK) |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);" + N +
       "\tjust_setup = 0;")
assert old in s; s = s.replace(old, new, 1)

# status-in arm keeps CNAK (it's not right-after-setup)
# STUP handler: flag + close the OUT side of the setup stage (CNAK)
old = ("\t\t\tif (usb_dma && (oi & DXEPINT_STUP)) {" + N +
       "\t\t\t\tmemcpy(setup_pkt, ep0_dma_out, 8);" + N +
       "\t\t\t\tep0_setup();" + N +
       "\t\t\t}")
new = ("\t\t\tif (usb_dma && (oi & DXEPINT_STUP)) {" + N +
       "\t\t\t\tmemcpy(setup_pkt, ep0_dma_out, 8);" + N +
       "\t\t\t\tjust_setup = 1;" + N +
       "\t\t\t\tDOEPCTL(0) |= DXEPCTL_CNAK;" + N +
       "\t\t\t\tep0_setup();" + N +
       "\t\t\t}")
assert old in s; s = s.replace(old, new, 1)

# dev_soft_init: PWRONPRGDONE + reset just_setup
old = "\tDCTL |= DCTL_CGOUTNAK | DCTL_CGNPINNAK;"
new = old + N + "\tDCTL |= DCTL_PWRONPRGDONE;" + N + "\tjust_setup = 0;"
assert old in s; s = s.replace(old, new, 1)

# hw line: add ghw3 (real dfifo depth)
old = "usbcdc: hw ahb=%08x ghw2=%08x ghw4=%08x dctl=%08x\\n\","
new = "usbcdc: hw ahb=%08x ghw2=%08x ghw3=%08x ghw4=%08x dctl=%08x\\n\","
assert old in s; s = s.replace(old, new, 1)
old = "GAHBCFG, GHWCFG2, GHWCFG4, DCTL);"
new = "GAHBCFG, GHWCFG2, GHWCFG3, GHWCFG4, DCTL);"
assert old in s; s = s.replace(old, new, 1)

# dedup the diepint flood: only print when the value changes
old = ("\t\t\tif (ei & DXEPINT_XFERCOMPL)" + N +
       "\t\t\t\tep0_in_done();" + N +
       "\t\t\telse if (ei)" + N +
       "\t\t\t\tprintk(KERN_INFO, \"ep0i: diepint %08x dma %08x\\n\"," + N +
       "\t\t\t\t       ei, DIEPDMA(0));")
new = ("\t\t\tif (ei & DXEPINT_XFERCOMPL)" + N +
       "\t\t\t\tep0_in_done();" + N +
       "\t\t\telse if (ei && ei != last_ei) {" + N +
       "\t\t\t\tlast_ei = ei;" + N +
       "\t\t\t\tprintk(KERN_INFO, \"ep0i: diepint %08x dma %08x\\n\"," + N +
       "\t\t\t\t       ei, DIEPDMA(0));" + N +
       "\t\t\t}")
assert old in s; s = s.replace(old, new, 1)

# declare last_ei
i = s.find("static int just_setup;")
j = s.find(N, i) + len(N)
s = s[:j] + "static uint32_t last_ei;" + N + s[j:]

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
