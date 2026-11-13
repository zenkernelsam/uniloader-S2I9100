# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# EP1-IN DMA probe: arm a real endpoint+transfer during init.  The
# prefetch needs no host - if the engine runs, DTXFSTS(1)/DIEPDMA(1)
# move.  Separates "EP0-specific gate" from "IN-DMA dead globally".
anchor = "\tdev_soft_init();" + N + N + "\t/* One-shot connect"
old = anchor
new = ("\tdev_soft_init();" + N + N +
       "\t/* IN-DMA probe on EP1 (dedicated fifo1, no NPTX collision):" + N +
       "\t * configure it exactly like SET_CONFIGURATION would, then arm" + N +
       "\t * one DMA transfer.  Prefetch needs no host traffic; if the" + N +
       "\t * engine runs at all, DTXFSTS(1)/DIEPDMA(1) will move. */" + N +
       "\tDIEPCTL(1) = DXEPCTL_USBACTEP | DXEPCTL_EPTYPE(2) |" + N +
       "\t\t(1 << 22) | DXEPCTL_MPS(64) | DXEPCTL_SNAK;" + N +
       "\tmemset(ep1_dma_buf, 0xA5, sizeof(ep1_dma_buf));" + N +
       "\tDIEPDMA(1) = (uint32_t)ep1_dma_buf;" + N +
       "\tDIEPTSIZ(1) = (1 << 19) | 16;" + N +
       "\tDIEPCTL(1) |= DXEPCTL_EPENA | DXEPCTL_CNAK;" + N + N +
       "\t/* One-shot connect")
assert old in s; s = s.replace(old, new, 1)

# heartbeat: add EP1 probe telemetry + raw DIEPINT(0)
old = ("\t\t\tprintk(KERN_INFO, \"usbcdc: poll i=%d gints=%08x st%d dma%08x\\n\"," + N +
       "\t\t\t       i, GINTSTS, ep0_state, DIEPDMA(0));")
new = ("\t\t\tprintk(KERN_INFO, \"usbcdc: poll i=%d gints=%08x st%d dma%08x\\n\"" + N +
       "\t\t\t\t\"  i0=%08x d1=%08x f1=%04x i1=%08x\\n\"," + N +
       "\t\t\t       i, GINTSTS, ep0_state, DIEPDMA(0)," + N +
       "\t\t\t       DIEPINT(0), DIEPDMA(1), DTXFSTS(1) & 0xffff, DIEPINT(1));")
assert old in s; s = s.replace(old, new, 1)

# tx line: add OUT-side snapshot + DAINT for one-photo context
old = ("\tprintk(KERN_INFO, \"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x thr%08x\\n\"," + N +
       "\t       len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0), DTHRCTL);")
new = ("\tprintk(KERN_INFO, \"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x\\n\"" + N +
       "\t\t\"  octl%08x otsiz%08x odma%08x daint%08x\\n\"," + N +
       "\t       len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0)," + N +
       "\t       DOEPCTL(0), DOEPTSIZ(0), DOEPDMA(0), DAINT);")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
