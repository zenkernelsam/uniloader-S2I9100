# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# SETD1PID in DMA mode too - the first data-stage packet must be
# DATA1 regardless of how the payload reaches the fifo.  This old
# core clearly does not manage the toggle itself (host ACKed the
# 18-byte reply then re-issued the identical request - classic
# DATA0-where-DATA1-was-required rejection).
old = "(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);"
new = "(ep0_d1 ? DXEPCTL_SETD1PID : 0);"
assert old in s; s = s.replace(old, new, 1)

# status-IN: DATA1 always
old = "(usb_dma ? 0 : DXEPCTL_SETD1PID);"
new = "DXEPCTL_SETD1PID;"
assert old in s; s = s.replace(old, new, 1)

# tx line: prove the buffer contents the engine will fetch
old = ("printk(KERN_INFO, \"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x\\n\"" + N +
       "\t\t\"  octl%08x otsiz%08x odma%08x daint%08x\\n\",")
new = ("printk(KERN_INFO, \"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x\\n\"" + N +
       "\t\t\"  buf%08x octl%08x otsiz%08x odma%08x daint%08x\\n\",")
assert old in s; s = s.replace(old, new, 1)
old = ("\t       len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0)," + N +
       "\t       DOEPCTL(0), DOEPTSIZ(0), DOEPDMA(0), DAINT);")
new = ("\t       len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0)," + N +
       "\t       *(volatile uint32_t *)ep0_dma_in," + N +
       "\t       DOEPCTL(0), DOEPTSIZ(0), DOEPDMA(0), DAINT);")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
