# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

old = ("printk(KERN_INFO, \"usbcdc: poll i=%d gints=%08x\\n\",")
new = ("printk(KERN_INFO, \"usbcdc: poll i=%d gints=%08x st%d dma%08x\\n\",")
assert old in s; s = s.replace(old, new, 1)

old = "i, GINTSTS);"
new = "i, GINTSTS, ep0_state, DIEPDMA(0));"
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
