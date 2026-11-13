# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

for line in ("\tDCTL |= DCTL_CGOUTNAK | DCTL_CGNPINNAK;" + N,
             "\tDCTL |= DCTL_PWRONPRGDONE;" + N,
             "\tGRSTCTL = GRSTCTL_INTKNQFLSH;" + N,
             "\tbounded_wait(&GRSTCTL, GRSTCTL_INTKNQFLSH, 0, 100000);" + N):
    assert line in s, line
    s = s.replace(line, "", 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
