# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# move GAHBCFG right after CSFTRST (upstream sets the bus mode before
# touching fifo maps/endpoints)
old = ("\tGRSTCTL = GRSTCTL_CSFTRST;" + N +
       "\tif (bounded_wait(&GRSTCTL, GRSTCTL_CSFTRST, 0, 100000))" + N +
       "\t\treturn -3;")
new = (old + N + N +
       "\t/* GHWCFG2 arch = internal dedicated DMA (0x228ffc50" + N +
       "\t * bits[4:3]=2): slave-mode TX cannot deliver a payload, the" + N +
       "\t * engine only runs with DMA_EN set.  Upstream arms the bus" + N +
       "\t * mode right after the core reset, before any fifo/EP cfg. */" + N +
       "\tGAHBCFG = GAHBCFG_GLBL_INTR_EN | GAHBCFG_DMA_EN |" + N +
       "\t\t  GAHBCFG_HBSTLEN_INCR4 | GAHBCFG_NPTXEMPLVL |" + N +
       "\t\t  GAHBCFG_PTXEMPLVL;")
assert old in s; s = s.replace(old, new, 1)

# drop the old late GAHBCFG write
old = ("\t/* GHWCFG2 arch = internal dedicated DMA (0x228ffc50" + N +
       "\t * bits[4:3]=2): slave-mode TX cannot deliver a payload, the" + N +
       "\t * engine only runs with DMA_EN set.  Setups still arrive via" + N +
       "\t * the RX fifo either way. */" + N +
       "\tGAHBCFG = GAHBCFG_GLBL_INTR_EN | GAHBCFG_DMA_EN |" + N +
       "\t\t  GAHBCFG_HBSTLEN_INCR4 | GAHBCFG_NPTXEMPLVL |" + N +
       "\t\t  GAHBCFG_PTXEMPLVL;" + N +
       "\tusb_dma = (GAHBCFG & GAHBCFG_DMA_EN) != 0;")
new = "\tusb_dma = (GAHBCFG & GAHBCFG_DMA_EN) != 0;"
assert old in s; s = s.replace(old, new, 1)

# re-arm OUT EP0 after a stall so the next setup still lands
old = ("\tDIEPCTL(0) |= DXEPCTL_STALL;" + N +
       "\tDOEPCTL(0) |= DXEPCTL_STALL;" + N +
       "\tep0_state = EP0_WAIT_SETUP;")
new = (old + N +
       "\tep0_arm_setup();")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
