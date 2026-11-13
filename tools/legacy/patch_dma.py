import io
p = "drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# 1) register defines: add DIEPDMA/DOEPDMA + GHWCFG2
old = "#define DTXFSTS(n)\tGREG(0x918 + (n) * 0x20)"
new = (old + N +
 "#define DIEPDMA(n)\tGREG(0x914 + (n) * 0x20)" + N +
 "#define DOEPDMA(n)\tGREG(0xB14 + (n) * 0x20)")
assert old in s; s = s.replace(old, new, 1)

# 2) dma buffers next to ep0_d1
old = "static int ep0_d1;"
new = (old + N +
 "/* This DWC2 may be a dedicated buffer-DMA core (trats only ever" + N +
 " * exercises it in DMA mode): setup packets still arrive via the" + N +
 " * RX fifo, but IN/OUT payloads are fetched from *DIEPDMA memory," + N +
 " * not from words pushed into the fifo port.  Feed BOTH paths so" + N +
 " * either architecture answers correctly.  phys==virt, dcache off. */" + N +
 "static uint8_t ep0_dma_in[64] __attribute__((aligned(32)));" + N +
 "static uint8_t ep0_dma_out[64] __attribute__((aligned(32)));" + N +
 "static uint8_t ep1_dma_buf[64] __attribute__((aligned(32)));")
assert old in s; s = s.replace(old, new, 1)

# 3) ep0_tx_start: write DIEPDMA before the fifo push
old = "\tDIEPTSIZ(0) = (1 << 19) | len;" + N + "\tfor (i = 0; i < words; i++) {"
new = ("\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
 "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
 "\tfor (i = 0; i < words; i++) {")
assert old in s; s = s.replace(old, new, 1)

# 4) ep0_status_in: program DIEPDMA for the ZLP
old = ("\tDIEPTSIZ(0) = (1 << 19) | 0;" + N +
 "\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK | DXEPCTL_SETD1PID;")
new = ("\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
 "\tDIEPTSIZ(0) = (1 << 19) | 0;" + N +
 "\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK | DXEPCTL_SETD1PID;")
assert old in s; s = s.replace(old, new, 1)

# 5) ep0_arm_setup: DOEPDMA scratch for OUT/status payloads
old = ("\tDOEPTSIZ(0) = (3 << 29) | (1 << 19) | (8 * 3);\t/* SUPCNT=3 */" + N +
 "\tDOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;")
new = ("\tDOEPDMA(0) = (uint32_t)ep0_dma_out;" + N +
 "\tDOEPTSIZ(0) = (3 << 29) | (1 << 19) | (8 * 3);\t/* SUPCNT=3 */" + N +
 "\tDOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;")
assert old in s; s = s.replace(old, new, 1)

# 6) DATA_OUT arm (SET_LINE_CODING): DOEPDMA for the 7-byte payload
old = ("\t\tep0_state = EP0_DATA_OUT;" + N +
 "\t\tDOEPTSIZ(0) = (1 << 19) | 7;" + N +
 "\t\tDOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;")
new = ("\t\tep0_state = EP0_DATA_OUT;" + N +
 "\t\tDOEPDMA(0) = (uint32_t)ep0_dma_out;" + N +
 "\t\tDOEPTSIZ(0) = (1 << 19) | 7;" + N +
 "\t\tDOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;")
assert old in s; s = s.replace(old, new, 1)

# 7) ep1_kick: dual-path for the bulk log channel
old = ("\tDIEPTSIZ(1) = (1 << 19) | n;" + N +
 "\tfor (unsigned int i = 0; i < (n + 3) / 4; i++) {")
new = ("\tmemcpy(ep1_dma_buf, pkt, n);" + N +
 "\tDIEPDMA(1) = (uint32_t)ep1_dma_buf;" + N +
 "\tDIEPTSIZ(1) = (1 << 19) | n;" + N +
 "\tfor (unsigned int i = 0; i < (n + 3) / 4; i++) {")
assert old in s; s = s.replace(old, new, 1)

# 8) GHWCFG2 define + hw dump
old = "#define GHWCFG4\t\tGREG(0x050)"
new = "#define GHWCFG2\t\tGREG(0x048)" + N + old
assert old in s; s = s.replace(old, new, 1)

old = 'printk(KERN_INFO, "usbcdc: hw ahb=%08x ghw4=%08x dcfg=%08x dctl=%08x\\n",' + N + '\t       GAHBCFG, GHWCFG4, DCFG, DCTL);'
new = 'printk(KERN_INFO, "usbcdc: hw ahb=%08x ghw2=%08x ghw4=%08x dctl=%08x\\n",' + N + '\t       GAHBCFG, GHWCFG2, GHWCFG4, DCTL);'
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("patched ok")
