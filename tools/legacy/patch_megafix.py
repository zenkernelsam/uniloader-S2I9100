# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# --- register bit defines ---
ins = ("#define DXEPINT_B2BSTUP\t\t(1u << 6)\t/* OUT: back-to-back setup */" + N +
       "#define DXEPINT_STSPHSERCVD\t(1u << 5)\t/* OUT: setup phase done */" + N +
       "#define DXEPINT_OUTTKNEPDIS\t(1u << 4)\t/* OUT: token while dis */" + N +
       "#define DXEPINT_INTKNTXFEMP\t(1u << 4)\t/* IN: token while empty */" + N +
       "#define GRSTCTL_INTKNQFLSH\t(1u << 3)" + N +
       "#define DCTL_CGOUTNAK\t\t(1u << 10)" + N +
       "#define DCTL_CGNPINNAK\t\t(1u << 8)" + N)
anchor = "#define DCTL_SFTDISCON\t\t(1u << 1)"
i = s.find(anchor) + len(anchor)
s = s[:i] + N + ins + s[i:]

# --- dev_soft_init: wider endpoint masks, token-queue flush, clear global NAKs
old = ("\tDIEPMSK = (1 << 3) | (1 << 2) | (1 << 0);\t/* timeout|ahberr|xfcompl */" + N +
       "\tDOEPMSK = (1 << 3) | (1 << 2) | (1 << 0);")
new = ("\tDIEPMSK = (1 << 4) | (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0);" + N +
       "\tDOEPMSK = (1 << 6) | (1 << 5) | (1 << 4) | (1 << 3) | (1 << 2) | (1 << 0);")
assert old in s; s = s.replace(old, new, 1)

old = ("\tfifo_flush_rx();" + N +
       "\tfifo_flush_tx(0x10);")
new = ("\tfifo_flush_rx();" + N +
       "\tfifo_flush_tx(0x10);" + N +
       "\tGRSTCTL = GRSTCTL_INTKNQFLSH;" + N +
       "\tbounded_wait(&GRSTCTL, GRSTCTL_INTKNQFLSH, 0, 100000);" + N +
       "\tDCTL |= DCTL_CGOUTNAK | DCTL_CGNPINNAK;")
assert old in s; s = s.replace(old, new, 1)

# --- SETD1PID only in slave mode; in BUF_DMA the engine owns the pid
old = "\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK | DXEPCTL_SETD1PID;"
new = "\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK | (usb_dma ? 0 : DXEPCTL_SETD1PID);"
assert old in s; s = s.replace(old, new, 1)

old = ("\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 ? DXEPCTL_SETD1PID : 0);")
new = ("\tDIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK |" + N +
       "\t\t(ep0_d1 && !usb_dma ? DXEPCTL_SETD1PID : 0);")
assert old in s; s = s.replace(old, new, 1)

# --- OEPINT handler: on B2BSTUP/STSPHSERCVD re-arm OUT EP0 for next setup
old = ("\t\t\tif (usb_dma && (oi & DXEPINT_STUP)) {" + N +
       "\t\t\t\tmemcpy(setup_pkt, ep0_dma_out, 8);" + N +
       "\t\t\t\tep0_setup();" + N +
       "\t\t\t}")
new = ("\t\t\tif (usb_dma && (oi & DXEPINT_STUP)) {" + N +
       "\t\t\t\tmemcpy(setup_pkt, ep0_dma_out, 8);" + N +
       "\t\t\t\tep0_setup();" + N +
       "\t\t\t}" + N +
       "\t\t\tif (usb_dma && (oi & (DXEPINT_B2BSTUP |" + N +
       "\t\t\t\t      DXEPINT_STSPHSERCVD)))" + N +
       "\t\t\t\tep0_arm_setup();")
assert old in s; s = s.replace(old, new, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
