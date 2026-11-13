# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# GRSTCTL bit defines - next to existing GRSTCTL reg def if any; find a good anchor
anchor = "#define GINTMSK"  # ensure unique
i = s.find(anchor)
assert i > 0

old = "#define GRSTCTL"
if old not in s:
    # add GRSTCTL reg + bits block before GINTSTS def
    ins = ("#define GRSTCTL\t\t(DWC2_BASE + 0x010)" + N +
           "#define GRSTCTL_AHBIDLE\t\t(1u << 31)" + N +
           "#define GRSTCTL_TXFNUM(n)\t((n) << 6)" + N +
           "#define GRSTCTL_TXFNUM_ALL\t0x10" + N +
           "#define GRSTCTL_TXFFLSH\t\t(1u << 5)" + N +
           "#define GRSTCTL_RXFFLSH\t\t(1u << 4)" + N +
           "#define GRSTCTL_INTKNQFLSH\t(1u << 3)" + N +
           "#define GRSTCTL_CSFTRST\t\t(1u << 0)" + N)
    # insert before GINTSTS define
    j = s.find("#define GINTSTS")
    assert j > 0
    s = s[:j] + ins + s[j:]

# 1) flush helpers after ep0_d1 decl or near top utility funcs
helper = (N +
"static int dwc2_wait_ahbidle(void)" + N +
"{" + N +
"\tunsigned int t = 100000;" + N +
"\twhile (!(GRSTCTL & GRSTCTL_AHBIDLE) && --t)" + N +
"\t\tudelay(1);" + N +
"\treturn t ? 0 : -1;" + N +
"}" + N +
N +
"static void dwc2_flush_txfifo(unsigned int num)" + N +
"{" + N +
"\tunsigned int t = 100000;" + N +
"\tdwc2_wait_ahbidle();" + N +
"\tGRSTCTL = GRSTCTL_TXFNUM(num) | GRSTCTL_TXFFLSH;" + N +
"\twhile ((GRSTCTL & GRSTCTL_TXFFLSH) && --t)" + N +
"\t\tudelay(1);" + N +
"\tdwc2_wait_ahbidle();" + N +
"}" + N +
N +
"static void dwc2_flush_rxfifo(void)" + N +
"{" + N +
"\tunsigned int t = 100000;" + N +
"\tdwc2_wait_ahbidle();" + N +
"\tGRSTCTL = GRSTCTL_RXFFLSH;" + N +
"\twhile ((GRSTCTL & GRSTCTL_RXFFLSH) && --t)" + N +
"\t\tudelay(1);" + N +
"\tdwc2_wait_ahbidle();" + N +
"}" + N)
# insert helpers right before ep0_tx_start comment
k = s.find("/* push a chunk")
assert k > 0
s = s[:k] + helper + N + s[k:]

# 2) in ep0_tx_start: flush EP0 tx fifo before arming DMA (upstream setdma_tx order)
old = ("\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;")
new = ("\tdwc2_flush_txfifo(0);\t/* EP0-IN lives on the shared NPTX fifo */" + N +
 "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
 "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;")
assert old in s; s = s.replace(old, new, 1)

# 3) dev_soft_init: flush rx + all tx + token queue near its start
old = "\tDAINTMSK"
if old in s:
    j = s.find(old)
    s = s[:j] + ("\tdwc2_flush_rxfifo();" + N +
                 "\tGRSTCTL = GRSTCTL_INTKNQFLSH;" + N +
                 "\t{ unsigned int t = 100000; while ((GRSTCTL & GRSTCTL_INTKNQFLSH) && --t) udelay(1); }" + N +
                 "\tdwc2_flush_txfifo(GRSTCTL_TXFNUM_ALL);" + N) + s[j:]

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
