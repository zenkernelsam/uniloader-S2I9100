# -*- coding: utf-8 -*-
import io
p = "/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"
s = io.open(p, encoding="utf-8", newline="").read()
N = "\r\n"

# add AHBIDLE waits inside the existing flush helpers (upstream waits
# for the ahb master to be idle around fifo flushes)
old = ("static void fifo_flush_rx(void)" + N +
"{" + N +
"\tGRSTCTL = GRSTCTL_RXFFLSH;" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_RXFFLSH, 0, 100000);" + N +
"}" + N +
N +
"static void fifo_flush_tx(unsigned int num)" + N +
"{" + N +
"\tGRSTCTL = GRSTCTL_TXFNUM(num) | GRSTCTL_TXFFLSH;" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_TXFFLSH, 0, 100000);" + N +
"}")
new = ("static void fifo_flush_rx(void)" + N +
"{" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_AHBIDLE, GRSTCTL_AHBIDLE, 100000);" + N +
"\tGRSTCTL = GRSTCTL_RXFFLSH;" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_RXFFLSH, 0, 100000);" + N +
"}" + N +
N +
"static void fifo_flush_tx(unsigned int num)" + N +
"{" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_AHBIDLE, GRSTCTL_AHBIDLE, 100000);" + N +
"\tGRSTCTL = GRSTCTL_TXFNUM(num) | GRSTCTL_TXFFLSH;" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_TXFFLSH, 0, 100000);" + N +
"\tbounded_wait(&GRSTCTL, GRSTCTL_AHBIDLE, GRSTCTL_AHBIDLE, 100000);" + N +
"}")
assert old in s; s = s.replace(old, new, 1)

# per-arm flush of the EP0 tx fifo before programming DMA, and read
# DIEPTSIZ back BEFORE EPENA so the photo can tell "pktcnt never
# latched" apart from "engine consumed it instantly".
old = ("\tdwc2_flush_txfifo(0);\t/* EP0-IN lives on the shared NPTX fifo */" + N +
 "\tmemcpy(ep0_dma_in, ep0_buf, len);")
if old not in s:
    old2 = ("\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
     "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
     "\tDIEPTSIZ(0) = (1 << 19) | len;")
    new2 = ("\tfifo_flush_tx(0);\t/* EP0-IN uses the shared NPTX fifo; upstream" + N +
     "\t * flushes the ep fifo before every DMA arm to drop stale state. */" + N +
     "\tmemcpy(ep0_dma_in, ep0_buf, len);" + N +
     "\tDIEPDMA(0) = (uint32_t)ep0_dma_in;" + N +
     "\tDIEPTSIZ(0) = (1 << 19) | len;" + N +
     "\ttsiz0 = DIEPTSIZ(0);")
    assert old2 in s; s = s.replace(old2, new2, 1)
    # declare tsiz0 at top of fn
    old3 = "\tunsigned int space = GNPTXSTS & 0xffff;"
    new3 = "\tunsigned int space = GNPTXSTS & 0xffff;\n\tunsigned int tsiz0;"
    assert old3 in s; s = s.replace(old3, new3, 1)
    # print both pre/post
    old4 = "\"ep0i: tx %uB sp%u tsiz%08x dma%08x dctl%08x\\n\","
    new4 = "\"ep0i: tx %uB sp%u tsiz%x>%x dma%08x dctl%08x\\n\","
    assert old4 in s; s = s.replace(old4, new4, 1)
    old5 = "len, space, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0));"
    new5 = "len, space, tsiz0, DIEPTSIZ(0), DIEPDMA(0), DIEPCTL(0));"
    assert old5 in s; s = s.replace(old5, new5, 1)

# same for ep1 bulk-in arming if it programs DIEPDMA(1)
old = "DIEPDMA(1) = (uint32_t)ep1_dma_buf;"
if old in s:
    s = s.replace(old,
        "fifo_flush_tx(1);\n\tDIEPDMA(1) = (uint32_t)ep1_dma_buf;", 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
