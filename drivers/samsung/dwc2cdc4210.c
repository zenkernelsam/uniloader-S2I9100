// SPDX-License-Identifier: GPL-2.0-only
/*
 * Polling-mode CDC ACM gadget for the Exynos 4210 DWC2 OTG device
 * controller (@0x12480000).  Goal: a plain microUSB data cable shows up
 * as a COM/ttyACM port on the host PC and streams uniLoader printk
 * output - the "no UART jig" debug channel, same niche the lilac
 * project's QcomXnuUsbDebug fills.
 *
 * Register/sequence reference: REVERSED from GT-I9100 S-Boot (SBL2,
 * assets/sbl2.bin @0x4d400000) — the production Odin download stack
 * that provably enumerates on this silicon.  See
 * research/SBOOT-DWC2-REVERSE.md for the full decode.
 *
 * Design: pure polled SLAVE mode (GAHBCFG=1, DMA_EN=0) exactly like
 * the working EP0 path arms replies at setup-decode time and pushes
 * their payloads word-by-word into DFIFO0. Setup payloads use the
 * GRXSTSP status port + DFIFO0 data port.  EP0-OUT is re-armed for
 * setup unconditionally on every OUT-EP0 event.  usbcdc_poll()
 * services USBRST/ENUMDONE/RXFLVL/IEPINT/OEPINT and drains the TX
 * ring; every wait is bounded so a missing controller can never hang
 * the boot (QEMU smdkc210 has no OTG model: the GSNPSID check bails).
 */

#include <stdint.h>
#include <string.h>
#include <lib/debug.h>
#include <lib/console.h>

/* Base addresses are overridable so the same logic can run under a
 * host-side register simulator (tools/usbcdc_sim.c) — the EP0 state
 * machine is testable without silicon. */
#ifndef DWC2_BASE
#define DWC2_BASE	0x12480000
#endif
#ifndef PHY_BASE
#define PHY_BASE	0x125B0000
#endif
#ifndef PMU_USBPHYCTRL
#define PMU_USBPHYCTRL	0x10020704	/* USB_PHY_CONTROL, bit0 = EN0 */
#endif
#ifndef CMU_GATE_IP_FSYS
#define CMU_GATE_IP_FSYS	(*(volatile uint32_t *)(0x10030000 + 0xC940))
#endif
#define GATE_FSYS_USB_DEVICE	(1u << 13)	/* clk-exynos4: usb_device */

#define GREG(x)		(*(volatile uint32_t *)(DWC2_BASE + (x)))
#define GOTGCTL		GREG(0x000)
#define GAHBCFG		GREG(0x008)
#define GAHBCFG_GLBL_INTR_EN	(1u << 0)
#define GAHBCFG_HBSTLEN_INCR4	(3u << 1)
#define GAHBCFG_DMA_EN		(1u << 5)
#define GAHBCFG_NPTXEMPLVL	(1u << 7)
#define GAHBCFG_PTXEMPLVL	(1u << 8)
#define GUSBCFG		GREG(0x00C)
#define GRSTCTL		GREG(0x010)
#define GINTSTS		GREG(0x014)
#define GINTMSK		GREG(0x018)
#define GRXSTSP		GREG(0x020)
#define GRXFSIZ		GREG(0x024)
#define GNPTXFSIZ	GREG(0x028)
#define GNPTXSTS	GREG(0x02C)
#define GSNPSID		GREG(0x040)
#define GHWCFG2		GREG(0x048)
#define GHWCFG3		GREG(0x04C)
#define GHWCFG4		GREG(0x050)
#define DPTXFSIZ(n)	GREG(0x104 + ((n) - 1) * 4)

#define DREG(x)		GREG(0x800 + (x))
#define DCFG		DREG(0x000)
#define DCTL		DREG(0x004)
#define DTHRCTL		DREG(0x030)
#define DSTS		DREG(0x008)
#define DIEPMSK		DREG(0x010)
#define DOEPMSK		DREG(0x014)
#define DAINT		DREG(0x018)
#define DAINTMSK	DREG(0x01C)

#define IEP(n)		GREG(0x900 + (n) * 0x20)
#define OEP(n)		GREG(0xB00 + (n) * 0x20)
#define DIEPCTL(n)	IEP(n)
#define DIEPINT(n)	GREG(0x908 + (n) * 0x20)
#define DIEPTSIZ(n)	GREG(0x910 + (n) * 0x20)
#define DOEPCTL(n)	OEP(n)
#define DOEPINT(n)	GREG(0xB08 + (n) * 0x20)
#define DOEPTSIZ(n)	GREG(0xB10 + (n) * 0x20)
#define DTXFSTS(n)	GREG(0x918 + (n) * 0x20)
#define DIEPDMA(n)	GREG(0x914 + (n) * 0x20)
#define DOEPDMA(n)	GREG(0xB14 + (n) * 0x20)	/* INEPTFSPC per EP */

#define PCGCCTL		GREG(0xE00)
#ifndef FIFO
#define FIFO(n)		(*(volatile uint32_t *)(DWC2_BASE + 0x1000 + (n) * 0x1000))
#endif
/* RX payload pop port — same DFIFO register on silicon, split in the
 * sim so the host can inject setup bytes independent of TX pushes. */
#ifndef FIFO_RD
#define FIFO_RD(n)	FIFO(n)
#endif

#define PHYREG(x)	(*(volatile uint32_t *)(PHY_BASE + (x)))
#define PHYPWR		PHYREG(0x00)
#define PHYCLK		PHYREG(0x04)
#define PHYRST		PHYREG(0x08)
#define PHYTUNE		PHYREG(0x24)

/* bit names used (subset of dwc2_core.h) */
#define GRSTCTL_AHBIDLE		(1u << 31)
#define GRSTCTL_TXFNUM(x)	((x) << 6)
#define GRSTCTL_TXFNUM_ALL	(0x10 << 6)
#define GRSTCTL_TXFFLSH		(1u << 5)
#define GRSTCTL_RXFFLSH		(1u << 4)
#define GRSTCTL_CSFTRST		(1u << 0)

#define GINTSTS_WKUPINT		(1u << 31)
#define GINTSTS_OEPINT		(1u << 19)
#define GINTSTS_IEPINT		(1u << 18)
#define GINTSTS_ENUMDONE	(1u << 13)
#define GINTSTS_USBRST		(1u << 12)
#define GINTSTS_RXFLVL		(1u << 4)

#define DXEPCTL_EPENA		(1u << 31)
#define DXEPCTL_EPDIS		(1u << 30)
#define DXEPCTL_SETD1PID	(1u << 29)
#define DXEPCTL_SETD0PID	(1u << 28)
#define DXEPCTL_SNAK		(1u << 27)
#define DXEPCTL_CNAK		(1u << 26)
#define DXEPCTL_STALL		(1u << 21)
#define DXEPCTL_EPTYPE(x)	((x) << 18)	/* 0 ctl 1 isoc 2 bulk 3 int */
#define DXEPCTL_USBACTEP	(1u << 15)
#define DXEPCTL_MPS(x)		((x) & 0x7ff)

#define DXEPINT_STUP		(1u << 3)
#define DXEPINT_XFERCOMPL	(1u << 0)
#define DXEPINT_TIMEOUT		(1u << 3)	/* IN: timeout / OUT: setup */
#define DXEPINT_AHBERR		(1u << 2)
#define DXEPINT_EPDISBLD	(1u << 1)

#define DCTL_SFTDISCON		(1u << 1)
#define DXEPINT_B2BSTUP		(1u << 6)	/* OUT: back-to-back setup */
#define DXEPINT_STSPHSERCVD	(1u << 5)	/* OUT: setup phase done */
#define DXEPINT_INTKNTXFEMP	(1u << 4)	/* IN: token while empty */


#define GRXSTS_PKTSTS(x)	(((x) >> 17) & 0xf)
#define GRXSTS_BYTECNT(x)	(((x) >> 4) & 0x7ff)
#define GRXSTS_EPNUM(x)		((x) & 0xf)

#define PKTSTS_OUTRX		2
#define PKTSTS_OUTDONE		3
#define PKTSTS_SETUPDONE	4
#define PKTSTS_SETUPRX		6

/* Slave FIFO map: RX 512 words @0, EP0 TX 256 @512, EP1 TX 384 @768. */
#define RXF_WORDS	0x200
#define NPTX_WORDS	0x100
#define NPTX_OFF	0x200
/* GHWCFG4.DED_FIFO_EN=1: every non-control IN endpoint owns a TX fifo.
 * S-Boot never needed this because its Odin EP1-IN ran on DMA.  Total
 * 0x200+0x100+0x180 = 0x480 words, under GHWCFG3 dfifo depth 0x4e8. */
#define EP1TX_WORDS	0x180
#define EP1TX_OFF	(NPTX_OFF + NPTX_WORDS)

/* GINTMSK runtime values from S-Boot's dispatcher (0x4d41bf58):
 * 0x800c3810 = WKUP|OEP|IEP|ENUMDONE|USBRST|RXFLVL; RXFLVL is masked
 * off (0x800c3800) while the fifo is being popped. */
#define GINTMSK_RUN		0x800c3810u
#define GINTMSK_RXMASK		0x800c3800u

/* EP0 arm values, s3c-hsotg style (the working Exynos 4210 driver):
 * USBACTEP is called RO in the databook but must be written for EP0 to
 * activate, and EPENA is set when the reply is staged — never deferred
 * to INTKNTXFEMP, which cannot fire on a disabled endpoint.  EP0's MPS
 * field encodes 64B as 0, so the low bits stay clear. */
#define EP0_ACT			0x00008000u	/* USBACTEP */
#define EP0_ARM_TX		0x84008000u	/* EPENA|CNAK|USBACTEP */
#define EP0_ARM_ZLP		0x84008000u
#define EP0_OUT_ARM		0x84008000u
#define EP0_OUT_TSIZ		0x20080008u	/* SUPCNT1|PKTCNT1|8B */

/* ---------------- usb descriptors ---------------- */

static const uint8_t dev_desc[] = {
	18, 1,			/* bLength, DEVICE */
	0x00, 0x02,		/* bcdUSB 2.0 */
	2, 0, 0,		/* class CDC, sub/proto 0 */
	64,			/* MPS */
	0x25, 0x05,		/* VID 0x0525 (NetChip, gadget customary) */
	0xa7, 0xa4,		/* PID 0xa4a7 (linux cdc-acm gadget) */
	0x01, 0x00,		/* bcdDevice 0.01 */
	1, 2, 3,		/* iMan, iProd, iSerial */
	1
};

static uint8_t cfg_desc[] = {
	9, 2, 67, 0, 2, 1, 0, 0x80, 250 >> 1,	/* cfg hdr, 2 ifaces, bus-pow 500mA? (fa=125*2) */
	/* iface0: CDC comm */
	9, 4, 0, 0, 1, 2, 2, 1, 0,
	/* header functional */
	5, 0x24, 0, 0x10, 0x01,
	/* call mgmt functional */
	5, 0x24, 1, 0, 1,
	/* ACM functional */
	4, 0x24, 2, 0x02,
	/* union functional */
	5, 0x24, 6, 0, 1,
	/* EP2 IN interrupt (never serviced) */
	7, 5, 0x82, 3, 8, 0, 16,
	/* iface1: CDC data */
	9, 4, 1, 0, 2, 10, 0, 0, 0,
	/* EP1 IN bulk */
	7, 5, 0x81, 2, 64, 0, 0,
	/* EP1 OUT bulk */
	7, 5, 0x01, 2, 64, 0, 0,
};

/* bcdUSB 2.0 device at HIGH speed: the spec REQUIRES answering
 * GET_DESCRIPTOR(QUALIFIER) — a stall tells Windows "illegal device".
 * Reports what we'd be at full speed; body mirrors the fs config. */
static const uint8_t qual_desc[] = {
	10, 6,			/* bLength, DEVICE_QUALIFIER */
	0x00, 0x02,		/* bcdUSB 2.0 */
	2, 0, 0,		/* class CDC */
	64,			/* MPS */
	1, 0			/* bNumConfigurations, reserved */
};

static const uint8_t str0[] = { 4, 3, 0x09, 0x04 };
static const uint8_t str1[] = {
	32, 3, 'i',0,'9',0,'1',0,'0',0,'0',0,' ',0,
	'u',0,'n',0,'i',0,'L',0,'o',0,'a',0,'d',0,'e',0,'r',0
};
static const uint8_t str2[] = {
	24, 3, 'U',0,'S',0,'B',0,' ',0,'C',0,'D',0,'C',0,' ',0,
	'L',0,'O',0,'G',0
};
static const uint8_t str3[] = {
	24, 3, 'S',0,'2',0,'I',0,'9',0,'1',0,'0',0,'0',0,'-',0,
	'O',0,'S',0,'6',0
};

/* ---------------- state ---------------- */

static int usb_ok;
static int enumerated;		/* ENUMDONE seen */
static int configured;		/* SET_CONFIGURATION seen */
static unsigned int bulk_mps = 64;
static int host_open;		/* SET_CONTROL_LINE_STATE seen (port open) */
static int ep1_busy;		/* IN transfer in flight on EP1 */
static int ep1_dbg;		/* one-shot DTXFSTS probe */
static int ep1_intdbg;		/* first N distinct EP1 interrupt states */
static int ep1_compldbg;		/* completion has its own print budget */
static uint32_t ep1_lastint;
static int in_poll;		/* reentrancy guard: printk inside a
				   handler triggers usbcon_write ->
				   usbcdc_poll; nested polls must
				   return immediately */

/* Setup stages a reply; ep0_commit() arms it before leaving the decoder. */
enum { REQ_NONE, REQ_DATA, REQ_ZLP, REQ_OUT } ep0_req;
static const uint8_t *ep0_ptr;	/* pending TX payload */
static unsigned int ep0_plen;	/* pending TX byte count */
static uint8_t setup_pkt[8];

#define TXRING 16384
static char txring[TXRING];
static volatile unsigned int tx_head, tx_tail;

/* ---------------- helpers ---------------- */

static void udelay(unsigned int us)
{
	/* ~1.2GHz A9: rough spin; bounded so it can never hang */
	volatile unsigned int i;

	while (us--) {
		for (i = 0; i < 400; i++)
			__asm__ __volatile__("nop");
	}
}

static int bounded_wait(volatile uint32_t *reg, uint32_t mask,
			uint32_t val, unsigned int tries)
{
	while (tries--) {
		if ((*reg & mask) == val)
			return 0;
		udelay(1);
	}
	return -1;
}

static void phy_init(void)
{
	/* otg_phy_init(), c210/universal flavour (PHY0_SLEEP path) */
	*(volatile uint32_t *)PMU_USBPHYCTRL |= 1;	/* USB_PHY_CTRL_EN0 */

	/* S-Boot 量产真值：PHYPWR/PHYCLK/RSTCON/PHYTUNE 全部绝对值盖章，
	 * sbl2.bin 0x4d416860 反汇编实录。 */
	PHYPWR = 0x1f80;
	PHYCLK = 3;
	PHYRST = 1;
	udelay(20000);
	PHYRST = 0;
	udelay(20000);
	PHYTUNE = 0x001819bb;
}

static void ep0_out_rearm(void);

/* S-Boot 0x4d41b9f0 + 0x4d41b228: full device re-init, run on every
 * USBRST so each enumeration attempt starts from the same clean
 * endpoint state. */
static void dev_soft_init(void)
{
	int i;

	DCFG = (1 << 18);		/* EPMISCNT=1, DEVSPD=HS */
	/* NOTE: no SFTDISCON pulse here — dev_soft_init also runs on the
	 * USBRST path, where disconnecting would re-trigger enumeration
	 * forever.  The one-shot pulse lives in usbcdc4210_init(). */

	/* Deliberately no EPDIS loop and no FIFO flushes here: S-Boot's
	 * USBRST handler (0x4d41b9f0) does neither, and this core's RX
	 * fifo goes deaf if it is flushed while the device is live (the
	 * status word still arrives, but the payload never lands where
	 * DFIFO reads can see it).  CSRST at init already flushed. */

	/* S-Boot: SNAK every OUT ep, then EPENA|CNAK every OUT ep. */
	for (i = 0; i < 4; i++)
		DOEPCTL(i) |= DXEPCTL_SNAK;

	/* S-Boot mask values: IN EP0/EP1 + OUT EP0/EP2 (0x00050003); we
	 * need EP1-OUT instead of EP2-OUT → IN{0,1} + OUT{0,1}. */
	DAINTMSK = (1 << 17) | (1 << 16) | (1 << 1) | (1 << 0);
	DOEPMSK = 13;	/* XFRC|AHBERR|STUP — S-Boot exact */
	DIEPMSK = 29;	/* XFRC|AHBERR|TIMEOUT|INTKNTXFEMP (not EPDISBLD) */

	GRXFSIZ = RXF_WORDS;
	GNPTXFSIZ = (NPTX_WORDS << 16) | NPTX_OFF;
	/* EP1's dedicated TX fifo; without it its slave pushes vanish. */
	DPTXFSIZ(1) = (EP1TX_WORDS << 16) | EP1TX_OFF;

	for (i = 0; i < 4; i++)
		DOEPCTL(i) |= DXEPCTL_EPENA | DXEPCTL_CNAK;
	DCFG &= ~0x7f0u;			/* DEVADDR=0 */

	/* S-Boot 0x4d41b228: clear ep ints, EP0-IN CNAK, EP0-OUT armed */
	DIEPINT(0) = 0x3ff;
	DIEPINT(1) = 0x3ff;
	DOEPINT(0) = 0x3ff;
	DOEPINT(1) = 0x3ff;
	/* Activate EP0-IN without arming a transfer (s3c-hsotg:
	 * "enable, but don't activate EP0in" writes mps|USBACTEP).  An
	 * absolute CNAK write here would wipe USBACTEP, leaving every
	 * later arm inert. */
	DIEPCTL(0) = EP0_ACT;
	ep0_out_rearm();

	GINTMSK = GINTMSK_RUN;

	ep0_req = REQ_NONE;
	ep0_ptr = 0;
	ep0_plen = 0;
	ep1_busy = 0;
	ep1_dbg = ep1_intdbg = ep1_compldbg = 0;
	ep1_lastint = 0;
	configured = 0;
	host_open = 0;
}

/* S-Boot 0x4d41bd1c tail: EP0-OUT is re-armed for the next setup on
 * EVERY OUT-EP0 event — no state check, no conditions. */
static void ep0_out_rearm(void)
{
	DOEPTSIZ(0) = EP0_OUT_TSIZ;
	DOEPCTL(0) = EP0_OUT_ARM;
}

/* Stage one control-IN transfer: arm EPENA FIRST, then push the whole
 * payload into DFIFO0.  Max control data here is 67B (17 words), far
 * below the 512-word NPTX fifo, so S-Boot's per-64B-packet pacing loop
 * (which only exists for Odin's multi-KB descriptors) is unnecessary. */
static void ep0_send(const uint8_t *buf, unsigned int len)
{
	unsigned int npackets = (len + 63) >> 6;
	unsigned int words = (len + 3) >> 2;
	unsigned int i;

	if (words) {
		/* Shared NPTX fifo: wait for room, but never hang boot */
		for (i = 0; i < 100000; i++) {
			if ((DTXFSTS(0) & 0xffff) >= words)
				break;
			udelay(1);
		}
	}

	DIEPTSIZ(0) = (npackets << 19) | len;
	DIEPCTL(0) = EP0_ARM_TX;

	for (i = 0; i < words; i++) {
		unsigned int j = i * 4;
		uint32_t w = (j < len ? (uint32_t)buf[j] : 0) |
			     (j + 1 < len ? (uint32_t)buf[j + 1] << 8 : 0) |
			     (j + 2 < len ? (uint32_t)buf[j + 2] << 16 : 0) |
			     (j + 3 < len ? (uint32_t)buf[j + 3] << 24 : 0);

		FIFO(0) = w;
	}
}

static void ep0_arm_zlp(void)
{
	DIEPTSIZ(0) = (1 << 19) | 0;
	DIEPCTL(0) = EP0_ARM_ZLP;
}

/* Transmit whatever the setup decoder staged: real data, or a status
 * ZLP for no-data requests and zero-length replies (winusb can ask for
 * wLength=0 — arming PKTCNT=0 would be illegal). */
static void ep0_commit(void)
{
	if (ep0_req == REQ_DATA && ep0_plen) {
		printk(KERN_INFO, "ep0i: tx %uB\n", ep0_plen);
		ep0_send(ep0_ptr, ep0_plen);
	} else if (ep0_req == REQ_DATA || ep0_req == REQ_ZLP) {
		ep0_arm_zlp();
	}
	ep0_ptr = 0;
	ep0_plen = 0;
	ep0_req = REQ_NONE;
}

/* Fallback: if the host still knocks on an empty (but enabled) fifo
 * while a reply is staged, push it here too. */
static void ep0_kick(void)
{
	if (ep0_req != REQ_NONE && ep0_req != REQ_OUT)
		ep0_commit();
}

static void ep0_reply(const uint8_t *buf, unsigned int len, unsigned int asked)
{
	ep0_ptr = buf;
	ep0_plen = len < asked ? len : asked;
	ep0_req = REQ_DATA;
}

static void ep0_status_in(void)
{
	ep0_req = REQ_ZLP;
}

static void ep0_stall(void)
{
	DIEPCTL(0) |= DXEPCTL_STALL;
	DOEPCTL(0) |= DXEPCTL_STALL;
	ep0_req = REQ_NONE;
	ep0_out_rearm();
}

/* handle one decoded setup packet: decode into the staged-reply state,
 * then ep0_commit() arms EP0-IN and pushes the reply immediately.
 * (S-Boot only records here and waits for INTKNTXFEMP; that model
 * deadlocks on this core because the knock needs EPENA first.) */
static void ep0_setup(void)
{
	uint8_t rt = setup_pkt[0], rq = setup_pkt[1];
	uint16_t wv = setup_pkt[2] | (setup_pkt[3] << 8);
	uint16_t wl = setup_pkt[6] | (setup_pkt[7] << 8);

	printk(KERN_INFO, "ep0: rq%02x %02x wv%04x wl%u\n",
	       rt, rq, wv, wl);
	if (rt == 0x80 && rq == 6) {		/* GET_DESCRIPTOR dev->host */
		switch (wv >> 8) {
		case 1: ep0_reply(dev_desc, sizeof(dev_desc), wl); goto tail;
		case 2: ep0_reply(cfg_desc, sizeof(cfg_desc), wl); goto tail;
		case 3:
			switch (wv & 0xff) {
			case 0: ep0_reply(str0, sizeof(str0), wl); goto tail;
			case 1: ep0_reply(str1, sizeof(str1), wl); goto tail;
			case 2: ep0_reply(str2, sizeof(str2), wl); goto tail;
			default: ep0_reply(str3, sizeof(str3), wl); goto tail;
			}
		case 6: ep0_reply(qual_desc, sizeof(qual_desc), wl); goto tail;
		case 7: {	/* OTHER_SPEED: same body, type byte 7 */
			static uint8_t osc[sizeof(cfg_desc)];
			memcpy(osc, cfg_desc, sizeof(osc));
			osc[1] = 7;
			unsigned int mps = bulk_mps == 512 ? 64 : 512;
			osc[57] = osc[64] = mps & 255;
			osc[58] = osc[65] = mps >> 8;
			ep0_reply(osc, sizeof(osc), wl);
			goto tail;
		}
		}
		ep0_stall();
		return;
	}
	if (rt == 0x00 && rq == 5) {		/* SET_ADDRESS */
		/* S-Boot applies the address IMMEDIATELY at setup decode —
		 * DCFG = base | (addr<<4) | 0x40000 — not after the ZLP. */
		DCFG = (DCFG & ~0x7f0u) | ((wv & 0x7f) << 4) | 0x40000;
		ep0_status_in();
		goto tail;
	}
	if (rt == 0x00 && rq == 9) {		/* SET_CONFIGURATION */
		/* s3c-hsotg style: configure EP1 (bulk, dedicated fifo 1,
		 * MPS 64, DATA0) but let ep1_kick set EPENA per packet.
		 * S-Boot's 0x84088840 assumed DMA and TXFNUM=0. */
		DIEPCTL(1) = DXEPCTL_EPTYPE(2) | DXEPCTL_USBACTEP |
			DXEPCTL_MPS(bulk_mps) | (1 << 22) /* TXFNUM=1 */ |
			DXEPCTL_SETD0PID;
		printk(KERN_INFO, "usbcdc: ep1 ctl=%08x txf=%08x dtx=%08x\n",
		       DIEPCTL(1), DPTXFSIZ(1), DTXFSTS(1));
		DIEPCTL(2) = DXEPCTL_USBACTEP | DXEPCTL_EPTYPE(3) |
			DXEPCTL_MPS(8) | DXEPCTL_SNAK;
		DOEPCTL(1) = DXEPCTL_USBACTEP | DXEPCTL_EPTYPE(2) |
			DXEPCTL_MPS(bulk_mps) | DXEPCTL_EPENA | DXEPCTL_CNAK;
		configured = 1;
		ep0_status_in();
		goto tail;
	}
	if (rt == 0x21 && rq == 0x20) {		/* SET_LINE_CODING, 7B out */
		ep0_req = REQ_OUT;		/* bytes arrive via RXFLVL */
		return;
	}
	if (rt == 0xa1 && rq == 0x21) {		/* GET_LINE_CODING */
		static const uint8_t lc[7] = {
			0x00, 0xc2, 0x01, 0x00, 0, 0, 8 /* 115200 8N1 */
		};
		ep0_reply(lc, 7, wl);
		goto tail;
	}
	if (rt == 0x21 && rq == 0x22) {		/* SET_CONTROL_LINE_STATE */
		host_open = 1;
		ep0_status_in();
		goto tail;
	}
	if (rq == 1 || rq == 3)			/* CLEAR/SET_FEATURE */
		ep0_status_in();
	else if (rt & 0x80)			/* other dev->host std req */
		ep0_reply((const uint8_t *)"\0\0", 2, wl);
	else
		ep0_status_in();
tail:
	/* Send the reply NOW.  Waiting for INTKNTXFEMP deadlocks on this
	 * core: that interrupt needs the endpoint already enabled, and
	 * only this arm can enable it. */
	ep0_commit();
}

/* ---------------- tx ring + console ---------------- */

static void ring_push(const char *s)
{
	while (*s) {
		unsigned int next = (tx_head + 1) & (TXRING - 1);

		if (next == tx_tail)
			break;			/* full: drop */
		txring[tx_head] = *s++;
		tx_head = next;
	}
}

/* EP1-IN printk stream, using dedicated FIFO 1. */
static void ep1_kick(void)
{
	unsigned int n = 0, space;
	uint8_t pkt[64] = { 0 };
	uint32_t w, ctl_before, size_set, size_fifo, space_fifo;

	if (ep1_busy || !configured || tx_head == tx_tail)
		return;
	ctl_before = DIEPCTL(1);
	if (DIEPINT(1) & DXEPINT_XFERCOMPL)
		DIEPINT(1) = DXEPINT_XFERCOMPL;	/* stale */

	/* Dedicated fifo 1: free space lives in DTXFSTS(1), not the
	 * shared NPTX register (s3c-hsotg does the same split).  Check
	 * before popping so a full fifo never eats ring bytes. */
	space = DTXFSTS(1) & 0xffff;
	n = (tx_head - tx_tail) & (TXRING - 1);
	if (n > sizeof(pkt))
		n = sizeof(pkt);
	if (n > space * 4)
		n = space * 4;
	if (!n)
		return;

	for (unsigned int i = 0; i < n; i++) {
		pkt[i] = txring[tx_tail];
		tx_tail = (tx_tail + 1) & (TXRING - 1);
	}

	/* s3c-hsotg sets MC(1) for every non-control IN endpoint. */
	DIEPTSIZ(1) = (1 << 19) | n | 0x20000000;
	size_set = DIEPTSIZ(1);

	/* Match s3c-hsotg and the kernel: TSIZ -> EPENA -> FIFO. With
	 * HS MPS512, each <=64-byte log packet is explicitly a short packet. */
	DIEPCTL(1) = (DIEPCTL(1) & ~(DXEPCTL_EPDIS | DXEPCTL_SNAK |
		DXEPCTL_STALL)) | DXEPCTL_EPENA | DXEPCTL_CNAK;
	for (unsigned int i = 0; i < (n + 3) / 4; i++) {
		w = (uint32_t)pkt[i * 4] | ((uint32_t)pkt[i * 4 + 1] << 8) |
		    ((uint32_t)pkt[i * 4 + 2] << 16) |
		    ((uint32_t)pkt[i * 4 + 3] << 24);
		FIFO(1) = w;
	}
	size_fifo = DIEPTSIZ(1);
	space_fifo = DTXFSTS(1);
	DIEPINT(1) = DXEPINT_INTKNTXFEMP;	/* clear knock, like s3c-hsotg */
	if (ep1_dbg < 8) {
		/* Capture before printk can delay servicing the next event. */
		uint32_t ctl = DIEPCTL(1), size_arm = DIEPTSIZ(1);
		uint32_t space_arm = DTXFSTS(1), intr = DIEPINT(1);
		printk(KERN_INFO,
		       "ep1 pre ctl=%08x set=%08x fifo=%08x dtx=%08x\n",
		       ctl_before, size_set, size_fifo, space_fifo);
		printk(KERN_INFO,
		       "ep1 k%d n=%u ctl=%08x tsiz=%08x dtx=%08x int=%08x\n",
		       ep1_dbg, n, ctl, size_arm, space_arm, intr);
		ep1_dbg++;
	}
	ep1_busy = 1;
}

/* main service routine — S-Boot 0x4d41bf58/0x4d41bd1c dispatch model:
 * GINTSTS is read once, cleared wholesale, then dispatched bit by bit.
 * Safe to call any time after usbcdc_init(). */
void usbcdc_poll(void)
{
	uint32_t st;

	if (!usb_ok || in_poll)
		return;
	in_poll = 1;

	st = GINTSTS;
	if (!st)
		goto drain;
	GINTSTS = st;			/* S-Boot: clear all at once */

	if (st & GINTSTS_USBRST)	/* 0x1000: full re-init */
		dev_soft_init();
	if (st & GINTSTS_ENUMDONE) {	/* 0x2000 */
		enumerated = 1;
		bulk_mps = ((DSTS >> 1) & 3) == 0 ? 512 : 64;
		cfg_desc[57] = cfg_desc[64] = bulk_mps & 255;
		cfg_desc[58] = cfg_desc[65] = bulk_mps >> 8;
		/* S-Boot reads DSTS enum speed then patches descriptor
		 * MPS; our MPS stays 64 (legal for FS too). */
		printk(KERN_INFO, "usbcdc: enumdone dsts=%08x\n", DSTS);
		ep0_out_rearm();
	}
	if (st & GINTSTS_RXFLVL) {
		uint32_t gs, ps, ep, bc;

		GINTMSK = GINTMSK_RXMASK;	/* mask RXFLVL while popping */
		gs = GRXSTSP;			/* pop the status word */
		ps = GRXSTS_PKTSTS(gs);
		ep = GRXSTS_EPNUM(gs);
		bc = GRXSTS_BYTECNT(gs);

		if (ps == PKTSTS_SETUPRX) {	/* 6: setup payload in DFIFO0 */
			uint32_t w0 = FIFO_RD(0);
			uint32_t w1 = FIFO_RD(0);

			memcpy(setup_pkt, &w0, 4);
			memcpy(setup_pkt + 4, &w1, 4);
			ep0_setup();
		} else if (ps == PKTSTS_OUTRX) {	/* 2: OUT data */
			unsigned int i;
			uint32_t w;
			for (i = 0; i < bc; i += 4)
				w = FIFO_RD(0);	/* slave RX payload always uses FIFO0 */
			(void)w;
			if (ep == 0 && ep0_req == REQ_OUT) {
				/* SET_LINE_CODING payload arrived;
				 * line coding ignored, answer ZLP now. */
				ep0_req = REQ_NONE;
				ep0_arm_zlp();
			}
		}
		/* 1 goutnak / 3 outdone / 4 setupdone: ignored like S-Boot */
		/* S-Boot re-arms EP0-OUT on every OUT-EP0 event.  Do it
		 * here, *after* the entry is consumed: re-arming from the
		 * OEPINT branch can land before the payload is read, and
		 * this core then drops the fifo entry. */
		if (ep == 0)
			ep0_out_rearm();
		GINTMSK = GINTMSK_RUN;
	}
	if (st & GINTSTS_IEPINT) {	/* 0x40000 */
		uint32_t d = DAINT & 0xffff;
		if (d & 1) {
			uint32_t ei = DIEPINT(0);
			if (ei & DXEPINT_INTKNTXFEMP)
				ep0_kick();	/* host knocked: send now */
			if (ei & DXEPINT_XFERCOMPL)
				printk(KERN_INFO, "ep0i: compl\n");
			DIEPINT(0) = ei;
		}
		if (d & 2) {
			uint32_t ei = DIEPINT(1);
			uint32_t ctl = DIEPCTL(1), size = DIEPTSIZ(1);
			uint32_t space = DTXFSTS(1);
			DIEPINT(1) = ei;
			if (ei && ei != ep1_lastint && ep1_intdbg < 10) {
				printk(KERN_INFO,
				       "ep1i: int=%08x ctl=%08x tsiz=%08x dtx=%08x\n",
				       ei, ctl, size, space);
				ep1_intdbg++;
			}
			ep1_lastint = ei;
			if (ei & DXEPINT_XFERCOMPL) {
				ep1_busy = 0;
				if (ep1_compldbg < 8) {
					printk(KERN_INFO, "ep1 done int=%08x tsiz=%08x\n",
					       ei, size);
					ep1_compldbg++;
				}
			}
			if (ei & DXEPINT_AHBERR)
				ep1_busy = 0;
		}
		if (d & 4) {
			uint32_t ei = DIEPINT(2);
			DIEPINT(2) = ei;
		}
	}
	if (st & GINTSTS_OEPINT) {	/* 0x80000 */
		uint32_t d = (DAINT >> 16) & 0xffff;
		if (d & 1) {
			uint32_t oi = DOEPINT(0);
			if (oi)
				printk(KERN_INFO, "ep0o: %08x\n", oi);
			/* re-arm happens after the RX entry is consumed */
			DOEPINT(0) = oi;
		}
		if (d & 2) {
			uint32_t oi = DOEPINT(1);
			DOEPINT(1) = oi;
		}
	}
drain:
	ep1_kick();
	in_poll = 0;
}

/* Keep the gadget alive until the host has actually opened the port.
 * Windows only sends SET_CONTROL_LINE_STATE from Open(); once the loader
 * jumps, the kernel adopt path cannot answer control transfers until it
 * starts polling, which is too late for an Open issued after handoff.
 * Bounded so an unplugged phone still boots after the timeout. */
int usbcdc4210_wait_host(unsigned int ms)
{
	unsigned int i;

	if (!usb_ok)
		return 0;
	printk(KERN_INFO, "usbcdc: waiting up to %u ms for host open\n", ms);
	for (i = 0; i < ms; i++) {
		usbcdc_poll();
		if (host_open)
			break;
		if ((i % 500) == 0)
			printk(KERN_INFO, "usbcdc: host not open yet (%u ms)\n", i);
		udelay(1000);
	}
	printk(KERN_INFO, "usbcdc: host %s after %u ms\n",
	       host_open ? "opened" : "did not open", i);
	return host_open;
}

static void usbcon_write(int level, const char *prefix, const char *msg)
{
	(void)level;
	ring_push(prefix);
	ring_push(msg);
	ring_push("\r\n");
	usbcdc_poll();
}

static const struct console usbcon = {
	.write = usbcon_write,
};

/* ---------------- init ---------------- */

int usbcdc4210_init(void)
{
	uint32_t gate;

	/* Gate 0: the aclk133 "usb_device" clock lives in GATE_IP_FSYS
	 * (CMU+0xC940, bit13 per clk-exynos4).  S-Boot only opens it on
	 * the download-mode path, so a normal boot hands us a gated
	 * block whose registers all read 0 — first boot on hardware
	 * silently bailed right here with zero USB enumeration. */
	printk(KERN_INFO, "usbcdc: pre gate=%08x phyctl=%08x sid=%08x\n",
	       CMU_GATE_IP_FSYS, *(volatile uint32_t *)PMU_USBPHYCTRL,
	       GSNPSID);
	gate = CMU_GATE_IP_FSYS | GATE_FSYS_USB_DEVICE;
	CMU_GATE_IP_FSYS = gate;
	udelay(10);

	/* PHY power must precede the ID check: with USB_PHY_CTRL off the
	 * whole OTG core reads back 0 on real silicon, so phy_init()
	 * after the sanity check was self-defeating. */
	phy_init();
	udelay(1000);

	/* Gate A: core clock/reset gate must be open for sane ID.
	 * PCGCCTL bit0 = gate hclk (0 = running). */
	PCGCCTL = 0;
	udelay(10);

	printk(KERN_INFO, "usbcdc: post gate=%08x phyctl=%08x sid=%08x\n",
	       CMU_GATE_IP_FSYS, *(volatile uint32_t *)PMU_USBPHYCTRL,
	       GSNPSID);

	if ((GSNPSID & 0xffff0000) != 0x4f540000) {
		/* Report rather than vanish: without this the failure is
		 * invisible on real hardware (no console registered yet). */
		printk(KERN_INFO, "usbcdc: no dwc2, gsnpsid=%08x gate=%08x\n",
		       GSNPSID, gate);
		return -1;			/* no controller (QEMU) */
	}

	/* core soft reset */
	if (bounded_wait(&GRSTCTL, GRSTCTL_AHBIDLE, GRSTCTL_AHBIDLE, 100000))
		return -2;
	GRSTCTL = GRSTCTL_CSFTRST;
	if (bounded_wait(&GRSTCTL, GRSTCTL_CSFTRST, 0, 100000))
		return -3;

	/* S-Boot writes GAHBCFG=1 — GLBL_INTR_EN ONLY.  The production
	 * stack runs EP0 in pure slave mode with DMA_EN=0 and only ever
	 * flips DMA_EN (0x27) for the Odin bulk transfers.  Every
	 * "DMA-only" theory we had was wrong: slave is the proven path. */
	GAHBCFG = GAHBCFG_GLBL_INTR_EN;

	/* S-Boot writes GUSBCFG=0x540f — FDMOD + TRDT=5 + UTMI 16-bit +
	 * TOUTCAL=7, the exact same value. */
	GUSBCFG = (1 << 30) | (1 << 14) | (0x5 << 10) | (1 << 3) | 0x7;

	/* FIFO map lives in dev_soft_init(), including dedicated EP1 TX. */
	dev_soft_init();

	/* One-shot connect: drop + re-raise the pullup so the host issues
	 * a fresh enumeration against our already-configured EPs. */
	DCTL |= DCTL_SFTDISCON;
	udelay(10000);		/* S-Boot delay(10): 10ms */
	DCTL &= ~DCTL_SFTDISCON;

	usb_ok = 1;
	console_register(&usbcon);
	printk(KERN_INFO, "usbcdc: dwc2 device up, gsnpsid=%08x\n", GSNPSID);
	printk(KERN_INFO, "usbcdc: hw ahb=%08x ghw2=%08x ghw3=%08x ghw4=%08x dctl=%08x thr=%08x\n",
	       GAHBCFG, GHWCFG2, GHWCFG3, GHWCFG4, DCTL, DTHRCTL);

	/* Dwell servicing EP0 while the host enumerates — bounded but
	 * heartbeat-driven: udelay is uncalibrated on real silicon, so
	 * count iterations not microseconds, and exit as soon as the
	 * host finishes configuring us instead of burning a fixed wait.
	 * A heartbeat line every 2000 spins proves the loop is alive —
	 * a screen frozen on "device up" looked like a hang. */
	for (int i = 0; i < 60000; i++) {
		usbcdc_poll();
		if (configured)
			break;
		if ((i & 0x3fff) == 0x2000)
			printk(KERN_INFO, "usbcdc: poll i=%d gints=%08x req%d\n"
				"  i0=%08x o0=%08x ictl=%08x octl=%08x\n"
				"  gotg=%08x dsts=%08x dtx=%08x\n"
				"  grx=%08x nptx=%08x txf1=%08x dma0=%08x ahb=%08x\n",
			       i, GINTSTS, ep0_req,
			       DIEPINT(0), DOEPINT(0), DIEPCTL(0), DOEPCTL(0),
			       GOTGCTL, DSTS, DTXFSTS(0),
			       GRXFSIZ, GNPTXFSIZ, DPTXFSIZ(1), DOEPDMA(0),
			       GAHBCFG);
	}
	printk(KERN_INFO, "usbcdc: enum=%d configured=%d gintsts=%08x dsts=%08x\n",
	       enumerated, configured, GINTSTS, DSTS);
	return 0;
}
