// SPDX-License-Identifier: GPL-2.0-only
/*
 * Polling-mode CDC ACM gadget for the Exynos 4210 DWC2 OTG device
 * controller (@0x12480000).  Goal: a plain microUSB data cable shows up
 * as a COM/ttyACM port on the host PC and streams uniLoader printk
 * output - the "no UART jig" debug channel, same niche the lilac
 * project's QcomXnuUsbDebug fills.
 *
 * Register/sequence reference: u-boot drivers/usb/gadget/dwc2_udc_otg.c
 * + dwc2_udc_otg_phy.c (board "trats" == GT-I9100) and
 * drivers/usb/common/dwc2_core.h.
 *
 * Design: pure polled slave-mode, no IRQs, no DMA.  usbcdc_poll()
 * services USBRST/ENUMDONE/RXFLVL and drains the TX ring; it is called
 * from the console write path so enumeration traffic is handled as a
 * side effect of logging.  Every wait is bounded - a missing or dead
 * controller must never hang the boot (QEMU smdkc210 does not model
 * the OTG block at all, so the GSNPSID sanity check bails there).
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
#define GUSBCFG		GREG(0x00C)
#define GRSTCTL		GREG(0x010)
#define GINTSTS		GREG(0x014)
#define GINTMSK		GREG(0x018)
#define GRXSTSP		GREG(0x020)
#define GRXFSIZ		GREG(0x024)
#define GNPTXFSIZ	GREG(0x028)
#define GNPTXSTS	GREG(0x02C)
#define GSNPSID		GREG(0x040)
#define DPTXFSIZ(n)	GREG(0x104 + ((n) - 1) * 4)

#define DREG(x)		GREG(0x800 + (x))
#define DCFG		DREG(0x000)
#define DCTL		DREG(0x004)
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
#define DTXFSTS(n)	GREG(0x918 + (n) * 0x20)	/* INEPTFSPC per EP */

#define PCGCCTL		GREG(0xE00)
#ifndef FIFO
#define FIFO(n)		(*(volatile uint32_t *)(DWC2_BASE + 0x1000 + (n) * 0x1000))
#endif

#define PHYREG(x)	(*(volatile uint32_t *)(PHY_BASE + (x)))
#define PHYPWR		PHYREG(0x00)
#define PHYCLK		PHYREG(0x04)
#define PHYRST		PHYREG(0x08)

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

#define DXEPINT_XFERCOMPL	(1u << 0)
#define DXEPINT_TIMEOUT		(1u << 3)	/* IN: timeout / OUT: setup */
#define DXEPINT_AHBERR		(1u << 2)
#define DXEPINT_EPDISBLD	(1u << 1)

#define DCTL_SFTDISCON		(1u << 1)

#define GRXSTS_PKTSTS(x)	(((x) >> 17) & 0xf)
#define GRXSTS_BYTECNT(x)	(((x) >> 4) & 0x7ff)
#define GRXSTS_EPNUM(x)		((x) & 0xf)

#define PKTSTS_OUTNAK		1
#define PKTSTS_OUTRX		2
#define PKTSTS_OUTDONE		3
#define PKTSTS_SETUPDONE	4
#define PKTSTS_SETUPRX		6

/* FIFO layout (32-bit words): RX 512 @0, NPTX(EP0) 128 @512,
 * EP1 bulk-IN 128 @640, EP2 int-IN 32 @768.  Total fits the device
 * FIFO RAM easily. */
#define RXF_WORDS	0x200
#define NPTX_WORDS	0x80
#define EP1TX_WORDS	0x80
#define EP2TX_WORDS	0x20

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

static const uint8_t cfg_desc[] = {
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
	7, 5, 0x82, 3, 8, 0, 255,
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
	30, 3, 'i',0,'9',0,'1',0,'0',0,'0',0,' ',0,
	'u',0,'n',0,'i',0,'L',0,'o',0,'a',0,'d',0,'e',0,'r',0
};
static const uint8_t str2[] = {
	24, 3, 'U',0,'S',0,'B',0,' ',0,'C',0,'D',0,'C',0,' ',0,
	'L',0,'O',0,'G',0
};
static const uint8_t str3[] = {
	20, 3, 'S',0,'2',0,'I',0,'9',0,'1',0,'0',0,'0',0,'-',0,'1',0
};

/* ---------------- state ---------------- */

static int usb_ok;		/* controller + phy responded */
static int enumerated;		/* ENUMDONE seen */
static int configured;		/* SET_CONFIGURATION seen */
static int host_open;		/* SET_CONTROL_LINE_STATE seen (port open) */
static uint8_t new_addr;	/* pending SET_ADDRESS */
static int ep1_busy;		/* IN transfer in flight on EP1 */

enum { EP0_WAIT_SETUP, EP0_DATA_IN, EP0_STATUS_IN, EP0_STATUS_OUT,
       EP0_DATA_OUT } ep0_state;

static uint8_t setup_pkt[8];
static const uint8_t *ep0_buf;
static unsigned int ep0_len;	/* remaining to send */
static unsigned int ep0_asked;	/* wLength from host */

#define TXRING 4096
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

	PHYPWR &= ~((1u << 5) | (1u << 4) | (1u << 3) | (1u << 0));
	/* phyclk: clear ID_PULLUP0|COMMON_ON_N0, CLK_SEL_24MHZ */
	PHYCLK = (PHYCLK & ~((1u << 2) | (1u << 4))) | 0x3;
	/* rstcon: PHY_SW_RST0 pulse */
	PHYRST = (PHYRST & ~((1u << 1) | (1u << 2))) | (1u << 0);
	udelay(20);
	PHYRST &= ~((1u << 0) | (1u << 1) | (1u << 2));
	udelay(20);
}

static void fifo_flush_rx(void)
{
	GRSTCTL = GRSTCTL_RXFFLSH;
	bounded_wait(&GRSTCTL, GRSTCTL_RXFFLSH, 0, 100000);
}

static void fifo_flush_tx(unsigned int num)
{
	GRSTCTL = GRSTCTL_TXFNUM(num) | GRSTCTL_TXFFLSH;
	bounded_wait(&GRSTCTL, GRSTCTL_TXFFLSH, 0, 100000);
}

static void dev_soft_init(void)
{
	int i;

	/* EPMISCNT=1, DEVSPD=HS: trats runs the HS chirp (its PHY is a
	 * full UTMI+ HS transceiver).  FS-only was our guess; upstream
	 * silicon does HS on this block. */
	DCFG = (1 << 18) | 0;		/* EPMISCNT=1, DEVSPD=HS */
	/* NOTE: no SFTDISCON pulse here — dev_soft_init also runs on the
	 * USBRST path, where disconnecting would re-trigger enumeration
	 * forever.  The one-shot pulse lives in usbcdc4210_init(). */

	for (i = 0; i < 4; i++) {
		DOEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;
		DIEPCTL(i) = DXEPCTL_EPDIS | DXEPCTL_SNAK;
	}
	DIEPMSK = (1 << 3) | (1 << 2) | (1 << 0);	/* timeout|ahberr|xfcompl */
	DOEPMSK = (1 << 3) | (1 << 2) | (1 << 0);
	DAINTMSK = (1 << 16) | 1;			/* ep0 out+in */
	/* Unmask what we poll: on some DWC2 integration the status bits
	 * never raise in GINTSTS while masked — EP0 stayed deaf on the
	 * first cable plug (Windows VID_0000 descriptor fail). */
	GINTMSK = GINTSTS_USBRST | GINTSTS_ENUMDONE | GINTSTS_RXFLVL |
		  GINTSTS_IEPINT | GINTSTS_OEPINT;

	fifo_flush_rx();
	fifo_flush_tx(0x10);

	ep0_state = EP0_WAIT_SETUP;
	ep0_len = 0;
	ep1_busy = 0;
	configured = 0;
	host_open = 0;
}

static void ep0_arm_setup(void)
{
	DOEPTSIZ(0) = (3 << 29) | (1 << 19) | (8 * 3);	/* SUPCNT=3 */
	DOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;
}

/* push a chunk (<=64B) into EP0-IN NPTX fifo and start it */
static int ep0_tx_start(unsigned int len)
{
	unsigned int words = (len + 3) >> 2, i;
	uint32_t w;
	unsigned int space = GNPTXSTS & 0xffff;

	if (space < words)
		return -1;

	DIEPTSIZ(0) = (1 << 19) | len;
	for (i = 0; i < words; i++) {
		memcpy(&w, ep0_buf + i * 4, 4);
		FIFO(0) = w;
	}
	DIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;
	ep0_buf += len;
	ep0_len -= len;
	return 0;
}

static void ep0_reply(const uint8_t *buf, unsigned int len, unsigned int asked)
{
	ep0_buf = buf;
	ep0_len = len < asked ? len : asked;
	ep0_asked = asked;
	ep0_state = EP0_DATA_IN;
	ep0_tx_start(ep0_len > 64 ? 64 : ep0_len);
}

static void ep0_status_in(void)
{
	ep0_state = EP0_STATUS_IN;
	ep0_buf = (const uint8_t *)"";
	ep0_len = 0;
	DIEPTSIZ(0) = (1 << 19) | 0;
	DIEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;
}

static void ep0_status_out(void)
{
	ep0_state = EP0_STATUS_OUT;
	ep0_arm_setup();
}

static void ep0_stall(void)
{
	DIEPCTL(0) |= DXEPCTL_STALL;
	DOEPCTL(0) |= DXEPCTL_STALL;
	ep0_state = EP0_WAIT_SETUP;
}

/* handle one decoded setup packet */
static void ep0_setup(void)
{
	uint8_t rt = setup_pkt[0], rq = setup_pkt[1];
	uint16_t wv = setup_pkt[2] | (setup_pkt[3] << 8);
	uint16_t wl = setup_pkt[6] | (setup_pkt[7] << 8);

	printk(KERN_INFO, "ep0: rq%02x %02x wv%04x wl%u\n",
	       rt, rq, wv, wl);
	if (rt == 0x80 && rq == 6) {		/* GET_DESCRIPTOR dev->host */
		switch (wv >> 8) {
		case 1: ep0_reply(dev_desc, sizeof(dev_desc), wl); return;
		case 2: ep0_reply(cfg_desc, sizeof(cfg_desc), wl); return;
		case 3:
			switch (wv & 0xff) {
			case 0: ep0_reply(str0, sizeof(str0), wl); return;
			case 1: ep0_reply(str1, sizeof(str1), wl); return;
			case 2: ep0_reply(str2, sizeof(str2), wl); return;
			default: ep0_reply(str3, sizeof(str3), wl); return;
			}
		case 6: ep0_reply(qual_desc, sizeof(qual_desc), wl); return;
		case 7: {	/* OTHER_SPEED: same body, type byte 7 */
			static uint8_t osc[sizeof(cfg_desc)];
			memcpy(osc, cfg_desc, sizeof(osc));
			osc[1] = 7;
			ep0_reply(osc, sizeof(osc), wl);
			return;
		}
		}
		ep0_stall();
		return;
	}
	if (rt == 0x00 && rq == 5) {		/* SET_ADDRESS */
		new_addr = wv & 0x7f;
		ep0_status_in();
		return;
	}
	if (rt == 0x00 && rq == 9) {		/* SET_CONFIGURATION */
		/* EP1 IN bulk, fifo1; EP2 IN int, fifo2 */
		DIEPCTL(1) = DXEPCTL_USBACTEP | DXEPCTL_EPTYPE(2) |
			(1 << 22) | DXEPCTL_MPS(64) | DXEPCTL_EPENA |
			DXEPCTL_CNAK | DXEPCTL_SETD0PID;
		DIEPCTL(2) = DXEPCTL_USBACTEP | DXEPCTL_EPTYPE(3) |
			(2 << 22) | DXEPCTL_MPS(8) | DXEPCTL_SNAK;
		DOEPCTL(1) = DXEPCTL_USBACTEP | DXEPCTL_EPTYPE(2) |
			DXEPCTL_MPS(64) | DXEPCTL_EPENA | DXEPCTL_CNAK;
		configured = 1;
		ep0_status_in();
		return;
	}
	if (rt == 0x21 && rq == 0x20) {		/* SET_LINE_CODING, 7B out */
		ep0_state = EP0_DATA_OUT;
		DOEPTSIZ(0) = (1 << 19) | 7;
		DOEPCTL(0) |= DXEPCTL_EPENA | DXEPCTL_CNAK;
		return;
	}
	if (rt == 0xa1 && rq == 0x21) {		/* GET_LINE_CODING */
		static const uint8_t lc[7] = {
			0x00, 0xc2, 0x01, 0x00, 0, 0, 8 /* 115200 8N1 */
		};
		ep0_reply(lc, 7, wl);
		return;
	}
	if (rt == 0x21 && rq == 0x22) {		/* SET_CONTROL_LINE_STATE */
		host_open = 1;
		ep0_status_in();
		return;
	}
	if (rq == 1 || rq == 3)			/* CLEAR/SET_FEATURE */
		ep0_status_in();
	else if (rt & 0x80)			/* other dev->host std req */
		ep0_reply((const uint8_t *)"\0\0", 2, wl);
	else
		ep0_status_in();
}

static void ep0_in_done(void)
{
	switch (ep0_state) {
	case EP0_DATA_IN:
		if (ep0_len) {
			ep0_tx_start(ep0_len > 64 ? 64 : ep0_len);
			break;
		}
		/* if host asked for more than we had and len was an exact
		 * multiple of 64, a ZLP ends the data stage */
		if (ep0_asked > (unsigned int)(ep0_buf - 0) && 0) { }
		ep0_status_out();
		break;
	case EP0_STATUS_IN:
		if (new_addr) {
			DCFG = (DCFG & ~(0x7f << 4)) | (new_addr << 4);
			new_addr = 0;
		}
		ep0_state = EP0_WAIT_SETUP;
		break;
	default:
		break;
	}
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

static void ep1_kick(void)
{
	unsigned int n = 0, space;
	uint8_t pkt[64];
	uint32_t w;

	if (ep1_busy || !configured || !host_open || tx_head == tx_tail)
		return;
	if (DIEPINT(1) & DXEPINT_XFERCOMPL)
		DIEPINT(1) = DXEPINT_XFERCOMPL;	/* stale */

	while (n < sizeof(pkt) && tx_tail != tx_head) {
		pkt[n++] = txring[tx_tail];
		tx_tail = (tx_tail + 1) & (TXRING - 1);
	}
	space = DTXFSTS(1) & 0xffff;
	if (space < (n + 3) / 4)
		return;

	DIEPTSIZ(1) = (1 << 19) | n;
	for (unsigned int i = 0; i < (n + 3) / 4; i++) {
		w = pkt[i * 4] | (pkt[i * 4 + 1] << 8) |
		    (pkt[i * 4 + 2] << 16) |
		    ((i * 4 + 3 < n ? pkt[i * 4 + 3] : 0) << 24);
		FIFO(1) = w;
	}
	DIEPCTL(1) |= DXEPCTL_EPENA | DXEPCTL_CNAK;
	ep1_busy = 1;
}

/* main service routine; safe to call any time after usbcdc_init() */
void usbcdc_poll(void)
{
	uint32_t st;

	if (!usb_ok)
		return;

	st = GINTSTS;
	if (!st)
		goto drain;

	if (st & GINTSTS_USBRST) {
		GINTSTS = GINTSTS_USBRST;
		new_addr = 0;
		dev_soft_init();
	}
	if (st & GINTSTS_ENUMDONE) {
		GINTSTS = GINTSTS_ENUMDONE;
		enumerated = 1;
		DIEPCTL(0) = (DIEPCTL(0) & ~3u) | 0;	/* mps 64 */
		DOEPCTL(0) = (DOEPCTL(0) & ~3u) | 0;
		DIEPCTL(0) |= DXEPCTL_CNAK;
		DOEPCTL(0) |= DXEPCTL_CNAK;
		ep0_arm_setup();
	}
	if (st & GINTSTS_RXFLVL) {
		uint32_t gs = GRXSTSP;
		unsigned int ps = GRXSTS_PKTSTS(gs);
		unsigned int bc = GRXSTS_BYTECNT(gs);

		GINTSTS = GINTSTS_RXFLVL;
		if (ps == PKTSTS_SETUPRX) {
			/* each GRXSTSP read POPS the fifo — two statements,
			 * strict order, don't fold into one declaration */
			uint32_t lo = GRXSTSP;
			uint32_t hi = GRXSTSP;
			memcpy(setup_pkt, &lo, 4);
			memcpy(setup_pkt + 4, &hi, 4);
		} else if (ps == PKTSTS_SETUPDONE) {
			ep0_setup();
		} else if (ps == PKTSTS_OUTRX) {
			unsigned int words = (bc + 3) / 4, i;
			for (i = 0; i < words; i++)
				(void)GRXSTSP;	/* discard OUT data */
			if (ep0_state == EP0_DATA_OUT)
				ep0_status_in();
		} else if (ps == PKTSTS_OUTDONE) {
			if (ep0_state == EP0_STATUS_OUT)
				ep0_state = EP0_WAIT_SETUP;
			ep0_arm_setup();
		}
	}
	if (st & GINTSTS_IEPINT) {
		uint32_t d = DAINT & 0xffff;
		if (d & 1) {
			uint32_t ei = DIEPINT(0);
			DIEPINT(0) = ei;
			if (ei & DXEPINT_XFERCOMPL)
				ep0_in_done();
		}
		if (d & 2) {
			uint32_t ei = DIEPINT(1);
			DIEPINT(1) = ei;
			if (ei & (DXEPINT_XFERCOMPL | DXEPINT_AHBERR))
				ep1_busy = 0;
		}
	}
drain:
	ep1_kick();
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

	/* trats recipe: FDMOD + NP TXF rewind + TRDT 5 + UTMI 16-bit +
	 * TOUTCAL 7.  u-boot reconfig_usbd() defaults the PHY interface
	 * to 16-bit unless a board explicitly asks for 8; trats (the
	 * i9100 reference) uses 16.  8-bit here let the host see the
	 * pullup yet decode zero packets — Windows VID_0000. */
	GUSBCFG = (1 << 30) | (1 << 14) | (0x5 << 10) | (1 << 3) | 0x7;

	/* FIFO map */
	GRXFSIZ = RXF_WORDS;
	GNPTXFSIZ = (NPTX_WORDS << 16) | RXF_WORDS;
	DPTXFSIZ(1) = (EP1TX_WORDS << 16) | (RXF_WORDS + NPTX_WORDS);
	DPTXFSIZ(2) = (EP2TX_WORDS << 16) |
		      (RXF_WORDS + NPTX_WORDS + EP1TX_WORDS);

	dev_soft_init();

	/* One-shot connect: drop + re-raise the pullup so the host issues
	 * a fresh enumeration against our already-configured EPs. */
	DCTL |= DCTL_SFTDISCON;
	udelay(3000);
	DCTL &= ~DCTL_SFTDISCON;

	usb_ok = 1;
	console_register(&usbcon);
	printk(KERN_INFO, "usbcdc: dwc2 device up, gsnpsid=%08x\n", GSNPSID);

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
			printk(KERN_INFO, "usbcdc: poll i=%d gints=%08x\n",
			       i, GINTSTS);
	}
	printk(KERN_INFO, "usbcdc: enum=%d configured=%d gintsts=%08x dsts=%08x\n",
	       enumerated, configured, GINTSTS, DSTS);
	return 0;
}
