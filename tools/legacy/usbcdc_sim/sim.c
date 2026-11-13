// SPDX-License-Identifier: GPL-2.0-only
/*
 * Host-side register-level simulator for dwc2cdc4210.c — the EP0 state
 * machine runs under a scripted host enumeration so descriptor logic
 * is verifiable without silicon (QEMU smdkc210 has no DWC2 model).
 *
 * Model: flat register buffer + a DFIFO TX-push capture array + a
 * DFIFO RX-pop injection queue.  The event flow mirrors the working
 * Exynos 4210 driver (s3c-hsotg): setup arrives via RXFLVL(SETUPRX) +
 * DFIFO0 payload pop; the reply is armed (EPENA) and pushed into the
 * fifo at decode time; EP0-OUT is re-armed on every OUT-EP0 event.
 * What it CANNOT check: actual USB wire behaviour.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static uint32_t dwc2[0x1000];	/* 16KB: regs 0..0xE00 + DFIFO 0x1000.. */
static uint32_t phy[16];
static uint32_t pmu_phyctl;
static uint32_t cmu_gate;

#define DWC2_BASE	((uintptr_t)&dwc2[0])
#define PHY_BASE	((uintptr_t)&phy[0])
#define PMU_USBPHYCTRL	((uintptr_t)&pmu_phyctl)
#define CMU_GATE_IP_FSYS (*(volatile uint32_t *)&cmu_gate)

/* TX pushes: per-EP cursor into a capture array. */
static uint32_t fifoq[4][512];
static unsigned fifoq_len[4];
static volatile uint32_t *sim_fifo_port(int ep)
{
	return &fifoq[ep][fifoq_len[ep]++ & 0x1ff];
}
#define FIFO(n) (*sim_fifo_port(n))

/* RX pops: injected by the test script, consumed by FIFO_RD. */
static uint32_t rxfifo[64];
static unsigned rx_head, rx_len;
static uint32_t sim_rx_pop(int ep)
{
	(void)ep;
	return rxfifo[rx_head++ & 0x3f];
}
#define FIFO_RD(n) sim_rx_pop(n)

#include <lib/debug.h>
#include <lib/console.h>

#include "../../uniloader-S2I9100/drivers/samsung/dwc2cdc4210.c"

void printk(int level, const char *fmt, ...)
{
	va_list ap;
	(void)level;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static int consoles;
void console_register(const struct console *con)
{
	consoles++;
}

/* ---- helpers ---- */
#define R32(off)	(dwc2[(off) / 4])

static int fails;
#define CHECK(cond, msg) do { \
		if (cond) { printf("  PASS %s\n", msg); } \
		else { printf("  FAIL %s\n", msg); fails++; } \
	} while (0)

static void fifo_read_ep0(uint8_t *dst, unsigned len)
{
	for (unsigned i = 0; i < len; i++)
		dst[i] = (uint8_t)(fifoq[0][i / 4] >> ((i % 4) * 8));
}

static void inject(uint32_t gintsts)
{
	R32(0x014) |= gintsts;
	usbcdc_poll();
	R32(0x014) = 0;
}

/* host posts a setup packet: SETUPRX status + 8B payload in DFIFO0 */
static void do_setup(const uint8_t *pkt)
{
	fifoq_len[0] = 0;	/* fresh TX capture for this response */
	rx_head = rx_len = 0;
	memcpy(rxfifo, pkt, 8);
	rx_len = 2;
	R32(0x020) = (PKTSTS_SETUPRX << 17) | (8 << 4) | 0; /* ep0, 8B */
	inject(GINTSTS_RXFLVL);
}

static void ep0_in_complete(void)
{
	R32(0x818) = 1;
	dwc2[0x908 / 4] = DXEPINT_XFERCOMPL;
	inject(GINTSTS_IEPINT);
	R32(0x818) = 0;
}

/* status-OUT (or any OUT-EP0) event -> unconditional setup re-arm */
static void out_done(void)
{
	R32(0x818) = 0x10000;		/* DAINT ep0-out */
	dwc2[0xB08 / 4] = DXEPINT_XFERCOMPL;
	inject(GINTSTS_OEPINT);
	R32(0x818) = 0;
}

static const uint8_t GET_DESC_DEV[]  = {0x80,6,0x00,0x01,0,0,64,0};
static const uint8_t GET_DESC_CFG[]  = {0x80,6,0x00,0x02,0,0,0xff,0};
static const uint8_t GET_DESC_STR0[] = {0x80,6,0x00,0x03,0,0,4,0};
static const uint8_t GET_DESC_QUAL[] = {0x80,6,0x00,0x06,0,0,10,0};
static const uint8_t GET_DESC_OSC[]  = {0x80,6,0x00,0x07,0,0,0xff,0};
static const uint8_t SET_ADDR[]      = {0x00,5,5,0,0,0,0,0};
static const uint8_t SET_CONFIG[]    = {0x00,9,1,0,0,0,0,0};
static const uint8_t SET_CLS[]       = {0x21,0x22,0,0,0,0,0,0};

int main(void)
{
	uint8_t buf[80];

	printf("== dwc2 EP0 enumeration simulator (s3c-hsotg model) ==\n");

	usb_ok = 1;
	R32(0x008) = GAHBCFG_GLBL_INTR_EN;	/* init() writes this first */
	dwc2[0x02C / 4] = NPTX_WORDS;		/* GNPTXSTS space */
	dwc2[0x918 / 4] = 0xffff;		/* DTXFSTS0: fifo has room */
	dwc2[0x938 / 4] = 0xffff;		/* DTXFSTS1: ep1 fifo has room */
	dev_soft_init();

	printf("[init]\n");
	CHECK((R32(0x81c) & 0x30003) == 0x30003, "DAINTMSK ep0+ep1 io");
	CHECK(R32(0x018) == GINTMSK_RUN, "GINTMSK = S-Boot runtime mask");
	CHECK(R32(0x900) == EP0_ACT, "EP0-IN activated (USBACTEP)");
	CHECK(R32(0xB00) == EP0_OUT_ARM, "EP0-OUT armed 0x84008000");
	CHECK(R32(0xB10) == EP0_OUT_TSIZ, "EP0-OUT tsiz SUPCNT1|8B");
	CHECK(R32(0x008) == 1, "GAHBCFG = 1 (no DMA)");

	printf("[USBRST]\n");
	inject(GINTSTS_USBRST);
	CHECK(ep0_req == REQ_NONE, "req state cleared");

	printf("[GET_DESCRIPTOR device — reply pushed at decode]\n");
	do_setup(GET_DESC_DEV);
	CHECK(ep0_req == REQ_NONE, "reply sent, nothing pending");
	CHECK(R32(0x900) == EP0_ARM_TX, "EP0-IN armed 0x84008000");
	CHECK(R32(0x910) == ((1u << 19) | 18), "tsiz pkt1 len18");
	CHECK(fifoq_len[0] == 5, "5 words pushed (18B)");
	fifo_read_ep0(buf, 18);
	printf("  dev fifo: %02x %02x %02x %02x | tsiz=%08x ctl=%08x\n",
	       buf[0], buf[1], buf[2], buf[3], R32(0x910), R32(0x900));
	CHECK(buf[0] == 18 && buf[1] == 1, "dev_desc hdr 18/DEVICE");
	CHECK(buf[7] == 64, "MPS=64");
	CHECK(buf[8] == 0x25 && buf[9] == 0x05, "VID 0525");
	CHECK(buf[10] == 0xa7 && buf[11] == 0xa4, "PID a4a7");
	ep0_in_complete();
	out_done();
	CHECK(R32(0xB00) == EP0_OUT_ARM, "EP0-OUT rearmed after out evt");

	printf("[SET_ADDRESS 5 — applied at decode, ZLP armed now]\n");
	do_setup(SET_ADDR);
	CHECK(((R32(0x800) >> 4) & 0x7f) == 5, "devaddr=5 applied NOW");
	CHECK(R32(0x900) == EP0_ARM_ZLP, "ZLP arm 0x84008000");
	CHECK(R32(0x910) == (1u << 19), "ZLP DIEPTSIZ");
	ep0_in_complete();
	out_done();

	printf("[GET_DESCRIPTOR config (67B -> 64+3)]\n");
	do_setup(GET_DESC_CFG);
	CHECK(R32(0x910) == ((2u << 19) | 67), "tsiz 2 pkts / 67B");
	CHECK(fifoq_len[0] == 17, "pushed 17 words (64+3 bytes)");
	fifo_read_ep0(buf, 9);
	CHECK(buf[0] == 9 && buf[1] == 2 && buf[2] == 67, "cfg hdr 9/CFG/67");
	ep0_in_complete();
	out_done();

	printf("[SET_CONFIGURATION]\n");
	do_setup(SET_CONFIG);
	CHECK(configured == 1, "configured");
	CHECK((R32(0x920) & DXEPCTL_USBACTEP) != 0, "EP1 configured");
	CHECK((R32(0x920) & (1u << 22)) != 0, "EP1 TXFNUM=1");
	CHECK(R32(0x900) == EP0_ARM_ZLP, "status ZLP armed");
	ep0_in_complete();
	out_done();

	printf("[SET_CONTROL_LINE_STATE -> host_open]\n");
	do_setup(SET_CLS);
	CHECK(host_open == 1, "host_open");
	CHECK(R32(0x900) == EP0_ARM_ZLP, "status ZLP armed");
	ep0_in_complete();
	out_done();

	printf("[GET_DESCRIPTOR qualifier]\n");
	do_setup(GET_DESC_QUAL);
	CHECK(R32(0x910) == ((1u << 19) | 10), "qual 10B");
	fifo_read_ep0(buf, 10);
	CHECK(buf[0] == 10 && buf[1] == 6, "qual hdr 10/QUALIFIER");
	ep0_in_complete();
	out_done();

	printf("[GET_DESCRIPTOR other_speed]\n");
	do_setup(GET_DESC_OSC);
	CHECK(R32(0x910) == ((2u << 19) | 67), "osc 67B / 2 pkts");
	fifo_read_ep0(buf, 9);
	CHECK(buf[0] == 9 && buf[1] == 7 && buf[2] == 67,
	      "osc hdr 9/OTHER_SPEED/67");
	ep0_in_complete();
	out_done();

	printf("[string descriptor]\n");
	do_setup(GET_DESC_STR0);
	CHECK(R32(0x910) == ((1u << 19) | 4), "str0 4B");
	fifo_read_ep0(buf, 4);
	CHECK(buf[0] == 4 && buf[1] == 3, "str0 hdr");
	ep0_in_complete();
	out_done();

	printf("[ep1 bulk TX ring]\n");
	ring_push("hello");
	ep1_kick();
	CHECK(R32(0x930) == ((1u << 19) | 5 | 0x20000000), "EP1 TSIZ 5B MC=1");
	CHECK((R32(0x920) & DXEPCTL_EPENA) != 0, "EP1 EPENA armed per packet");
	CHECK((fifoq[1][0] & 0xff) == 'h', "EP1 fifo data");

	printf("== %d failures ==\n", fails);
	return fails ? 1 : 0;
}
