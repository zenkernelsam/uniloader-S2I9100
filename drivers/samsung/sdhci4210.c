/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Exynos 4210 SDHCI driver for uniLoader
 *
 * Samsung Galaxy S2 (GT-I9100) external microSD slot: sdhci_2 at
 * 0x12530000.  Exynos 4 hosts are standard SDHCI 2.0, so this driver
 * follows the spec: PIO data path, CMD17/CMD18 reads, no writes.
 *
 * Bring-up notes:
 *  - CMU clock programming (CLK_SRC/DIV_PERIL0) is best-effort; on the
 *    phone S-Boot may already feed the host, and QEMU ignores the CMU.
 *    Verify gate/mux indices against the real datasheet on device.
 *  - Card-detect GPIO pinmux is not touched yet; we report PRESENT
 *    state so a missing card shows up clearly in the log.
 */

#include <stdint.h>
#include <string.h>
#include <lib/debug.h>
#include <soc/exynos4210.h>

#define SDHC		EXYNOS4210_SDHCI_SD_BASE	/* slot 2 = microSD */

/* SDHCI register offsets */
#define R_SDMA_ADDR	0x00
#define R_BLKSIZE	0x04
#define R_BLKCNT	0x06
#define R_ARG		0x08
#define R_XFER		0x0C
#define R_CMD		0x0E
#define R_RESP0		0x10
#define R_RESP1		0x14
#define R_RESP2		0x18
#define R_RESP3		0x1C
#define R_BUF		0x20
#define R_PRESENT	0x24
#define R_HOST		0x28
#define R_POWER		0x29
#define R_CLK		0x2C
#define R_TIMEOUT	0x2E
#define R_SWRST		0x2F
#define R_INTSTS	0x30
#define R_ERRSTS	0x32
#define R_INTEN		0x34
#define R_ERREN		0x36
#define R_CAPAB		0x40
#define R_VERSION	0xFE

/* PRESENT state bits */
#define P_CMD_INHIBIT	(1 << 0)
#define P_DATA_INHIBIT	(1 << 1)
#define P_BUF_RD_EN	(1 << 11)
#define P_CARD_INSERTED	(1 << 16)

/* INTSTS bits */
#define I_CMD_DONE	(1 << 0)
#define I_XFER_DONE	(1 << 1)
#define I_BUF_RD_RDY	(1 << 4)
#define I_ERROR		(1 << 15)

/* CMD register fields */
#define CMD_RESP_NONE	0x0
#define CMD_RESP_R136	0x1
#define CMD_RESP_R48	0x2
#define CMD_RESP_R48B	0x3
#define CMD_CRC_EN	(1 << 3)
#define CMD_IDX_EN	(1 << 4)
#define CMD_DATA_EN	(1 << 5)

/* XFER mode bits */
#define X_DMA_EN	(1 << 0)
#define X_BCNT_EN	(1 << 1)
#define X_ACMD12_EN	(1 << 2)
#define X_READ		(1 << 4)
#define X_MULTI		(1 << 5)

int sd_chatter = 1;	/* silenced by sd-boot.c around bulk reads */

static int sd_ready;
static int sd_sectors;
static uint32_t sd_rca;
static int sd_hcs;		/* high-capacity (block addressed) */

static inline uint16_t rd16(uint32_t off)
{
	return *(volatile uint16_t *)(SDHC + off);
}

static inline void wr16(uint32_t off, uint16_t v)
{
	*(volatile uint16_t *)(SDHC + off) = v;
}

static inline void wr8(uint32_t off, uint8_t v)
{
	*(volatile uint8_t *)(SDHC + off) = v;
}

static uint32_t sd_cmd(unsigned idx, uint32_t arg, unsigned resp,
		       unsigned extra)
{
	unsigned t;

	/* Wait for CMD line free */
	t = 100000;
	while (readl((void *)(SDHC + R_PRESENT)) & P_CMD_INHIBIT)
		if (!--t)
			return ~0u;
	if (extra & CMD_DATA_EN) {
		t = 100000;
		while (readl((void *)(SDHC + R_PRESENT)) & P_DATA_INHIBIT)
			if (!--t)
				return ~0u;
	}

	writel(0xffffffff, (void *)(SDHC + R_INTSTS));
	writel(arg, (void *)(SDHC + R_ARG));
	wr16(R_CMD, (uint16_t)((idx << 8) | resp | extra));

	t = 200000;
	for (;;) {
		uint32_t s = readl((void *)(SDHC + R_INTSTS));
		if (s & I_ERROR) {
			uint32_t e = readl((void *)(SDHC + R_ERRSTS));
			writel(s, (void *)(SDHC + R_INTSTS));
			printk(KERN_INFO, "sdhci: cmd%u err sts %08x\n",
			       idx, e);
			return ~0u;
		}
		if (s & I_CMD_DONE)
			break;
		if (!--t)
			return ~0u;
	}
	return readl((void *)(SDHC + R_RESP0));
}

static void host_reset_clock(void)
{
	unsigned t;

	/* Reset all */
	wr8(R_SWRST, 0x01);
	t = 100000;
	while (rd16(R_SWRST) & 0x07)
		if (!--t)
			break;

	/* Bus power: 3.3V + on */
	wr8(R_POWER, 0x0F);

	/* Internal clock: divisor 0x80 (128), enable, wait stable */
	wr16(R_CLK, 0x0080 | 0x0001);
	t = 100000;
	while (!(rd16(R_CLK) & 0x0002))
		if (!--t)
			break;
	wr16(R_CLK, 0x0080 | 0x0005);	/* + SD clock enable */

	/* Generous data timeout */
	wr8(R_TIMEOUT, 0x0E);

	/* 1-bit bus for bring-up */
	wr8(R_HOST, 0x00);
}

/* Feed the host clock: SCLKMPLL(6) -> SDMMC2 mux, div 16 -> ~50 MHz.
 * Best-effort: ignored under QEMU, possibly redundant under S-Boot. */
static void cmu_feed_sdmmc2(void)
{
	uint32_t v;

	v = readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_SRC_PERIL0));
	v = (v & ~(0xF << 16)) | (6 << 16);
	writel(v, (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_SRC_PERIL0));

	v = readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_DIV_PERIL0));
	v = (v & ~(0xF << 16)) | (15 << 16);
	writel(v, (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_DIV_PERIL0));

	v = readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_GATE_IP_PERIL));
	v |= (1 << 18);	/* SDMMC2 gate, index to verify on device */
	writel(v, (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_GATE_IP_PERIL));
}

static int sd_read_blocks(uint32_t lba, unsigned count, void *buf)
{
	unsigned t, n;
	uint32_t *p = buf;

	if (count > 1) {
		/* multi-block: count in BLKCNT, auto CMD12 off —
		 * rely on host's block count */
		wr16(R_BLKCNT, (uint16_t)count);
		wr16(R_XFER, X_BCNT_EN | X_READ | X_MULTI);
	} else {
		wr16(R_BLKCNT, 1);
		wr16(R_XFER, X_BCNT_EN | X_READ);
	}
	wr16(R_BLKSIZE, 0x0200 | (7 << 12));	/* 512B, SDMA boundary */

	/* CMD18 (READ_MULTIPLE_BLOCK) for both paths; BLKCNT=1 covers
	 * the single-block case on this host. */
	if (sd_cmd(18, sd_hcs ? lba : lba * 512,
		   CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN,
		   CMD_DATA_EN) == ~0u)
		return -1;

	for (n = 0; n < count; n++) {
		unsigned w;

		t = 400000;
		while (!(readl((void *)(SDHC + R_INTSTS)) & I_BUF_RD_RDY)) {
			if (readl((void *)(SDHC + R_INTSTS)) & I_ERROR)
				return -1;
			if (!--t)
				return -1;
		}
		writel(I_BUF_RD_RDY, (void *)(SDHC + R_INTSTS));
		for (w = 0; w < 128; w++)
			p[n * 128 + w] =
				readl((void *)(SDHC + R_BUF));
	}

	t = 400000;
	while (!(readl((void *)(SDHC + R_INTSTS)) & I_XFER_DONE)) {
		if (readl((void *)(SDHC + R_INTSTS)) & I_ERROR)
			return -1;
		if (!--t)
			return -1;
	}
	writel(I_XFER_DONE, (void *)(SDHC + R_INTSTS));
	return 0;
}

int sd_read_sectors(uint32_t lba, unsigned count, void *buf)
{
	if (!sd_ready)
		return -1;
	while (count) {
		unsigned chunk = count > 8 ? 8 : count;	/* BLKCNT sanity */

		if (sd_read_blocks(lba, chunk, buf))
			return -1;
		lba += chunk;
		buf = (char *)buf + chunk * 512;
		count -= chunk;
	}
	return 0;
}

int sd_get_sectors(void) { return sd_ready ? sd_sectors : 0; }
int sd_get_rca(void) { return sd_ready ? (int)sd_rca : -1; }
int sd_is_ready(void) { return sd_ready; }

void sd_host_probe_4210(void)
{
	uint32_t ocr, r;

	printk(KERN_INFO, "sdhci4210: version %04x capab %08x present %08x\n",
	       rd16(R_VERSION), readl((void *)(SDHC + R_CAPAB)),
	       readl((void *)(SDHC + R_PRESENT)));

	cmu_feed_sdmmc2();
	host_reset_clock();

	if (!(readl((void *)(SDHC + R_PRESENT)) & P_CARD_INSERTED)) {
		printk(KERN_INFO, "sdhci4210: no card inserted\n");
		return;
	}

	if (sd_cmd(0, 0, CMD_RESP_NONE, 0) == ~0u)
		goto out;

	/* CMD8: 2.0-capable card check */
	r = sd_cmd(8, 0x1AA, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0);
	sd_hcs = (r & 0xFF) == 0xAA;

	/* ACMD41 */
	for (;;) {
		unsigned t = 300;

		if (sd_cmd(55, 0, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0)
		    == ~0u)
			goto out;
		ocr = sd_cmd(41, 0x40300000,
			     CMD_RESP_R48, 0);	/* HCS|3.3-3.4V */
		if (ocr & (1u << 31))
			break;
		if (!--t)
			goto out;
	}
	if (ocr & (1u << 30))
		sd_hcs = 1;

	if (sd_cmd(2, 0, CMD_RESP_R136 | CMD_CRC_EN, 0) == ~0u)
		goto out;
	r = sd_cmd(3, 0, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0);
	if (r == ~0u)
		goto out;
	sd_rca = r & 0xFFFF0000;

	/* CSD for capacity */
	if (sd_cmd(9, sd_rca, CMD_RESP_R136 | CMD_CRC_EN, 0) == ~0u)
		goto out;
	{
		uint32_t c0 = readl((void *)(SDHC + R_RESP0));
		uint32_t c1 = readl((void *)(SDHC + R_RESP1));

		if (sd_hcs) {
			uint32_t csize = ((c1 & 0x3F) << 16) | (c0 >> 16);
			sd_sectors = (csize + 1) * 1024;
		} else {
			uint32_t csize = (c1 >> 14) & 0xFFF;
			uint32_t mult = (c1 >> 7) & 7;
			uint32_t rn = (c1 >> 16) & 0xF;
			sd_sectors = (csize + 1) << (mult + 2);
			sd_sectors >>= (9 - (int)rn) < 0 ? 0 : (9 - (int)rn);
			sd_sectors >>= 0;
		}
	}

	/* Select card */
	if (sd_cmd(7, sd_rca, CMD_RESP_R48B | CMD_CRC_EN | CMD_IDX_EN, 0)
	    == ~0u)
		goto out;
	/* Block length 512 */
	if (sd_cmd(16, 512, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0) == ~0u)
		goto out;

	sd_ready = 1;
	printk(KERN_INFO, "sdhci4210: card ready, %u sectors (%u MB), %s\n",
	       sd_sectors, sd_sectors / 2048,
	       sd_hcs ? "SDHC/SDXC" : "SDSC");
	return;

out:
	printk(KERN_INFO, "sdhci4210: card identify failed\n");
}
