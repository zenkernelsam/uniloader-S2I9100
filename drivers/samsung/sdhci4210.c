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

static uint32_t SDHC = EXYNOS4210_SDHCI_SD_BASE;	/* slot 2 = microSD */

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
#define I_BUF_WR_RDY	(1 << 4)
#define I_BUF_RD_RDY	(1 << 5)
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

/* Flight-recorder state: the present-bit scan plus probe progress is
 * written to a fixed scratch LBA once a card answers CMD7, so a dead
 * panel/UART still leaves evidence on the card. */
static uint32_t sd_present_scan[4];
static uint32_t sd_csd_raw[4];
static uint32_t sd_probe_stage;
static int sd_host_sel = -1;
static int sd_selected;
static uint32_t sd_gpk2con_before, sd_gpk2con_after, sd_gpx3dat;
static uint32_t sd_ldo17_before = ~0u, sd_ldo17_after = ~0u, sd_i2c_status;

/* Last sd_cmd failure, for the forensic records. */
static uint32_t sd_last_cmd, sd_last_err, sd_last_detail;

/* Forensic cells in DRAM (survive a warm reset -> readable from TWRP
 * via /dev/mem, no working bus needed):
 *   0x7FFE0040: SD-side SDHB record   0x7FFE0240: eMMC-side EM1B record
 * INFORM6/7 carry a packed summary in case DMC reinit scribbles DRAM. */
#define FORENSIC_CELL_SD	(EXYNOS4210_DDRCELL_PA + 0x040)
#define FORENSIC_CELL_EMMC	(EXYNOS4210_DDRCELL_PA + 0x240)

static void forensic_inform(void)
{
	uint32_t cd = 0;
	int i;

	for (i = 0; i < 4; i++)
		if (sd_present_scan[i] & P_CARD_INSERTED)
			cd |= (1u << i);

	/* 0xF0E | stage nibble (1-7=SD side, A-F=eMMC side) |
	 * last-SD-stage nibble | host_sel+1 | card-detect bits */
	writel(0xF0E00000 | ((sd_probe_stage & 0xF) << 12) |
	       ((sd_probe_stage < 10 ? sd_probe_stage : 0) << 8) |
	       (((unsigned)sd_host_sel + 1) << 4) | cd,
	       (void *)EXYNOS4210_PMU_INFORM6);
	/* gpx3dat | ldo17 before | ldo17 after | i2c status */
	writel(((sd_gpx3dat & 0xFF) << 24) |
	       ((sd_ldo17_before & 0xFF) << 16) |
	       ((sd_ldo17_after & 0xFF) << 8) |
	       (sd_i2c_status & 0xFF),
	       (void *)EXYNOS4210_PMU_INFORM7);
}

/* --- I2C5 bitbang on GPB6(SDA)/GPB7(SCL): MAX8997 PMIC @0x66 owns
 * the external slot VTF rail (LDO17, 2.8V).  S-Boot's normal boot
 * path likely leaves the slot unpowered, which would exactly match
 * "every host dead". --- */

static void sd_udelay(unsigned int us)
{
	volatile unsigned int i;

	while (us--)
		for (i = 0; i < 400; i++)
			__asm__ __volatile__("nop");
}

static void gpb_pin(int pin, int out)
{
	uint32_t c = readl((void *)EXYNOS4210_GPBCON);

	c = (c & ~(0xFu << (pin * 4))) | ((out ? 1u : 0u) << (pin * 4));
	writel(c, (void *)EXYNOS4210_GPBCON);
}

static int gpb_val(int pin)
{
	return !!(readl((void *)EXYNOS4210_GPBDAT) & (1u << pin));
}

static void i2c_sda(int v)	/* open-drain: 1 = release to pull-up */
{
	gpb_pin(6, !v);
}

static void i2c_scl(int v)
{
	gpb_pin(7, !v);
}

static void i2c_start(void)
{
	i2c_sda(1); i2c_scl(1); sd_udelay(5);
	i2c_sda(0); sd_udelay(5);
	i2c_scl(0); sd_udelay(5);
}

static void i2c_stop(void)
{
	i2c_sda(0); i2c_scl(1); sd_udelay(5);
	i2c_sda(1); sd_udelay(5);
}

static int i2c_wr(unsigned char b)	/* returns 1 on ACK */
{
	int i, ack;

	for (i = 7; i >= 0; i--) {
		i2c_sda((b >> i) & 1);
		i2c_scl(1); sd_udelay(5);
		i2c_scl(0); sd_udelay(2);
	}
	i2c_sda(1);			/* release for ACK */
	i2c_scl(1); sd_udelay(2);
	ack = !gpb_val(6);		/* low = ACK */
	i2c_scl(0); sd_udelay(5);
	return ack;
}

static unsigned char i2c_rd(void)
{
	unsigned char b = 0;
	int i;

	i2c_sda(1);			/* release */
	for (i = 7; i >= 0; i--) {
		i2c_scl(1); sd_udelay(2);
		b = (b << 1) | gpb_val(6);
		i2c_scl(0); sd_udelay(5);
	}
	i2c_sda(0);			/* master NAK (single byte) */
	i2c_scl(1); sd_udelay(5);
	i2c_scl(0); sd_udelay(5);
	return b;
}

static int pmic_read_reg(unsigned reg, unsigned char *v)
{
	i2c_start();
	if (!i2c_wr(0xCC)) { sd_i2c_status |= 1; i2c_stop(); return -1; }
	if (!i2c_wr(reg))  { sd_i2c_status |= 2; i2c_stop(); return -1; }
	i2c_start();
	if (!i2c_wr(0xCD)) { sd_i2c_status |= 4; i2c_stop(); return -1; }
	*v = i2c_rd();
	i2c_stop();
	return 0;
}

static int pmic_write_reg(unsigned reg, unsigned char v)
{
	i2c_start();
	if (!i2c_wr(0xCC)) { sd_i2c_status |= 8; i2c_stop(); return -1; }
	if (!i2c_wr(reg))  { sd_i2c_status |= 0x10; i2c_stop(); return -1; }
	if (!i2c_wr(v))    { sd_i2c_status |= 0x20; i2c_stop(); return -1; }
	i2c_stop();
	return 0;
}

static void sd_slot_power(void)
{
	unsigned char v;

	/* GPB6/7 to GPIO for bitbang (bus already pulled up on board). */
	writel(readl((void *)EXYNOS4210_GPBDAT) &
	       ~((1u << 6) | (1u << 7)), (void *)EXYNOS4210_GPBDAT);
	gpb_pin(6, 0); gpb_pin(7, 0);
	writel(readl((void *)EXYNOS4210_GPBPUD) | (0x2 << 12) | (0x2 << 14),
	       (void *)EXYNOS4210_GPBPUD);
	i2c_sda(1); i2c_scl(1);
	sd_udelay(100);

	if (pmic_read_reg(0x4B /*MAX8997 LDO17CTRL*/, &v) == 0) {
		sd_ldo17_before = v;
		if (pmic_write_reg(0x4B, v | 0xC0 /*EN_LDO*/) == 0) {
			if (pmic_read_reg(0x4B, &v) == 0)
				sd_ldo17_after = v;
		}
	}
	sd_udelay(2000);		/* rail ramp */
}

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
		if (!--t) {
			sd_last_cmd = idx; sd_last_err = 1;
			sd_last_detail = readl((void *)(SDHC + R_PRESENT));
			return ~0u;
		}
	if (extra & CMD_DATA_EN) {
		t = 100000;
		while (readl((void *)(SDHC + R_PRESENT)) & P_DATA_INHIBIT)
			if (!--t) {
				sd_last_cmd = idx; sd_last_err = 2;
				sd_last_detail = readl((void *)(SDHC + R_PRESENT));
				return ~0u;
			}
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
			sd_last_cmd = idx; sd_last_err = 3;
			sd_last_detail = e;
			return ~0u;
		}
		if (s & I_CMD_DONE)
			break;
		if (!--t) {
			printk(KERN_INFO, "sdhci: cmd%u timeout (intsts %08x)\n",
			       idx, s);
			sd_last_cmd = idx; sd_last_err = 4;
			sd_last_detail = s;
			return ~0u;
		}
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

	/* Internal clock: divisor field is at bits[15:8]; N=128 -> ~200kHz
	 * from a ~52MHz base, safe for card init. */
	wr16(R_CLK, (0x80 << 8) | 0x0001);
	t = 100000;
	while (!(rd16(R_CLK) & 0x0002))
		if (!--t)
			break;
	wr16(R_CLK, (0x80 << 8) | 0x0005);	/* + SD clock enable */

	/* Enable all status bits: QEMU only sets INTSTS when the matching
	 * status-enable bit is on (real HW sets status unconditionally). We
	 * poll INTSTS, so leave the signal-enable register alone. */
	writel(0xFFFFFFFF, (void *)(SDHC + R_INTEN));

	/* Generous data timeout */
	wr8(R_TIMEOUT, 0x0E);

	/* 1-bit bus for bring-up */
	wr8(R_HOST, 0x00);
}

/* Feed a host clock: SCLKMPLL(6) -> mux, div 16 -> ~50 MHz.  On 4210 the
 * SDMMC mux/div live in CLK_{SRC,DIV}_FSYS, one 4-bit field per host
 * (host n at bits [4n+3:4n]); gate = GATE_IP_FSYS bit(5+n).  Best-effort:
 * ignored under QEMU, possibly redundant under S-Boot. */
static void cmu_feed_sdmmc(unsigned host)
{
	uint32_t v;
	unsigned sh = host * 4;

	v = readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_SRC_FSYS));
	v = (v & ~(0xF << sh)) | (6 << sh);
	writel(v, (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_SRC_FSYS));

	v = readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_DIV_FSYS));
	v = (v & ~(0xF << sh)) | (15 << sh);
	writel(v, (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_DIV_FSYS));

	/* clk-exynos4: sdmmcN = GATE_IP_FSYS bit(5+N) (not PERIL — bit18
	 * there is spi2; the old write was a no-op masked by S-Boot's
	 * ungate). */
	v = readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_GATE_IP_FSYS));
	v |= (1 << (5 + host));
	writel(v, (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_GATE_IP_FSYS));
}

static int sd_read_blocks(uint32_t lba, unsigned count, void *buf)
{
	unsigned t, n;
	uint32_t *p = buf;

	wr16(R_BLKSIZE, 0x0200 | (7 << 12));	/* 512B, SDMA boundary */
	if (count > 1) {
		/* CMD18 streams until stopped: Auto CMD12 is required or
		 * the card keeps sending and the next command times out. */
		wr16(R_BLKCNT, (uint16_t)count);
		wr16(R_XFER, X_BCNT_EN | X_READ | X_MULTI | X_ACMD12_EN);
		if (sd_cmd(18, sd_hcs ? lba : lba * 512,
			   CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN,
			   CMD_DATA_EN) == ~0u)
			return -1;
	} else {
		wr16(R_BLKCNT, 1);
		wr16(R_XFER, X_BCNT_EN | X_READ);
		if (sd_cmd(17, sd_hcs ? lba : lba * 512,
			   CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN,
			   CMD_DATA_EN) == ~0u)
			return -1;
	}

	for (n = 0; n < count; n++) {
		unsigned w;

#if defined(CONFIG_EXYNOS_CDCACM4210)
		/* Service EP0 between every SD block: without this, host
		 * setup packets starve for whole seconds during staging
		 * and enumeration dies (observed on hardware). */
		extern void usbcdc_poll(void);
		usbcdc_poll();
#endif

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

/* PIO write path — CMD24 only, one block at a time.  Exists so board
 * code can drop forensics (register dumps) into a raw LBA range that
 * survives the boot for host-side readback. */
static int sd_write_block(uint32_t lba, const void *buf)
{
	unsigned t, w;
	const uint32_t *p = buf;

	wr16(R_BLKSIZE, 0x0200 | (7 << 12));
	wr16(R_BLKCNT, 1);
	wr16(R_XFER, X_BCNT_EN);	/* write = X_READ clear */
	if (sd_cmd(24, sd_hcs ? lba : lba * 512,
		   CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN,
		   CMD_DATA_EN) == ~0u)
		return -1;

	t = 400000;
	while (!(readl((void *)(SDHC + R_INTSTS)) & I_BUF_WR_RDY)) {
		if (readl((void *)(SDHC + R_INTSTS)) & I_ERROR)
			return -1;
		if (!--t)
			return -1;
	}
	writel(I_BUF_WR_RDY, (void *)(SDHC + R_INTSTS));
	for (w = 0; w < 128; w++)
		writel(p[w], (void *)(SDHC + R_BUF));

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

int sd_write_sectors(uint32_t lba, unsigned count, const void *buf)
{
	if (!sd_ready)
		return -1;
	while (count--) {
		if (sd_write_block(lba++, buf))
			return -1;
		buf = (const char *)buf + 512;
	}
	return 0;
}

unsigned sd_sector_count(void)
{
	return sd_sectors;
}

/* LBA 16/17 live in the 1MB head before the FAT partition - safe
 * scratch space on any MBR-laid card, and reachable without trusting
 * sd_sector_count() (which mis-parsed on the real SDXC card). */
#define SD_FORENSIC_LBA	16

static unsigned sd_forensic_fill(uint32_t *rec)
{
	unsigned o = 0;
	int i;

	rec[o++] = 0x53444842;		/* 'SDHB' */
	rec[o++] = sd_probe_stage;
	rec[o++] = (uint32_t)SDHC;
	for (i = 0; i < 4; i++)
		rec[o++] = sd_present_scan[i];
	for (i = 0; i < 4; i++)
		rec[o++] = sd_csd_raw[i];
	rec[o++] = sd_rca;
	rec[o++] = sd_hcs;
	rec[o++] = sd_sectors;
	rec[o++] = readl((void *)(SDHC + R_PRESENT));
	rec[o++] = sd_gpk2con_before;
	rec[o++] = sd_gpk2con_after;
	rec[o++] = sd_gpx3dat;
	rec[o++] = sd_ldo17_before;
	rec[o++] = sd_ldo17_after;
	rec[o++] = sd_i2c_status;
	rec[o++] = sd_last_cmd;
	rec[o++] = sd_last_err;
	rec[o++] = sd_last_detail;
	rec[o++] = 0xF00DF00D;
	return o;
}

static void sd_forensic_record(void)
{
	uint32_t rec[128];

	if (!sd_selected)
		return;
	memset(rec, 0, sizeof(rec));
	sd_forensic_fill(rec);
	/* Mirror to the DRAM cell unconditionally — card write may
	 * fail, the warm-reset readback path must not depend on it. */
	memcpy((void *)FORENSIC_CELL_SD, rec, sizeof(rec));
	(void)sd_write_block(SD_FORENSIC_LBA, rec);
}

int sd_get_sectors(void) { return sd_ready ? sd_sectors : 0; }
int sd_get_rca(void) { return sd_ready ? (int)sd_rca : -1; }
int sd_is_ready(void) { return sd_ready; }

/* ---------------- eMMC forensic channel ----------------
 * The SD flight record depends on a card answering CMD7 — if the
 * external slot is truly dead we never get the record back.  The
 * eMMC is a second, always-powered channel: minimal MMC-proto init
 * on host 0, then drop the same record into a free tail sector of
 * the KERNEL partition (LBA 73728..90111 per the GPT backup — we
 * own that region, 686KB of 8MB used).  Read back under TWRP.
 */
#define EMMC_FORENSIC_LBA	90110	/* KERNEL tail-2, unused space */

/* Progressive eMMC-side record: rewritten at every probe stage so a
 * dead probe still leaves its corpse in the DRAM cell + INFORM regs. */
static void emmc_record(unsigned stage, uint32_t ocr)
{
	uint32_t rec[128];
	unsigned o = 0;

	memset(rec, 0, sizeof(rec));
	rec[o++] = 0x454D3142;		/* 'EM1B' */
	rec[o++] = stage;
	rec[o++] = readl((void *)(SDHC + R_PRESENT));
	rec[o++] = readl((void *)(SDHC + R_CAPAB));
	rec[o++] = readl((void *)(SDHC + R_CAPAB + 4));
	rec[o++] = ocr;
	rec[o++] = sd_rca;
	rec[o++] = sd_hcs;
	rec[o++] = sd_last_cmd;
	rec[o++] = sd_last_err;
	rec[o++] = sd_last_detail;
	rec[o++] = sd_csd_raw[0];
	rec[o++] = sd_csd_raw[1];
	rec[o++] = sd_csd_raw[2];
	rec[o++] = sd_csd_raw[3];
	rec[o++] = 0xF00DF00D;
	memcpy((void *)FORENSIC_CELL_EMMC, rec, sizeof(rec));
	forensic_inform();
}

static int mmc_probe_emmc(void)
{
	uint32_t ocr, r;
	unsigned t;

	SDHC = EXYNOS4210_SDHCI_EMMC_BASE;
	cmu_feed_sdmmc(0);	/* S-Boot read KERNEL off eMMC, so the
				 * clock was very likely fed already —
				 * but a dead gate here costs nothing. */
	host_reset_clock();
	sd_selected = 0;
	sd_probe_stage = 10;		/* 10-19 = eMMC side */
	emmc_record(10, 0);

	if (sd_cmd(0, 0, CMD_RESP_NONE, 0) == ~0u) {
		emmc_record(10, 0);
		return -1;
	}

	/* CMD1 SEND_OP_COND: loop until the device reports ready.
	 * 0x40FF8000 = sector-mode request + 2.7-3.6V window. */
	ocr = 0;
	for (t = 300; t && !(ocr & (1u << 31)); t--) {
		ocr = sd_cmd(1, 0x40FF8000, CMD_RESP_R48, 0);
		if (ocr == ~0u) {
			emmc_record(10, ocr);
			return -1;
		}
	}
	if (!t) {
		emmc_record(10, ocr);
		return -1;
	}
	sd_hcs = !!(ocr & (1u << 30));
	sd_probe_stage = 11;
	emmc_record(11, ocr);

	if (sd_cmd(2, 0, CMD_RESP_R136 | CMD_CRC_EN, 0) == ~0u) {
		emmc_record(11, ocr);
		return -1;
	}
	/* MMC CMD3 = SET_RELATIVE_ADDR: host assigns, use 1<<16. */
	sd_rca = 0x00010000;
	r = sd_cmd(3, sd_rca, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0);
	if (r == ~0u) {
		emmc_record(11, ocr);
		return -1;
	}
	sd_probe_stage = 12;
	emmc_record(12, ocr);

	if (sd_cmd(9, sd_rca, CMD_RESP_R136 | CMD_CRC_EN, 0) == ~0u) {
		emmc_record(12, ocr);
		return -1;
	}
	sd_csd_raw[0] = readl((void *)(SDHC + R_RESP0));
	sd_csd_raw[1] = readl((void *)(SDHC + R_RESP1));
	sd_csd_raw[2] = readl((void *)(SDHC + R_RESP2));
	sd_csd_raw[3] = readl((void *)(SDHC + R_RESP3));
	sd_probe_stage = 13;
	emmc_record(13, ocr);

	if (sd_cmd(7, sd_rca, CMD_RESP_R48B | CMD_CRC_EN | CMD_IDX_EN, 0)
	    == ~0u) {
		emmc_record(13, ocr);
		return -1;
	}
	sd_selected = 1;
	sd_probe_stage = 14;
	emmc_record(14, ocr);

	if (sd_cmd(16, 512, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0)
	    == ~0u) {
		emmc_record(14, ocr);
		return -1;
	}
	sd_probe_stage = 15;
	emmc_record(15, ocr);
	return 0;
}

int sd_emmc_forensic_write(void)
{
	uint32_t rec[128];
	uint32_t old_sdhc = SDHC;
	int old_sel = sd_selected, old_hcs = sd_hcs, old_stage = sd_probe_stage;
	uint32_t old_rca = sd_rca;
	int ret;

	memset(rec, 0, sizeof(rec));
	sd_forensic_fill(rec);		/* capture SD-side state first */
	memcpy((void *)FORENSIC_CELL_SD, rec, sizeof(rec));
	forensic_inform();
	if (mmc_probe_emmc() != 0)
		ret = -1;
	else
		ret = sd_write_block(EMMC_FORENSIC_LBA, rec) ? -1 : 0;
	emmc_record(15, ret == 0 ? 0xACE : 0xBAD);	/* ocr field = verdict */

	/* Restore the SD-side view so staging continues on the card. */
	SDHC = old_sdhc;
	sd_selected = old_sel;
	sd_hcs = old_hcs;
	sd_probe_stage = old_stage;
	sd_rca = old_rca;
	return ret;
}

static int sd_identify(void)
{
	uint32_t ocr, r;
	unsigned err = 0;

	sd_rca = 0;
	sd_hcs = 0;
	sd_selected = 0;
	cmu_feed_sdmmc((SDHC - EXYNOS4210_SDHCI_BASE(0)) >> 16);
	host_reset_clock();
	sd_probe_stage = 1;
	forensic_inform();

	if (sd_cmd(0, 0, CMD_RESP_NONE, 0) == ~0u)
		return -1;

	/* CMD8: 2.0-capable card check — echo means spec>=2.0 only;
	 * block addressing (HCS) is decided by OCR CCS below. */
	r = sd_cmd(8, 0x1AA, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0);
	sd_probe_stage = 2;
	forensic_inform();

	/* ACMD41 — bail fast on hard errors (eMMC/empty slot) instead
	 * of grinding the full retry budget. */
	for (;;) {
		unsigned t = 300;

		if (sd_cmd(55, 0, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0)
		    == ~0u)
			return -1;
		ocr = sd_cmd(41, 0x40300000,
			     CMD_RESP_R48, 0);	/* HCS|3.3-3.4V */
		if (ocr & (1u << 31))
			break;
		if (ocr == ~0u && ++err > 8)
			return -1;
		if (!--t)
			return -1;
	}
	sd_hcs = !!(ocr & (1u << 30));	/* CCS: 1=block addr, 0=byte addr */
	sd_probe_stage = 3;
	forensic_inform();

	if (sd_cmd(2, 0, CMD_RESP_R136 | CMD_CRC_EN, 0) == ~0u)
		return -1;
	r = sd_cmd(3, 0, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0);
	if (r == ~0u)
		return -1;
	sd_rca = r & 0xFFFF0000;
	sd_probe_stage = 4;
	forensic_inform();

	/* CSD for capacity — must precede CMD7: SEND_CSD is only legal
	 * in standby state. */
	if (sd_cmd(9, sd_rca, CMD_RESP_R136 | CMD_CRC_EN, 0) == ~0u)
		return -1;
	sd_csd_raw[0] = readl((void *)(SDHC + R_RESP0));
	sd_csd_raw[1] = readl((void *)(SDHC + R_RESP1));
	sd_csd_raw[2] = readl((void *)(SDHC + R_RESP2));
	sd_csd_raw[3] = readl((void *)(SDHC + R_RESP3));
	{
		/* R136 response is shifted: rspreg[i] holds CSD bits
		 * [i*32+8 .. i*32+39]. */
		uint32_t c0 = sd_csd_raw[1];
		uint32_t c1 = sd_csd_raw[2];

		if (sd_hcs) {
			/* CSD v2: C_SIZE = CSD[69:48] -> rspreg[1] bits 29:8 */
			uint32_t csize = (c0 >> 8) & 0x3FFFFF;
			sd_sectors = (csize + 1) * 1024;
		} else {
			/* CSD v1: C_SIZE = CSD[73:62] (rspreg2[1:0]|rspreg1[31:22]),
			 * C_SIZE_MULT = CSD[49:47] (rspreg1[9:7]),
			 * READ_BL_LEN = CSD[83:80] (rspreg2[11:8]).
			 * sectors = (C_SIZE+1) << (mult+2) << (bl_len-9) */
			uint32_t csize = ((c1 & 3) << 10) | (c0 >> 22);
			uint32_t mult = (c0 >> 7) & 7;
			uint32_t blen = (c1 >> 8) & 0xF;

			sd_sectors = (csize + 1) << (mult + 2);
			if (blen > 9)
				sd_sectors <<= blen - 9;
			else if (blen < 9)
				sd_sectors >>= 9 - blen;
		}
	}
	sd_probe_stage = 6;
	forensic_inform();

	/* Select card, then drop the flight record — even if CMD16 or
	 * later staging dies, the probe state survives. */
	if (sd_cmd(7, sd_rca, CMD_RESP_R48B | CMD_CRC_EN | CMD_IDX_EN, 0)
	    == ~0u)
		return -1;
	sd_selected = 1;
	sd_forensic_record();	/* LBA16 stage=6: card alive, CSD parsed */

	/* Block length 512 */
	if (sd_cmd(16, 512, CMD_RESP_R48 | CMD_CRC_EN | CMD_IDX_EN, 0) == ~0u)
		return -1;
	sd_probe_stage = 7;
	forensic_inform();
	sd_forensic_record();	/* LBA16 stage=7: fully ready */
	return 0;
}

void sd_host_probe_4210(void)
{
	static const uint32_t hosts[] = {
		EXYNOS4210_SDHCI_BASE(2),	/* i9100 external microSD */
		EXYNOS4210_SDHCI_BASE(0),
		EXYNOS4210_SDHCI_BASE(1),
		EXYNOS4210_SDHCI_BASE(3),
	};
	unsigned h;

	/* Snapshot every host's present state first — the record shows
	 * what the hardware actually reported, regardless of what we do
	 * with it below. */
	for (h = 0; h < 4; h++)
		sd_present_scan[h] =
			readl((void *)(hosts[h] + R_PRESENT));

	/* Slot power first: VTF = MAX8997 LDO17 over I2C5, which the
	 * normal-boot path may leave off entirely. */
	sd_slot_power();

	/* u-boot exynos4x12 SDMMC2 pinmux: GPK2[0..6] func 2 (pin2 is
	 * the unused internal CD — leave as input), pull none, LV4
	 * drive.  The real card-detect is GPX3.4, wired active-low —
	 * configure it as an input so the record shows the true slot
	 * state instead of a floating pad. */
	sd_gpk2con_before = readl((void *)EXYNOS4210_GPK2CON);
	writel(0x02222022, (void *)EXYNOS4210_GPK2CON);
	writel(0x00000000, (void *)EXYNOS4210_GPK2PUD);
	writel(0x00333033, (void *)EXYNOS4210_GPK2DRV);
	writel(readl((void *)EXYNOS4210_GPX3CON) & ~(0xF << 16),
	       (void *)EXYNOS4210_GPX3CON);
	writel(readl((void *)EXYNOS4210_GPX3PUD) & ~(0x3 << 8),
	       (void *)EXYNOS4210_GPX3PUD);
	sd_gpk2con_after = readl((void *)EXYNOS4210_GPK2CON);
	sd_gpx3dat = readl((void *)EXYNOS4210_GPX3DAT);

	/* Pass 1: hosts reporting a card.  Pass 2: the rest — on the
	 * phone the external slot's card-detect may not feed R_PRESENT,
	 * so a "missing" card must still be attempted; empty hosts
	 * fail fast at CMD55/ACMD41. */
	for (h = 0; h < 4; h++) {
		if (!(sd_present_scan[h] & P_CARD_INSERTED))
			continue;
		SDHC = hosts[h];
		sd_host_sel = h;
		if (sd_identify() == 0)
			goto found;
	}
	for (h = 0; h < 4; h++) {
		if (sd_present_scan[h] & P_CARD_INSERTED)
			continue;
		SDHC = hosts[h];
		sd_host_sel = h;
		if (sd_identify() == 0)
			goto found;
	}
	printk(KERN_INFO, "sdhci4210: no usable card on any host\n");
	return;

found:

	sd_ready = 1;
	printk(KERN_INFO,
	       "sdhci4210: card ready on host %u @%08x, %u sectors (%u MB), %s\n",
	       sd_host_sel, (unsigned)SDHC, sd_sectors, sd_sectors / 2048,
	       sd_hcs ? "SDHC/SDXC" : "SDSC");
}
