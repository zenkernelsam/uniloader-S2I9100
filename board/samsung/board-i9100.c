/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Samsung Galaxy S2 (GT-I9100) support
 * for uniLoader.  Exynos 4210, dual Cortex-A9, 480x800 AMOLED
 * (LD9040 driven by FIMD parallel RGB).
 *
 * Display strategy: read the live FIMD state instead of hardcoding a
 * splash framebuffer.  On the phone S-Boot leaves window 0 scanning a
 * logo buffer, so VIDW00ADD0B0/VIDW00ADD0B1 tell us the real address;
 * under QEMU (no S-Boot) VIDCON0 reads back disabled, and then we
 * program a minimal RGB-scanout window ourselves so the emulated
 * display still gets a simplefb console.
 */

#include <board.h>
#include <util.h>
#include <stdint.h>
#include <string.h>
#include <drivers/framework.h>
#include <lib/simplefb.h>
#include <lib/debug.h>
#include <soc/exynos4210.h>

#define FIMD		EXYNOS4210_FIMD0_BASE
#define FB_FALLBACK	0x5E000000	/* our own buffer when S-Boot
				   left no running scanout (QEMU) */

#define FB_WIDTH	480
#define FB_HEIGHT	800
#define FB_STRIDE	4		/* bytes per pixel, ARGB8888 */

static struct video_info i9100_fb = {
	.format = FB_FORMAT_ARGB8888,
	.width = FB_WIDTH,
	.height = FB_HEIGHT,
	.stride = FB_STRIDE,
	.address = (void *)FB_FALLBACK
};

/* Forensics buffer: a snapshot of the FIMD/clock state as S-Boot left
 * it, captured in early_init and flushed to a raw SD sector at the end
 * of the card once the host controller is probed.  With no UART jig
 * and a possibly-broken panel path, the card is our readback channel. */
static uint32_t fimd_dump[128];
static int fimd_dump_dirty;

static void i9100_fimd_capture(void)
{
	unsigned int i, o = 0;

	fimd_dump[o++] = 0x46314D44;
	for (i = 0; i < 0x120; i += 4)
		fimd_dump[o++] =
			readl((void *)(FIMD + i));	/* 72 regs */
	fimd_dump[o++] = readl((void *)(EXYNOS4210_CMU_BASE + 0xC234));
	fimd_dump[o++] = readl((void *)(EXYNOS4210_CMU_BASE + 0xC534));
	fimd_dump[o++] = readl((void *)(EXYNOS4210_CMU_BASE +
					 EXYNOS4210_CLK_GATE_IP_LCD0));
	fimd_dump[o++] = readl((void *)(EXYNOS4210_CMU_BASE +
					 EXYNOS4210_CLK_GATE_IP_FSYS));
	fimd_dump[o++] = 0xF1D0FFFF;
	fimd_dump_dirty = 1;
}

static void i9100_fimd_report(void)
{
	uint32_t vidcon0 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
	uint32_t wincon0 = readl((void *)(FIMD + EXYNOS4210_FIMD_WINCON0));
	uint32_t add0b0 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD0B0));
	uint32_t add0b1 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD0B1));
	uint32_t tcon2 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDTCON2));

	printk(KERN_INFO, "fimd: VIDCON0=%08x WINCON0=%08x\n", vidcon0, wincon0);
	printk(KERN_INFO, "fimd: W0ADD0B0=%08x W0ADD0B1=%08x VIDTCON2=%08x\n",
	       add0b0, add0b1, tcon2);
	i9100_fimd_capture();
}

/* Program window 0 for a full-panel 480x800x32 RGB scanout.  Only used
 * when the display pipeline is NOT already running (QEMU bring-up); on
 * the phone we leave S-Boot's own setup untouched. */
static void i9100_fimd_init(uint32_t fb_pa)
{
	uint32_t vidcon0 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
	uint32_t fb_end = fb_pa + FB_WIDTH * FB_HEIGHT * FB_STRIDE;

	if (!(vidcon0 & (EXYNOS4210_FIMD_VIDCON0_ENVID |
			 EXYNOS4210_FIMD_VIDCON0_ENVID_F))) {
		/* Cold path (QEMU / S-Boot left no scanout): full program.
		 * LD9040 timing from exynos4210-i9100.dts:
		 * pclk 23492370, hactive 480 hbp 16 hfp 16 hsync 2,
		 * vactive 800 vbp 2 vfp 28 vsync 1.  VIDTCON fields are -1. */
		writel((1 << 16) | (27 << 8) | 0,
		       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON0));
		writel((15 << 16) | (15 << 8) | 1,
		       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON1));
		writel(((FB_HEIGHT - 1) << 11) | (FB_WIDTH - 1),
		       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON2));

		/* invert VDEN/VCLK + low-active syncs per i9100 dts */
		writel(0xf0, (void *)(FIMD + EXYNOS4210_FIMD_VIDCON1));

		/* SCLK_FIMD0 = XXTI 24MHz / 1 -> VCLK 24MHz (~2% off spec). */
		writel(readl((void *)(EXYNOS4210_CMU_BASE + 0xC234)) & ~0xf,
		       (void *)(EXYNOS4210_CMU_BASE + 0xC234));
		writel(readl((void *)(EXYNOS4210_CMU_BASE + 0xC534)) & ~0xf,
		       (void *)(EXYNOS4210_CMU_BASE + 0xC534));
		writel(readl((void *)(EXYNOS4210_CMU_BASE +
				     EXYNOS4210_CLK_GATE_IP_LCD0)) | 1,
		       (void *)(EXYNOS4210_CMU_BASE +
				EXYNOS4210_CLK_GATE_IP_LCD0));

		writel(EXYNOS4210_FIMD_VIDCON0_ENVID |
		       EXYNOS4210_FIMD_VIDCON0_ENVID_F,
		       (void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
	}
	/* else: S-Boot's scanout is live — its timing already makes the
	 * LD9040 happy (it drew the logo).  Reprogramming VIDCON/VIDTCON
	 * here produced fine stripes on real hardware; leave them. */

	writel(0, (void *)(FIMD + EXYNOS4210_FIMD_VIDOSD0A));
	writel(((FB_WIDTH - 1) << 12) | (FB_HEIGHT - 1),
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDOSD0B));
	writel(FB_WIDTH * FB_HEIGHT,
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDOSD0C));

	/* S-Boot does not necessarily draw the logo on window 0 — hardware
	 * showed the logo persisting under striped garbage, i.e. our win0
	 * overlay landed on top of another live window.  Retarget EVERY
	 * enabled window to our FB; WINCONx=0x20+4w, ADD0B0=0xA0+8w,
	 * ADD1B0=0xA4+8w, ADD0B1=0xD0+8w, ADD1B1=0xD4+8w, ADD2=0x100+4w. */
	for (int w = 0; w < 5; w++) {
		uint32_t wc = readl((void *)(FIMD + 0x20 + 4 * w));

		if (w && !(wc & EXYNOS4210_FIMD_WINCON_ENWIN))
			continue;	/* window unused, skip */
		printk(KERN_INFO, "fimd: win%d wincon=%08x add0=%08x\n",
		       w, wc, readl((void *)(FIMD + 0xA0 + 8 * w)));
		writel(fb_pa,  (void *)(FIMD + 0xA0 + 8 * w));
		writel(fb_pa,  (void *)(FIMD + 0xA4 + 8 * w));
		writel(fb_end, (void *)(FIMD + 0xD0 + 8 * w));
		writel(fb_end, (void *)(FIMD + 0xD4 + 8 * w));
		writel(FB_WIDTH * FB_STRIDE,
		       (void *)(FIMD + 0x100 + 4 * w));
		wc = (wc & ~(0xf << 2)) |
		     EXYNOS4210_FIMD_WINCON_ENWIN |
		     EXYNOS4210_FIMD_WINCON_BUFMODE |
		     EXYNOS4210_FIMD_WINCON_BPPMODE_32BPP_A888;
		writel(wc, (void *)(FIMD + 0x20 + 4 * w));
	}
}

#if defined(CONFIG_EXYNOS_SDHCI4210)
extern void sec_log_emit(const char *);
extern void i9_wdt_arm(void), i9_wdt_kick(void), i9_wdt_off(void);
#endif

int i9100_init(void)
{
	uint32_t vidcon0 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
	uint32_t fb_pa = FB_FALLBACK;

	i9100_fimd_report();
#if defined(CONFIG_EXYNOS_SDHCI4210)
	sec_log_emit("I9B init\n");	/* proves our C entry ran */
#endif

	/* S3C2410-style watchdog: S-Boot normally leaves it off, but if it
	 * is running the multi-minute SD staging would reset the board.
	 * One WTCON write is cheap insurance either way.  (The KERNEL arms
	 * it later for the unattended-recovery path; staging stays off.) */
	writel(0, (void *)(EXYNOS4210_WDT_BASE));

	/* Unattended-recovery readback: the kernel leaves a stage marker
	 * (INFORM6, 0x7766xxxx) that ticks forward as it boots, plus a
	 * panic reason (INFORM7) and a DDR scratch cell at 0x7FFE0000 on
	 * panic.  Report whatever the previous run left behind, then
	 * clear so a clean boot reports nothing. */
	{
		uint32_t st = readl((void *)EXYNOS4210_PMU_INFORM6);
		uint32_t rs = readl((void *)EXYNOS4210_PMU_INFORM7);
		volatile uint32_t *cell =
			(volatile uint32_t *)EXYNOS4210_DDRCELL_PA;

		if ((st & 0xffff0000U) == EXYNOS4210_STAGE_MAGIC ||
		    rs == EXYNOS4210_REASON_PANIC)
			printk(KERN_INFO,
			       "i9100: prev-boot marker stage=%08x reason=%08x\n",
			       st, rs);
		if (cell[0] == EXYNOS4210_DDRCELL_MAGIC) {
			printk(KERN_INFO,
			       "i9100: prev panic caller=%08x inform6=%08x\n",
			       cell[1], cell[2]);
			cell[0] = 0;
		}
		writel(0, (void *)EXYNOS4210_PMU_INFORM6);
		writel(0, (void *)EXYNOS4210_PMU_INFORM7);
	}

	/* Upstream style (board-j1xlte): when S-Boot's scanout is live,
	 * ADOPT the framebuffer it is already scanning — never poke FIMD
	 * registers mid-scanout (the all-window retarget here is what
	 * produced the 花屏).  Pick the enabled window with the largest
	 * OSD area and write pixels straight into its buffer.
	 *
	 * The XNU kernel contract (Video.v_baseAddr pinned 0x5E000000)
	 * still stands for the boot path; for forensic runs the visible
	 * console matters more — a clean retarget can happen at jump
	 * time later.  QEMU shows no live scanout -> cold-program ours. */
	if (vidcon0 & (EXYNOS4210_FIMD_VIDCON0_ENVID |
		       EXYNOS4210_FIMD_VIDCON0_ENVID_F)) {
		unsigned bw = 0;
		uint32_t barea = 0, bpp = 4;
		int w;

		for (w = 0; w < 5; w++) {
			uint32_t wc = readl((void *)(FIMD + 0x20 + 4 * w));
			uint32_t osdb = readl((void *)(FIMD + 0x44 +
						       0x10 * w));
			uint32_t area = (((osdb >> 12) & 0x7ff) + 1) *
					((osdb & 0x7ff) + 1);

			if (!(wc & EXYNOS4210_FIMD_WINCON_ENWIN))
				continue;
			printk(KERN_INFO,
			       "fimd: win%d wc=%08x osd=%08x fb=%08x\n",
			       w, wc, osdb,
			       readl((void *)(FIMD + 0xA0 + 8 * w)));
			if (area > barea) {
				barea = area;
				bw = w;
				bpp = (((wc >> 2) & 0xf) >= 0xb) ? 4 : 2;
			}
		}
		if (barea) {
			fb_pa = readl((void *)(FIMD + 0xA0 + 8 * bw));
			i9100_fb.stride = bpp;
			i9100_fb.format = bpp == 4 ? FB_FORMAT_ARGB8888
						   : FB_FORMAT_RGB565;
			printk(KERN_INFO,
			       "fimd: adopted S-Boot win%d fb @%08x bpp%u\n",
			       bw, fb_pa, bpp);
		} else {
			fb_pa = 0x5EC00000; /* documented S-Boot splash */
		}
	} else {
		/* Dead scanout (QEMU): program our own window as before. */
		i9100_fimd_init(FB_FALLBACK);
	}
	i9100_fb.address = (void *)fb_pa;

	/* Proof bands in every plausible scanned buffer — whichever
	 * window actually feeds the panel, a band shows.  Bright
	 * halfwords read as bright in 565 too. */
	{
		uint32_t cands[3] = {0, 0x5EC00000, 0x5E000000};
		unsigned c, i;

		cands[0] = fb_pa;
		for (c = 0; c < 3; c++) {
			volatile unsigned int *fb =
				(volatile unsigned int *)cands[c];

			if (!cands[c] || (c && cands[c] == cands[0]))
				continue;
			for (i = 0; i < FB_WIDTH * 64; i++)
				fb[(0x40000 >> 2) + i] = 0xFFFFFFFF;
			for (i = 0; i < FB_WIDTH * 24; i++)
				fb[(0x128000 >> 2) + i] = 0xFFFFFF00;
		}
	}

	return 0;
}

void uart_puts(const char *s)
{
	while (*s) {
		/* Bounded wait: if the UART clock is gated (S-Boot handover
		 * or QEMU quirk) an unbounded poll would hang the whole
		 * boot with zero diagnostics.  Bail instead. */
		unsigned int t = 50000;

		while (!(readl((void *)(EXYNOS4210_UART_BASE +
				EXYNOS4210_UTRSTAT)) &
			 EXYNOS4210_UTRSTAT_TX_EMPTY)) {
			if (!--t)
				return;
		}
		writel((unsigned int)(*s++ & 0xff),
		       (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_UTXH));
	}
}

extern void earlycon_register(void);

/* The S5P UART needs UCON TX enabled before bytes reach the wire; on
 * real hardware S-Boot has done this, under QEMU nothing has.  Program
 * it unconditionally — writing the same values twice is harmless. */
void early_console_init(void)
{
	writel(0x03, (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_ULCON));
	writel(0x03C5, (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_UCON));
	writel(0x00, (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_UFCON));
	writel(0x00, (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_UMCON));
	writel(53, (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_UBRDIV));
	writel(0x4, (void *)(EXYNOS4210_UART_BASE + EXYNOS4210_UFRACVAL));

	earlycon_register();
}

#if defined(CONFIG_EXYNOS_SDHCI4210)
extern void sd_host_probe_4210(void);
#endif
#if defined(CONFIG_EXYNOS_CDCACM4210)
extern int usbcdc4210_init(void);
extern void usbcdc_poll(void);
#endif

/* Runs after driver_probe_all(): the simplefb console is live, so
 * printk() output lands on the panel. */
static int i9100_late_init(void)
{
#if defined(CONFIG_EXYNOS_CDCACM4210)
	/* Bring the DWC2 device up BEFORE the storage probes: the host
	 * enumerates us while we stream probe progress to the COM port.
	 * usbcdc_poll() is driven from the console write path, so every
	 * printk services EP0.  This used to sit after the dead-SD
	 * branch - which never returns on the real device, so the USB
	 * console never came up at all.  Returns nonzero when the OTG
	 * block is absent (QEMU) - the console simply never registers. */
	usbcdc4210_init();
	/* Re-report the FIMD snapshot now that the CDC console may be
	 * live — early_init's printk only ever reached the UART. */
	printk(KERN_INFO,
	       "fimd: VIDCON0=%08x WINCON0=%08x ADD0B0=%08x\n",
	       readl((void *)(FIMD + EXYNOS4210_FIMD_VIDCON0)),
	       readl((void *)(FIMD + EXYNOS4210_FIMD_WINCON0)),
	       readl((void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD0B0)));
#endif
#if defined(CONFIG_EXYNOS_SDHCI4210)
	sec_log_emit("I9B late\n");
	i9_wdt_arm();	/* ~21s window; kicked per forensic stage/cmd.
			   A dead slot ends in a *warm* reset: hold
			   Vol-+Home to land in ODIN, no power-off. */
	sd_host_probe_4210();
	/* Flush the S-Boot FIMD/clock snapshot to a fixed scratch LBA. */
	if (fimd_dump_dirty) {
		extern int sd_write_sectors(uint32_t, unsigned, const void *);
		/* Fixed LBA in the pre-partition head: sd_sector_count()
		 * mis-parsed CSD v2 on the real SDXC card once, which
		 * threw the dump into FAT32 space.  LBA 17 always lands. */
		uint32_t lba = 17;

		if (sd_write_sectors(lba, 1, fimd_dump) == 0)
			printk(KERN_INFO, "fimd: reg dump -> lba %u\n", lba);
		else
			printk(KERN_INFO, "fimd: reg dump write failed\n");
		fimd_dump_dirty = 0;
	}
	{
		/* Fallback forensic channel: when the slot is dead, drop
		 * the same record into eMMC KERNEL tail instead (TWRP
		 * can dd it back).  Skip when the card answered — QEMU
		 * shares one sd-bus across hosts, so the MMC-proto CMD0
		 * would reset the real card mid-session. */
		extern int sd_emmc_forensic_write(void);
		extern int sd_is_ready(void);

		if (!sd_is_ready()) {
			unsigned i;
			uint32_t g2, g3;

			printk(KERN_INFO, "emmc forensic: %s\n",
			       sd_emmc_forensic_write() == 0
			       ? "written" : "failed");
			sec_log_emit("I9B forensic done; hold Vol+Home\n");
			/* Wait (bounded) for Vol-+Home: when they are held
			 * we fire PMU_SWRESET - the *true* warm reset that
			 * skips iROM DRAM re-init (the same path kernel
			 * panic capture uses) - and iROM drops into ODIN
			 * with our sec_log ring intact.  The WDT stays
			 * armed as a pure hang-recovery backstop. */
			for (i = 0; i < 600; i++) {
				volatile unsigned j;
				g2 = readl((void *)0x11000C44);	/* GPX2DAT */
				g3 = readl((void *)0x11000C64);	/* GPX3DAT */
				if (!(g3 & 0x20) && (g2 & 3) != 3)
					break;		/* home + a vol key */
				i9_wdt_kick();
#if defined(CONFIG_EXYNOS_CDCACM4210)
				usbcdc_poll();
#endif
				for (j = 0; j < 2000000; j++)
					;
			}
			sec_log_emit("I9B swreset now\n");
			writel(1, (void *)EXYNOS4210_PMU_SWRESET);
			for (;;)
				;
		} else {
			i9_wdt_off();
		}
	}
#endif
	return 0;
}

static const struct device i9100_devices[] = {
	{ "simplefb", &i9100_fb, "fb" },
};

struct board_data board_ops = {
	.name = "samsung-i9100",
	.ops = {
		.early_init = i9100_init,
#if defined(CONFIG_EXYNOS_SDHCI4210)
		.late_init = i9100_late_init,
#endif
	},
	.devices = i9100_devices,
	.num_devices = ARRAY_SIZE(i9100_devices),
	.quirks = 0
};
