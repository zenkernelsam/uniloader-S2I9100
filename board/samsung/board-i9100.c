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
}

/* Program window 0 for a full-panel 480x800x32 RGB scanout.  Only used
 * when the display pipeline is NOT already running (QEMU bring-up); on
 * the phone we leave S-Boot's own setup untouched. */
static void i9100_fimd_init(uint32_t fb_pa)
{
	uint32_t vidcon0;

	/* LD9040 timing from exynos4210-i9100.dts:
	 * pclk 23492370, hactive 480 hbp 16 hfp 16 hsync 2,
	 * vactive 800 vbp 2 vfp 28 vsync 1.  VIDTCON fields store value-1. */
	writel((1 << 16) | (27 << 8) | 0,	/* VBPD-1 VFPD-1 VSPW-1 */
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON0));
	writel((15 << 16) | (15 << 8) | 1,	/* HBPD-1 HFPD-1 HSPW-1 */
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON1));
	writel(((FB_HEIGHT - 1) << 11) | (FB_WIDTH - 1),	/* LINEVAL HOZVAL */
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON2));

	writel(0, (void *)(FIMD + EXYNOS4210_FIMD_VIDOSD0A));
	writel(((FB_WIDTH - 1) << 12) | (FB_HEIGHT - 1),
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDOSD0B));
	writel(FB_WIDTH * FB_HEIGHT,
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDOSD0C));

	writel(EXYNOS4210_FIMD_WINCON_ENWIN |
	       EXYNOS4210_FIMD_WINCON_BUFMODE |
	       EXYNOS4210_FIMD_WINCON_BPPMODE_32BPP_A888,
	       (void *)(FIMD + EXYNOS4210_FIMD_WINCON0));

	writel(fb_pa, (void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD0B0));
	writel(fb_pa + FB_WIDTH * FB_HEIGHT * FB_STRIDE,
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD0B1));
	writel(FB_WIDTH * FB_STRIDE,	/* PAGEWIDTH, OFFSIZE=0 */
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD2));

	/* i9100 dts asks for inverted VDEN/VCLK plus low-active syncs:
	 * IVCLK(7) IHSYNC(6) IVSYNC(5) IVDEN(4).  Without these the panel
	 * samples data on the wrong edges — that was the fine-stripe
	 * garbage seen on real hardware. */
	writel(0xf0, (void *)(FIMD + EXYNOS4210_FIMD_VIDCON1));

	/* Deterministic pixel clock: feed SCLK_FIMD0 from XXTI (24MHz)
	 * with ratio 0, so VCLK lands at 24MHz — within ~2% of the panel's
	 * 23.49MHz spec.  First hardware boot proved we cannot trust
	 * whatever S-Boot left in VIDCON0's clock fields. */
	writel((readl((void *)(EXYNOS4210_CMU_BASE + 0xC234)) & ~0xf),
	       (void *)(EXYNOS4210_CMU_BASE + 0xC234));	/* FIMD0_SEL=XXTI */
	writel((readl((void *)(EXYNOS4210_CMU_BASE + 0xC534)) & ~0xf),
	       (void *)(EXYNOS4210_CMU_BASE + 0xC534));	/* FIMD0_RATIO=0 */
	writel(readl((void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_GATE_IP_LCD0)) | 1,
	       (void *)(EXYNOS4210_CMU_BASE + EXYNOS4210_CLK_GATE_IP_LCD0));

	/* VIDCON0: VIDOUT(0)=RGB I/F, PNRMODE(0)=RGB parallel, CLKVAL_F=0,
	 * CLKDIR=0, CLKSEL_F=0 -> VCLK = SCLK_FIMD0 = 24MHz, ENVID|ENVID_F. */
	vidcon0 = EXYNOS4210_FIMD_VIDCON0_ENVID |
		  EXYNOS4210_FIMD_VIDCON0_ENVID_F;
	writel(vidcon0, (void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
}

int i9100_init(void)
{
	uint32_t vidcon0 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
	uint32_t fb_pa = FB_FALLBACK;

	i9100_fimd_report();

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

	/* Always scan our own fixed buffer at FB_FALLBACK, even when S-Boot
	 * left a live splash.  The kernel contract pins Video.v_baseAddr to
	 * 0x5E000000 (i9100_video_ok validates it, and pmap excludes that
	 * window from the managed pool), so adopting S-Boot's buffer would
	 * both break the address contract and hide all kernel console
	 * output.  Reprogramming window 0 keeps the contract, guarantees
	 * ARGB8888 regardless of S-Boot's pixel format, and makes kernel
	 * text visible on the real panel.  Panel/backlight (LD9040 SPI
	 * init) stay as S-Boot left them; the VIDTCON values written here
	 * match the timings S-Boot programs anyway. */
	i9100_fimd_init(fb_pa);
	if (vidcon0 & (EXYNOS4210_FIMD_VIDCON0_ENVID |
		       EXYNOS4210_FIMD_VIDCON0_ENVID_F))
		printk(KERN_INFO,
		       "fimd: retargeted live S-Boot scanout to fb @%08x\n",
		       fb_pa);
	else
		printk(KERN_INFO, "fimd: initialized own fb @%08x\n", fb_pa);

	/* Stage marker I: YELLOW band = board early_init done. */
	{
		volatile unsigned int *fb = (volatile unsigned int *)fb_pa;
		unsigned int i;

		for (i = 0; i < FB_WIDTH * 24; i++)
			fb[(0x128000 >> 2) + i] = 0xFFFFFF00;
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
#if defined(CONFIG_EXYNOS_SDHCI4210)
	sd_host_probe_4210();
#endif
#if defined(CONFIG_EXYNOS_CDCACM4210)
	/* Bring the DWC2 device up *before* the multi-minute SD staging:
	 * the host enumerates us while we stream I9S progress to both
	 * the panel and the fresh COM port.  usbcdc_poll() is driven
	 * from the console write path, so every printk services EP0.
	 * Returns nonzero when the OTG block is absent (QEMU) - the
	 * console simply never registers. */
	usbcdc4210_init();
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
