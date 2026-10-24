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
	/* LD9040 timing from exynos4210-i9100.dts:
	 * pclk 23492370, hactive 480 hbp 16 hfp 16 hsync 2,
	 * vactive 800 vbp 2 vfp 28 vsync 1. */
	writel((2 << 16) | (28 << 8) | 1,	/* VBPD VFPD VSPW */
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDTCON0));
	writel((16 << 16) | (16 << 8) | 2,	/* HBPD HFPD HSPW */
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

	writel(EXYNOS4210_FIMD_VIDCON0_ENVID |
	       EXYNOS4210_FIMD_VIDCON0_ENVID_F,
	       (void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
}

int i9100_init(void)
{
	uint32_t vidcon0 = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDCON0));
	uint32_t fb_pa;

	i9100_fimd_report();

	if (vidcon0 & (EXYNOS4210_FIMD_VIDCON0_ENVID |
		       EXYNOS4210_FIMD_VIDCON0_ENVID_F)) {
		/* S-Boot splash is live: adopt its window-0 buffer. */
		fb_pa = readl((void *)(FIMD + EXYNOS4210_FIMD_VIDW00ADD0B0));
		i9100_fb.address = (void *)fb_pa;
		printk(KERN_INFO, "fimd: adopted S-Boot fb @%08x\n", fb_pa);
	} else {
		/* No running scanout (QEMU -kernel boot): own the FIMD. */
		fb_pa = FB_FALLBACK;
		i9100_fimd_init(fb_pa);
		printk(KERN_INFO, "fimd: initialized own fb @%08x\n", fb_pa);
	}

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

/* Runs after driver_probe_all(): the simplefb console is live, so
 * printk() output lands on the panel. */
static int i9100_late_init(void)
{
	sd_host_probe_4210();
	return 0;
}
#endif

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
