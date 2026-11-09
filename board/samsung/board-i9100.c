/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Samsung Galaxy S2 (GT-I9100, i9100) support
 * for uniLoader. Exynos 4210, 480x800 Super AMOLED Plus.
 *
 * S-Boot leaves the FIMD display controller scanning out a boot logo
 * framebuffer (typically at 0x43E00000 or as programmed in VIDW00ADD0B0),
 * so we reuse it as a simplefb console.
 */

#include <board.h>
#include <util.h>
#include <stdint.h>
#include <string.h>
#include <drivers/framework.h>
#include <lib/simplefb.h>
#include <lib/debug.h>
#include <soc/exynos4210.h>

#if defined(CONFIG_EXYNOS_CDCACM4210)
extern int usbcdc4210_init(void);
extern void usbcdc_poll(void);
#endif

#ifndef CONFIG_XNU_FB_BASE
#define CONFIG_XNU_FB_BASE	0x43E00000
#endif

#define FB_DEFAULT_ADDRESS	CONFIG_XNU_FB_BASE
#define FB_WIDTH		480
#define FB_HEIGHT		800

static struct video_info i9100_fb = {
	.format = FB_FORMAT_ARGB8888,
	.width = FB_WIDTH,
	.height = FB_HEIGHT,
	.stride = 4,
	.address = (void *)FB_DEFAULT_ADDRESS
};

extern unsigned int boot_reg_r0, boot_reg_r1, boot_reg_r2;

struct atag_videolfb {
	uint16_t lfb_width;
	uint16_t lfb_height;
	uint16_t lfb_depth;
	uint16_t lfb_linelength;
	uint32_t lfb_base;
	uint32_t lfb_size;
};

int i9100_is_real_hardware(void)
{
	extern unsigned int boot_reg_r1, boot_reg_r2;
	volatile uint32_t *atag = (volatile uint32_t *)0x40000100;
	if (atag[1] == 0x54410001)
		return 1;
	if (boot_reg_r1 != 0 || boot_reg_r2 != 0)
		return 1;
	return 0;
}

static uint32_t parse_atag_fb(void)
{
	extern unsigned int boot_reg_r2;
	volatile uint32_t *p = (volatile uint32_t *)(boot_reg_r2 ? boot_reg_r2 : 0x40000100);
	if (p[1] != 0x54410001) /* ATAG_CORE */
		return 0;
	while (*p) {
		uint32_t sz = p[0];
		uint32_t tag = p[1];
		if (tag == 0x54410008) { /* ATAG_VIDEOLFB */
			struct atag_videolfb *v = (struct atag_videolfb *)&p[2];
			if (v->lfb_base >= 0x40000000 && v->lfb_base < 0x80000000)
				return v->lfb_base;
		}
		p += sz;
		if (p > (volatile uint32_t *)0x40002000)
			break;
	}
	return 0;
}

#include <main/i9100-previous-boot.h>
struct I9100PreviousBoot i9100_previous_boot;
int i9100_init(void)
{
	volatile uint32_t *trace = (volatile uint32_t *)0x10020818;
	volatile uint32_t *cell = (volatile uint32_t *)0x7ffe0000;
	uint32_t previous = trace[0], reason = trace[1];
	uint32_t ddr_valid = cell[0] == 0xcafebabeU && cell[1] <= 0xffffU;
	uint32_t ddr_stage = ddr_valid ? cell[1] : 0;
	uint32_t ddr_reason = ddr_valid ? cell[2] : 0;
	uint32_t pc = ddr_valid ? cell[3] : 0;
	memset(&i9100_previous_boot,0,sizeof(i9100_previous_boot));
	i9100_previous_boot.magic=I9100_PREVIOUS_BOOT_MAGIC;
	i9100_previous_boot.version=1;
	i9100_previous_boot.bytes=sizeof(i9100_previous_boot);
	i9100_previous_boot.valid=((previous&0xffff0000U)==0x77660000U ? 1U : 0U) |
	    (ddr_valid ? 2U : 0U);
	i9100_previous_boot.inform6=previous;i9100_previous_boot.inform7=reason;
	i9100_previous_boot.stage=ddr_stage;i9100_previous_boot.reason=ddr_reason;
	i9100_previous_boot.pc=pc;
	if (ddr_valid) {
		i9100_previous_boot.lr=cell[4];i9100_previous_boot.far=cell[5];
		i9100_previous_boot.fsr=cell[6];
		if (cell[11]==0x43505931U) {
			i9100_previous_boot.valid|=4U;
			for (unsigned n=0;n<4;n++)i9100_previous_boot.reserved[n]=cell[7+n];
		}
	}
	/* Consume the previous record before starting another attempt. */
	cell[0] = 0;
	trace[0] = 0x77660001U;
	trace[1] = 0;
	__asm__ __volatile__("dsb sy" ::: "memory");
	volatile uint32_t *fimd = (volatile uint32_t *)0x11C00000;
	volatile uint32_t *sysreg = (volatile uint32_t *)0x10010000;

	/* Enable FIMD bypass in SYSREG */
	sysreg[0x210 / 4] |= (1 << 1);
	/* QEMU has no S-Boot panel initialization. Leaving VIDTCON2 at
	 * reset makes its global surface 1x1 while window 0 is 480x800,
	 * which corrupts the 6.2 FIMD model's host-side framebuffer. */
	if (!i9100_is_real_hardware() && fimd[0x18 / 4] == 0) {
		fimd[0x10 / 4] = (1U << 16) | (27U << 8);
		fimd[0x14 / 4] = (15U << 16) | (15U << 8) | 1U;
		fimd[0x18 / 4] = ((FB_HEIGHT - 1) << 11) | (FB_WIDTH - 1);
	}

	uint32_t live_buf = fimd[0xA0 / 4];
	if (live_buf >= 0x40000000 && live_buf < 0x80000000) {
		i9100_fb.address = (void *)live_buf;
	} else {
		uint32_t detected = parse_atag_fb();
		if (detected)
			i9100_fb.address = (void *)detected;
		else
			i9100_fb.address = (void *)FB_DEFAULT_ADDRESS;
	}

	/* Disable overlay windows 1, 2, 3, 4 */
	fimd[0x24 / 4] = 0;
	fimd[0x28 / 4] = 0;
	fimd[0x2C / 4] = 0;
	fimd[0x30 / 4] = 0;

	/* Clear PRTCON protect */
	fimd[0x0C / 4] = 0;

	/* Protect shadow registers during configuration */
	fimd[0x34 / 4] = (1 << 10) | 1;

	/* Repoint window 0 */
	fimd[0xA0 / 4] = (uint32_t)i9100_fb.address;
	fimd[0xD0 / 4] = (uint32_t)i9100_fb.address + FB_WIDTH * FB_HEIGHT * 4;
	fimd[0x100 / 4] = (FB_WIDTH * 4) | (0 << 13);
	fimd[0x40 / 4] = 0;
	fimd[0x44 / 4] = ((FB_WIDTH - 1) << 11) | (FB_HEIGHT - 1);
	fimd[0x48 / 4] = FB_WIDTH * FB_HEIGHT;

	uint32_t w0 = fimd[0x20 / 4];
	fimd[0x20 / 4] = (w0 & ~(0xF << 2)) | (11 << 2) | (1 << 15) | 1;

	/* Unprotect shadow */
	fimd[0x34 / 4] = 1;

	/* Enable video output */
	fimd[0x00 / 4] |= 3;

	/* Forward RGB */
	fimd[0x2020 / 4] = 0;

	/* Clear framebuffer to black */
	{
		volatile unsigned int *fb = (volatile unsigned int *)i9100_fb.address;
		unsigned int i;

		for (i = 0; i < FB_WIDTH * FB_HEIGHT; i++) fb[i] = 0xFF000000; /* BLACK */
	}

	/* Trigger I80 command */
	fimd[0x1A4 / 4] = 3;

#if defined(CONFIG_EXYNOS_CDCACM4210)
	/* Bring the CDC ACM console up as early as the panel is live; its
	 * usbcon_write() hook also services EP0 on every printk. */
	usbcdc4210_init();
#endif
	if ((previous & 0xffff0000U) == 0x77660000U)
		printk(KERN_INFO, "i9100: previous stage=%08x reason=%08x pc=%08x\n",
		       previous, reason, pc);
	else if (ddr_valid)
		printk(KERN_INFO, "i9100: previous DDR stage=%08x reason=%08x pc=%08x\n",
		       ddr_stage, ddr_reason, pc);

	return 0;
}

void uart_puts(const char *s)
{
	while (*s) {
		char c = *s++;

		/* On real hardware, only use UART2 (Micro-USB).
		 * Do NOT touch UART0: on real hardware, UART0 is the Bluetooth port
		 * and is clock-gated / unpowered at boot, causing bus hangs! */
		if (i9100_is_real_hardware()) {
			unsigned int t2 = 10000;
			while (!(readl((void *)(EXYNOS4210_UART2_BASE + EXYNOS4210_UTRSTAT))
				 & EXYNOS4210_UTRSTAT_TX_EMPTY)) {
				if (!--t2)
					break;
			}
			if (t2) {
				writel((unsigned int)(c & 0xff),
				       (void *)(EXYNOS4210_UART2_BASE + EXYNOS4210_UTXH));
			}
		} else {
			/* In QEMU, UART0 is the main terminal console */
			unsigned int t0 = 50000;
			while (!(readl((void *)(EXYNOS4210_UART0_BASE + EXYNOS4210_UTRSTAT))
				 & EXYNOS4210_UTRSTAT_TX_EMPTY)) {
				if (!--t0)
					break;
			}
			if (t0) {
				writel((unsigned int)(c & 0xff),
				       (void *)(EXYNOS4210_UART0_BASE + EXYNOS4210_UTXH));
			}
		}
	}
}

unsigned int i9100_hw_revision = 0xffffffffU;

static int i9100_late_init(void)
{
	if (!i9100_is_real_hardware())
		return 0;

	extern unsigned int boot_reg_r2;
	volatile uint32_t *p = (volatile uint32_t *)(boot_reg_r2 ? boot_reg_r2 : 0x40000100);
	const char *cmdline = NULL;

	/* Bound ATAG traversal before using the revision to select charger wiring.
	 * Stop at malformed lengths; an absent revision remains explicitly unknown. */
	unsigned int atag_addr = (unsigned int)p;
	if (atag_addr >= 0x40000000U && atag_addr < 0x40010000U && !(atag_addr & 3U)) {
		unsigned int end = atag_addr + 4096U;
		if (end > 0x40010000U) end = 0x40010000U;
		while ((unsigned int)p + 8U <= end) {
			unsigned int sz = p[0], tag = p[1];
			if (!sz || sz < 2 || sz > (end - (unsigned int)p) / 4U) break;
			if (tag == 0x54410007U && sz >= 3 && p[2] <= 15)
				i9100_hw_revision = p[2];
			if (tag == 0x54410009U && sz > 2) {
				const char *text = (const char *)&p[2];
				unsigned int bytes = (sz - 2U) * 4U, n;
				for (n = 0; n < bytes && text[n]; n++) { }
				if (n < bytes) cmdline = text;
			}
			p += sz;
		}
	}
	printk(KERN_INFO, "i9100: hardware revision=%08x (ATAG)\n", i9100_hw_revision);

	int percent = -1;
	int mv = -1;

	if (cmdline) {
		const char *s = cmdline;
		while (*s) {
			if ((s[0] == 'b' && s[1] == 'a' && s[2] == 't') ||
			    (s[0] == 's' && s[1] == 'o' && s[2] == 'c') ||
			    (s[0] == 'c' && s[1] == 'a' && s[2] == 'p')) {
				while (*s && *s != '=' && *s != ' ' && (*s < '0' || *s > '9')) s++;
				if (*s == '=') s++;
				int val = 0;
				while (*s >= '0' && *s <= '9') {
					val = val * 10 + (*s - '0');
					s++;
				}
				if (val > 0 && val <= 100) {
					percent = val;
				} else if (val >= 2500 && val <= 4500) {
					mv = val;
				}
			} else {
				s++;
			}
		}
	}

	if (percent >= 0 && mv >= 0) {
		printk(KERN_INFO, "battery: %d%% (%d.%02dV)\n", percent, mv / 1000, (mv % 1000) / 10);
	} else if (percent >= 0) {
		printk(KERN_INFO, "battery: %d%%\n", percent);
	} else if (mv >= 0) {
		printk(KERN_INFO, "battery: %d.%02dV\n", mv / 1000, (mv % 1000) / 10);
	} else {
		printk(KERN_INFO, "battery: telemetry deferred to XNU\n");
	}

	return 0;
}

static const struct device i9100_devices[] = {
	{ "simplefb", &i9100_fb, "fb" },
};

struct board_data board_ops = {
	.name = "samsung-i9100",
	.ops = {
		.early_init = i9100_init,
		.late_init = i9100_late_init,
	},
	.devices = i9100_devices,
	.num_devices = ARRAY_SIZE(i9100_devices),
	.quirks = 0
};
