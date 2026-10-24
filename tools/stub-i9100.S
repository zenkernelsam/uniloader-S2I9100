/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Bring-up smoke stub for GT-I9100 uniloader: NOT a real kernel.
 * Loaded at PAYLOAD_ENTRY, entered at offset 0.  Spam 'X' on UART2
 * and paint a magenta stripe into the FIMD framebuffer so we can
 * prove the loader->payload jump works without XNU.
 *
 * Build:  arm-none-eabi-as -o stub-i9100.o stub-i9100.S
 *         arm-none-eabi-objcopy -O binary stub-i9100.o ../blob/Image
 */

	.syntax	unified
	.arm

	.equ	UART2_UTRSTAT,	0x13820010
	.equ	UART2_UTXH,	0x13820020
	.equ	FB_BASE,	0x5E000000	/* matches board FB_FALLBACK */

	.globl	_start
_start:
	ldr	sp, =0x45000000

	/* QEMU's UART starts TX-disabled; program ULCON/UCON/UFCON/UMCON
	 * so 'X' actually reaches the chardev. */
	ldr	r4, =0x13820000
	mov	r0, #0x03
	str	r0, [r4, #0x00]		/* ULCON: 8N1 */
	ldr	r0, =0x3C5
	str	r0, [r4, #0x04]		/* UCON: rx+tx polling */
	mov	r0, #0
	str	r0, [r4, #0x08]		/* UFCON: fifo off */
	str	r0, [r4, #0x0C]		/* UMCON */
	mov	r0, #53
	str	r0, [r4, #0x28]		/* UBRDIV */
	mov	r0, #4
	str	r0, [r4, #0x2C]		/* UFRACVAL */
	/* paint 64 lines of magenta into the adopted framebuffer */
	ldr	r1, =FB_BASE
	ldr	r2, =0xFFFF00FF
	mov	r3, #(480 * 64)
1:	str	r2, [r1], #4
	subs	r3, r3, #1
	bne	1b

	/* UART spam loop: 'X' forever */
2:	ldr	r4, =UART2_UTRSTAT
	ldr	r0, [r4]
	tst	r0, #2			/* TX buffer empty? */
	beq	2b
	mov	r0, #'X'
	ldr	r4, =UART2_UTXH
	str	r0, [r4]
	mov	r0, #0x100000
3:	subs	r0, r0, #1
	bne	3b
	b	2b
