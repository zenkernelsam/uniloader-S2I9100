/* i9100 CPU1 bring-up trampoline v6 — ARM mode, position independent.
 * Entered at PHYSICAL address, MMU/caches off.  Writes a stage marker
 * into alive_phys at each step so CPU0 can see how far it got.
 * Data tail (filled by CPU0):
 *   [0] TTBR0 [1] TTBR1 [2] TTBCR [3] DACR
 *   [4] SCTLR [5] VBAR  [6] SP    [7] ENTRY
 *   [8] alive_phys      [9] hb_phys                                    */
	.syntax unified
	.arm
	.globl tramp_start
tramp_start:
	cpsid	if
	adr	r4, tramp_data
	mov	r1, #1
	ldr	r0, [r4, #32]
	str	r1, [r0]			@ stage 1: entered
	dsb	sy
	ldm	r4, {r5-r12}
	mov	r1, #2
	str	r1, [r0]			@ stage 2
	mov	r0, #0
	mcr	p15, 0, r0, c8, c7, 0	@ TLBIALL
	mcr	p15, 0, r0, c7, c5, 0	@ ICIALLU
	mcr	p15, 0, r0, c7, c5, 6	@ BPIALL
	dsb
	isb
	ldr	r0, [r4, #32]
	mov	r1, #3
	str	r1, [r0]			@ stage 3
	mcr	p15, 0, r5, c2, c0, 0	@ TTBR0
	mcr	p15, 0, r6, c2, c0, 1	@ TTBR1
	mcr	p15, 0, r7, c2, c0, 2	@ TTBCR
	mcr	p15, 0, r8, c3, c0, 0	@ DACR
	mcr	p15, 0, r10, c12, c0, 0	@ VBAR
	ldr	r0, [r4, #32]
	mov	r1, #4
	str	r1, [r0]			@ stage 4
	/* identity-map our own 1MB inside TTBR1 (index = PC[31:20]).
	 * TTBR1 low 14 bits are IRGN/S attributes — mask to the real
	 * 16KB L1 base before adding the slot offset, or the write
	 * lands 0x18 late and corrupts a different entry. */
	mov	r0, pc, lsr #20
	mov	r1, r6, lsr #14		@ TTBR1 L1 base = reg & ~0x3FFF
	mov	r1, r1, lsl #14		@ (bic imm 0x3fff not encodable)
	add	r1, r1, r0, lsl #2
	ldr	r2, [r1]
	cmp	r2, #0
	bne	1f
	movw	r2, #0xC0E
	orr	r2, r2, r0, lsl #20
	str	r2, [r1]
	mov	r2, #0
	mcr	p15, 0, r2, c8, c7, 0	@ TLBIALL: drop stale walk
	mcr	p15, 0, r2, c7, c5, 0	@ ICIALLU
	dsb	sy
	isb
1:
	mrc	p15, 0, r0, c1, c0, 1	@ ACTLR
	orr	r0, r0, #0x40
	orr	r0, r0, #0x1
	mcr	p15, 0, r0, c1, c0, 1
	isb
	mrc	p15, 0, r0, c1, c0, 0	@ SCTLR
	orr	r0, r0, r9
	mcr	p15, 0, r0, c1, c0, 0
	dsb	sy
	isb
	/* MMU on: r4/alive/PC now resolve via the identity section */
	ldr	r0, [r4, #32]
	mov	r1, #5
	str	r1, [r0]			@ stage 5
	mov	sp, r11
	mrs	r0, cpsr
	bic	r1, r0, #0x1f
	orr	r2, r1, #0x12		@ IRQ
	msr	cpsr_c, r2
	mov	sp, r11
	orr	r2, r1, #0x17		@ ABT
	msr	cpsr_c, r2
	mov	sp, r11
	orr	r2, r1, #0x1b		@ UND
	msr	cpsr_c, r2
	mov	sp, r11
	orr	r2, r1, #0x11		@ FIQ
	msr	cpsr_c, r2
	mov	sp, r11
	msr	cpsr_c, r0
	mov	sp, r11
	ldr	r0, [r4, #32]
	mov	r1, #6
	str	r1, [r0]			@ stage 6: stacks seeded
	bx	r12
	.align	4
	.globl tramp_data
tramp_data:
	.word	0,0,0,0,0,0,0,0,0,0
