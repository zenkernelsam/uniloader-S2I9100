// SPDX-License-Identifier: GPL-2.0-only
/*
 * Host-side DWMMC/eMMC simulator for the sdhci4210.c eMMC probe path.
 * The real driver source is #included; readl/writel are rerouted to a
 * scripted card model behind the 0x12550000 register window.
 *
 * Card model: standard eMMC state machine (idle->ready->ident->stby->
 * tran->rcv).  Answers CMD0/1/2/3/7/9/16/17/24 with correct R1/R2/R3
 * semantics, feeds 128 words per block through FIFODAT@0x100, and
 * self-clears CMD_STRT on completion — matching MSHC behaviour.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/mman.h>

#define DWMMC_ADDR	0x12550000u

/* ---------------- eMMC card model ---------------- */

static uint32_t dwmmc[0x400];		/* register file 0x000..0xFFF */
static uint32_t resp[4];
static uint32_t pending;		/* RINTSTS bits */
static uint32_t rxq[128];		/* card -> host data */
static unsigned rx_len, rx_pos;
static uint32_t txq[128];		/* host -> card data */
static unsigned tx_pos;
static int card_state;			/* 0 idle 1 ready 2 ident 3 stby 4 tran 5 data 6 rcv */
static int cmd1_polls;
static uint32_t card_rca;
struct wr_rec { uint32_t lba, data[128]; };
static struct wr_rec writes[8];
static unsigned nwrites;

#define INT_CDETECT	(1u << 0)
#define INT_CDONE	(1u << 2)
#define INT_DTO		(1u << 3)
#define INT_TXDR	(1u << 4)
#define INT_RXDR	(1u << 5)
#define CMD_STRT	(1u << 31)
#define CMD_UPD_CLK	(1u << 21)
#define CMD_DATA_EXP	(1u << 9)
#define CMD_DAT_WR	(1u << 10)
#define ST_FIFO_EMPTY	(1u << 2)
#define ST_FIFO_FULL	(1u << 3)
#define ST_DATA_BUSY	(1u << 9)
#define ST_FIFO_COUNT	(0x1FFFu << 17)

/* controller bits the IDMAC path touches */
#define SIM_CTRL_USE_IDMAC	(1u << 25)
#define SIM_CTRL_RESETS		0x7	/* self-clearing reset bits */
#define SIM_BMOD_SWRESET	(1u << 0)
#define SIM_BMOD_ENABLE		(1u << 7)
#define SIM_IDMAC_TI		(1u << 0)
#define SIM_IDMAC_RI		(1u << 1)
#define SIM_IDMAC_NI		(1u << 8)
#define SIM_DES0_OWN		(1u << 31)

static uint32_t idsts;			/* 0x8C, W1C */

/* Data the card would put on the wire for a given LBA — shared by
 * the PIO FIFO queue and the IDMAC drain. */
static uint32_t block_word(uint32_t lba, unsigned w)
{
	if (nwrites && lba == writes[nwrites - 1].lba)
		return writes[nwrites - 1].data[w];
	if (lba == 73728 && w == 9)
		return 0x016F2818;
	return 0xA5A50000 | (w & 0xff);
}

static void card_cmd(unsigned idx, uint32_t arg, uint32_t flags)
{
	pending = 0;

	if (flags & CMD_UPD_CLK)	/* clock-update pseudo-command */
		return;

	resp[0] = 0x00000700;		/* R1: state field tran-ish */
	switch (idx) {
	case 0:  card_state = 0; break;
	case 1:
		/* two busy answers then ready, exercises the retry loop */
		if (++cmd1_polls < 3)
			resp[0] = 0x40FF8000;		/* not-ready OCR */
		else
			resp[0] = 0xC0FF8000;		/* ready + sector */
		break;
	case 2:	/* CID */
		resp[0] = 0x56495330; resp[1] = 0x304D0000;
		resp[2] = 0xDEADBEEF; resp[3] = 0x01020304;
		card_state = 2; break;
	case 3:
		card_rca = arg & 0xffff0000;
		resp[0] = 0x00000700;
		card_state = 3; break;
	case 9:	/* CSD */
		resp[0] = 0x400E0032; resp[1] = 0x5B590000;
		resp[2] = 0x0F7F8000; resp[3] = 0x8A40401F;
		break;
	case 7:  card_state = 4; break;
	case 16: resp[0] = 0x00000900; break;
	case 17: {	/* single block read */
		unsigned w;
		uint32_t lba = arg;
		rx_len = rx_pos = 0;
		if (dwmmc[0x00 / 4] & SIM_CTRL_USE_IDMAC) {
			/* IDMAC drains the FIFO straight to DRAM: fetch the
			 * descriptor at DBADDR, copy the block to des2.  The
			 * driver places both in the mmap'd forensic page, so
			 * the physicals are plain host pointers here. */
			volatile uint32_t *d =
				(volatile uint32_t *)(uintptr_t)
				dwmmc[0x88 / 4];
			volatile uint32_t *dst =
				(volatile uint32_t *)(uintptr_t)d[2];
			if (!(d[0] & SIM_DES0_OWN)) {
				pending |= (1u << 15);	/* EBE: bad desc */
				break;
			}
			for (w = 0; w < 128; w++)
				dst[w] = block_word(lba, w);
			d[0] &= ~SIM_DES0_OWN;
			idsts = SIM_IDMAC_TI | SIM_IDMAC_NI;
			pending |= INT_DTO;
		} else {
			for (w = 0; w < 128; w++)
				rxq[w] = block_word(lba, w);
			rx_len = 128;
			pending |= INT_RXDR;
		}
		card_state = 5;
		break;
	}
	case 24:	/* single block write: fifo words land via FIFODAT */
		tx_pos = 0;
		pending |= INT_TXDR;
		card_state = 6;
		if (nwrites < 8)
			writes[nwrites].lba = arg;
		break;
	}
	pending |= INT_CDONE;
}

/* ---------------- mmio dispatch ---------------- */

uint32_t readl(volatile uint32_t *addr)
{
	uintptr_t a = (uintptr_t)addr;
	uint32_t off;

	if ((a & ~0xFFFu) != DWMMC_ADDR)
		return 0;			/* unmapped: benign zero */
	off = a & 0xFFF;

	switch (off) {
	case 0x40: case 0x44:			/* MINTSTS / RINTSTS */
		return pending;
	case 0x8C:				/* IDSTS */
		return idsts;
	case 0x48: {				/* STATUS */
		uint32_t s = 0;
		unsigned depth = rx_len - rx_pos;
		if (!depth)
			s |= ST_FIFO_EMPTY;
		if (card_state == 6)
			s |= 0;			/* tx fifo drains instantly */
		if (card_state == 5 && depth)
			s |= ST_DATA_BUSY;
		s |= ((unsigned)(depth & 0x1fff)) << 17;
		return s;
	}
	case 0x50:				/* CDETECT: 0 = inserted */
		return 0;
	case 0x100:				/* FIFODAT */
#ifdef SIM_PIO_ZERO
		/* the upstream quirk: FIFO drains but the CPU data port
		 * reads back zeros — drives the driver's IDMAC fallback */
		if (rx_pos < rx_len) {
			rx_pos++;
			if (rx_pos >= rx_len)
				pending |= INT_DTO;
		}
		return 0;
#else
		if (rx_pos < rx_len) {
			uint32_t v = rxq[rx_pos++];
			if (rx_pos >= rx_len)
				pending |= INT_DTO;
			return v;
		}
		return 0;
#endif
	case 0x30: case 0x34: case 0x38: case 0x3C:
		return resp[(off - 0x30) / 4];
	case 0x2C:				/* M_CMD: STRT self-cleared */
		return dwmmc[off / 4] & ~CMD_STRT;
	default:
		return dwmmc[off / 4];
	}
}

void writel(unsigned int value, void *addr)
{
	uintptr_t a = (uintptr_t)addr;
	uint32_t off;

	if ((a & ~0xFFFu) != DWMMC_ADDR)
		return;
	off = a & 0xFFF;

	if (off == 0x44) {			/* RINTSTS write-to-clear */
		pending &= ~value;
		return;
	}
	if (off == 0x8C) {			/* IDSTS write-to-clear */
		idsts &= ~value;
		return;
	}
	if (off == 0x00) {			/* CTRL: reset bits self-clear */
		dwmmc[0] = value & ~SIM_CTRL_RESETS;
		return;
	}
	if (off == 0x80) {			/* BMOD: SWRESET self-clears */
		dwmmc[0x80 / 4] = value & ~SIM_BMOD_SWRESET;
		return;
	}
	if (off == 0x100) {			/* FIFODAT write */
		if (card_state == 6 && tx_pos < 128 && nwrites < 8) {
			writes[nwrites].data[tx_pos++] = value;
			if (tx_pos >= 128) {
				nwrites++;
				pending |= INT_DTO;
			}
		}
		return;
	}
	dwmmc[off / 4] = value;
	if (off == 0x2C && (value & CMD_STRT))
		card_cmd(value & 0x3f, dwmmc[0x28 / 4], value);
}

/* ---------------- console stubs ---------------- */

void printk(int level, const char *fmt, ...)
{
	va_list ap;
	(void)level;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

#include <lib/debug.h>
#include <lib/console.h>

void console_register(const struct console *con) { (void)con; }

#include "../../uniloader-S2I9100/drivers/samsung/sdhci4210.c"

/* ---------------- tests ---------------- */

static int fails;
#define CHECK(cond, msg) do { \
		if (cond) { printf("  PASS %s\n", msg); } \
		else { printf("  FAIL %s\n", msg); fails++; } \
	} while (0)

int main(void)
{
	uint32_t rb[128];
	int rc;

	printf("== dwmmc/eMMC probe simulator ==\n");

	/* sec_log_emit touches the ring through raw pointers, not
	 * readl/writel — back the real addresses with an anonymous
	 * mapping so pointer accesses land on RAM instead of faulting. */
	if (mmap((void *)0x4D800000, 0x200000,
		 PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
	    == MAP_FAILED) {
		perror("mmap sec_log");
		return 1;
	}
	/* Same for the DRAM forensic cells at 0x7FFE0000 (FORENSIC_CELL_*
	 * are memcpy'd through raw pointers). */
	if (mmap((void *)0x7FFE0000, 0x1000,
		 PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
	    == MAP_FAILED) {
		perror("mmap dramcell");
		return 1;
	}

	/* full probe: CMD0 -> CMD1(retry) -> 2 -> 3 -> 9 -> 7 -> 16 -> rd LBA73728 */
	rc = mmc_probe_emmc();
	printf("[probe] rc=%d stage=%u xfer_ok=%d hcs=%d cmd1_polls=%d\n",
	       rc, sd_probe_stage, emmc_xfer_ok, sd_hcs, cmd1_polls);
	CHECK(rc == 0, "probe succeeds");
	CHECK(emmc_xfer_ok == 1, "xfer_ok after CMD16");
	CHECK(cmd1_polls >= 3, "CMD1 retry loop exercised");
	CHECK(sd_probe_stage >= 15, "stage>=15");

	/* stage-16 record should hold the KERNEL zImage magic via emmc_record;
	 * verify the readback directly as well */
	rc = dw_read_block(73728, rb);
	CHECK(rc == 0, "dw_read_block KERNEL ok");
	CHECK(rb[9] == 0x016F2818, "zImage magic readback");
#ifdef SIM_PIO_ZERO
	printf("  (pio-zero build: fallback path exercised above)\n");
#endif

	/* the IDMAC path itself, on its own feet */
	memset(rb, 0, sizeof(rb));
	rc = dw_read_block_idmac(73728, rb);
	CHECK(rc == 0, "dw_read_block_idmac ok");
	CHECK(rb[9] == 0x016F2818, "idmac magic readback");

	/* The probe itself writes one EM1B record to LBA90109 per stage
	 * once emmc_xfer_ok is set — that IS the forensic channel, so
	 * those writes land in writes[] before ours.  Validate them and
	 * then check OUR write is the last one recorded. */
	CHECK(nwrites >= 2, "probe stage records hit LBA90109");
	CHECK(writes[0].lba == 90109 &&
	      writes[0].data[0] == 0x454D3142, "EM1B record well-formed");
	{
		uint32_t wb[128];
		unsigned i;
		for (i = 0; i < 128; i++)
			wb[i] = 0x12340000 | i;
		rc = dw_write_block(90109, wb);
		CHECK(rc == 0, "dw_write_block ok");
		CHECK(writes[nwrites - 1].lba == 90109, "write landed LBA90109");
		CHECK(writes[nwrites - 1].data[9] == 0x12340009,
		      "write data intact");
		memset(rb, 0, sizeof(rb));
		rc = dw_read_block(90109, rb);
		CHECK(rc == 0, "readback ok");
		CHECK(rb[9] == 0x12340009, "roundtrip data match");
	}

	printf("== %d failures ==\n", fails);
	return fails ? 1 : 0;
}
