
/* ---------------- I9100 USB CDC debug console (kernel side) -----------
 * Continuation of uniLoader's dwc2cdc4210 gadget: the DWC2 OTG device
 * @0x12480000 is adopted as-is when uniLoader enumerated it (the COM
 * port on the PC then stays open across the loader->kernel boundary),
 * or fully re-enumerated when it was not.  Pure polled slave mode,
 * driven from ios7j1_debug_putc: every kprintf char feeds a 4KB ring
 * and pumps EP1-IN; EP0 control traffic is serviced as a side effect.
 * No IRQs, no DMA, every wait bounded - a dead/absent/absorbed-by-QEMU
 * controller can never stall the kernel.  Panic text rides the same
 * putc, so the serial wire sees crash dumps live.
 */

#define I9100_DWC2_PA	0x12480000U
#define I9100_PHY_PA	0x125B0000U
#define I9100_PMU_USBPHY	0x10020704U

static vm_offset_t i9100_usb_map;

#define UREG(x) (*(volatile unsigned int *) \
		 (i9100_usb_map ? i9100_usb_map + (x) : I9100_DWC2_PA + (x)))
#define UGOTGCTL	UREG(0x000)
#define UGAHBCFG	UREG(0x008)
#define UGUSBCFG	UREG(0x00C)
#define UGRSTCTL	UREG(0x010)
#define UGINTSTS	UREG(0x014)
#define UGRXSTSP	UREG(0x020)
#define UGRXFSIZ	UREG(0x024)
#define UGNPTXFSIZ	UREG(0x028)
#define UGNPTXSTS	UREG(0x02C)
#define UGSNPSID	UREG(0x040)
#define UDPTXF(n)	UREG(0x104 + ((n) - 1) * 4)
#define UDCFG		UREG(0x800)
#define UDCTL		UREG(0x804)
#define UDSTS		UREG(0x808)
#define UDIEPMSK	UREG(0x810)
#define UDOEPMSK	UREG(0x814)
#define UDAINT		UREG(0x818)
#define UDAINTMSK	UREG(0x81C)
#define UIEP(n)		UREG(0x900 + (n) * 0x20)
#define UOEP(n)		UREG(0xB00 + (n) * 0x20)
#define UDIEPCTL(n)	UIEP(n)
#define UDIEPINT(n)	UREG(0x908 + (n) * 0x20)
#define UDIEPTSIZ(n)	UREG(0x910 + (n) * 0x20)
#define UDOEPCTL(n)	UOEP(n)
#define UDOEPINT(n)	UREG(0xB08 + (n) * 0x20)
#define UDOEPTSIZ(n)	UREG(0xB10 + (n) * 0x20)
#define UDTXFSTS(n)	UREG(0x918 + (n) * 0x20)
#define UFIFO(n)	UREG(0x1000 + (n) * 0x1000)
#define UPCGCCTL	UREG(0xE00)
#define UPHYREG(x)	(*(volatile unsigned int *) \
		 (i9100_usb_map ? (i9100_usb_map + 0x1B0000 - 0x12480000 + (x)) \
				: I9100_PHY_PA + (x)))

#define UGRST_AHBIDLE	(1u << 31)
#define UGRST_TXFNUM(n)	((n) << 6)
#define UGRST_TXFFLSH	(1u << 5)
#define UGRST_RXFFLSH	(1u << 4)
#define UGRST_CSFT	(1u << 0)
#define UGINT_WKUP	(1u << 31)
#define UGINT_OEP	(1u << 19)
#define UGINT_IEP	(1u << 18)
#define UGINT_ENUM	(1u << 13)
#define UGINT_USBRST	(1u << 12)
#define UGINT_RXFLVL	(1u << 4)
#define UEPCTL_EPENA	(1u << 31)
#define UEPCTL_EPDIS	(1u << 30)
#define UEPCTL_SD0	(1u << 28)
#define UEPCTL_SNAK	(1u << 27)
#define UEPCTL_CNAK	(1u << 26)
#define UEPCTL_STALL	(1u << 21)
#define UEPCTL_EPTYPE(x) ((x) << 18)
#define UEPCTL_ACT	(1u << 15)
#define UEPCTL_MPS(x)	((x) & 0x7ff)
#define UEPINT_XFC	(1u << 0)
#define UEPINT_AHBERR	(1u << 2)
#define UDCTL_SFTDIS	(1u << 1)
#define URX_PKTSTS(x)	(((x) >> 17) & 0xf)
#define URX_BYTECNT(x)	(((x) >> 4) & 0x7ff)

enum { USB_DEAD, USB_ADOPT, USB_OURS } ;
static int i9100_usb_mode;
static int i9100_usb_probed, i9100_usb_in, i9100_usb_busy1;
static int i9100_usb_configured, i9100_usb_hostopen, i9100_usb_enum;
static unsigned char i9100_usb_newaddr;
static unsigned char i9100_usb_setup[8];
static const unsigned char *i9100_usb_e0buf;
static unsigned int i9100_usb_e0len, i9100_usb_e0ask;
static int i9100_usb_e0st;
#define UE0_WAIT 0
#define UE0_DIN  1
#define UE0_SIN  2
#define UE0_SOUT 3
#define UE0_DOUT 4

#define UTXRING 4096
static char i9100_usb_ring[UTXRING];
static volatile unsigned int i9100_usb_h, i9100_usb_t;

static const unsigned char usb_dev_desc[] = {
	18, 1, 0, 2, 2, 0, 0, 64, 0x25, 0x05, 0xa7, 0xa4, 0x01, 0,
	1, 2, 3, 1 };
static const unsigned char usb_cfg_desc[] = {
	9, 2, 67, 0, 2, 1, 0, 0x80, 0xfa,
	9, 4, 0, 0, 1, 2, 2, 1, 0,
	5, 0x24, 0, 0x10, 0x01,
	5, 0x24, 1, 0, 1,
	4, 0x24, 2, 0x02,
	5, 0x24, 6, 0, 1,
	7, 5, 0x82, 3, 8, 0, 255,
	9, 4, 1, 0, 2, 10, 0, 0, 0,
	7, 5, 0x81, 2, 64, 0, 0,
	7, 5, 0x01, 2, 64, 0, 0 };
static const unsigned char usb_str0[] = { 4, 3, 9, 4 };
static const unsigned char usb_str1[] = {
	30, 3, 'i',0,'9',0,'1',0,'0',0,'0',0,' ',0,'u',0,'n',0,'i',0,
	'L',0,'o',0,'a',0,'d',0,'e',0,'r',0 };
static const unsigned char usb_str2[] = {
	26, 3, 'X',0,'N',0,'U',0,' ',0,'C',0,'D',0,'C',0,' ',0,'L',0,
	'O',0,'G',0 };
static const unsigned char usb_str3[] = {
	20, 3, 'S',0,'2',0,'I',0,'9',0,'1',0,'0',0,'0',0,'-',0,'1',0 };

static void i9100_usb_spin(unsigned int n)
{
	volatile unsigned int i;
	while (n--)
		for (i = 0; i < 200; i++)
			__asm__ __volatile__("nop");
}

static int i9100_usb_wait(volatile unsigned int *r, unsigned int m,
			  unsigned int v)
{
	unsigned int t = 100000;
	while (t--) {
		if ((*r & m) == v)
			return 0;
		i9100_usb_spin(1);
	}
	return -1;
}

static void i9100_usb_fifos(void)
{
	UGRXFSIZ = 0x200;
	UGNPTXFSIZ = (0x80 << 16) | 0x200;
	UDPTXF(1) = (0x80 << 16) | 0x280;
	UDPTXF(2) = (0x20 << 16) | 0x300;
	UGRSTCTL = UGRST_RXFFLSH;
	i9100_usb_wait(&UGRSTCTL, UGRST_RXFFLSH, 0);
	UGRSTCTL = UGRST_TXFNUM(0x10) | UGRST_TXFFLSH;
	i9100_usb_wait(&UGRSTCTL, UGRST_TXFFLSH, 0);
}

static void i9100_usb_e0arm(void)
{
	UDOEPTSIZ(0) = (3 << 29) | (1 << 19) | 24;
	UDOEPCTL(0) |= UEPCTL_EPENA;
}

static void i9100_usb_devinit(void)
{
	int i;

	UDCFG = (1 << 18) | 0;
	UDCTL |= UDCTL_SFTDIS;
	i9100_usb_spin(20);
	UDCTL &= ~UDCTL_SFTDIS;
	for (i = 0; i < 4; i++) {
		UDOEPCTL(i) = UEPCTL_EPDIS | UEPCTL_SNAK;
		UDIEPCTL(i) = UEPCTL_EPDIS | UEPCTL_SNAK;
	}
	UDIEPMSK = 7;
	UDOEPMSK = 0xB;
	UDAINTMSK = (1 << 16) | 1;
	i9100_usb_fifos();
	i9100_usb_e0st = UE0_WAIT;
	i9100_usb_e0len = 0;
	i9100_usb_busy1 = 0;
	i9100_usb_configured = 0;
	i9100_usb_hostopen = 0;
	i9100_usb_e0arm();
}

static void i9100_usb_hardinit(void)
{
	*(volatile unsigned int *)(i9100_usb_map ?
		i9100_usb_map + (0x10020704 - 0x12480000) :
		I9100_PMU_USBPHY) |= 1;
	UPHYREG(0) &= ~(0x39u);
	UPHYREG(4) = (UPHYREG(4) & ~0x14) | 0x3;
	UPHYREG(8) = (UPHYREG(8) & ~6) | 1;
	i9100_usb_spin(20);
	UPHYREG(8) &= ~7;
	i9100_usb_spin(20);

	i9100_usb_wait(&UGRSTCTL, UGRST_AHBIDLE, UGRST_AHBIDLE);
	UGRSTCTL = UGRST_CSFT;
	i9100_usb_wait(&UGRSTCTL, UGRST_CSFT, 0);
	UGUSBCFG = (1 << 30) | (1 << 14) | (0x5 << 10) | 0x7;
	i9100_usb_fifos();
	i9100_usb_devinit();
	i9100_usb_mode = USB_OURS;
}

static int i9100_usb_e0tx(unsigned int len)
{
	unsigned int words = (len + 3) >> 2, i;
	unsigned int w;

	if ((UGNPTXSTS & 0xffff) < words)
		return -1;
	UDIEPTSIZ(0) = (1 << 19) | len;
	for (i = 0; i < words; i++) {
		memcpy(&w, i9100_usb_e0buf + i * 4, 4);
		UFIFO(0) = w;
	}
	UDIEPCTL(0) |= UEPCTL_EPENA | UEPCTL_CNAK;
	i9100_usb_e0buf += len;
	i9100_usb_e0len -= len;
	return 0;
}

static void i9100_usb_e0reply(const unsigned char *b, unsigned int l,
			      unsigned int ask)
{
	i9100_usb_e0buf = b;
	i9100_usb_e0len = l < ask ? l : ask;
	i9100_usb_e0ask = ask;
	i9100_usb_e0st = UE0_DIN;
	i9100_usb_e0tx(i9100_usb_e0len > 64 ? 64 : i9100_usb_e0len);
}

static void i9100_usb_e0sin(void)
{
	i9100_usb_e0st = UE0_SIN;
	UDIEPTSIZ(0) = 1 << 19;
	UDIEPCTL(0) |= UEPCTL_EPENA | UEPCTL_CNAK;
}

static void i9100_usb_e0stall(void)
{
	UDIEPCTL(0) |= UEPCTL_STALL;
	UDOEPCTL(0) |= UEPCTL_STALL;
	i9100_usb_e0st = UE0_WAIT;
}

static void i9100_usb_e0setup(void)
{
	unsigned char rt = i9100_usb_setup[0], rq = i9100_usb_setup[1];
	unsigned int wv = i9100_usb_setup[2] | (i9100_usb_setup[3] << 8);
	unsigned int wl = i9100_usb_setup[6] | (i9100_usb_setup[7] << 8);
	static const unsigned char lc[7] =
		{ 0, 0xc2, 0x01, 0, 0, 0, 8 };

	if (rt == 0x80 && rq == 6) {
		switch (wv >> 8) {
		case 1:
			i9100_usb_e0reply(usb_dev_desc,
				sizeof(usb_dev_desc), wl);
			return;
		case 2:
			i9100_usb_e0reply(usb_cfg_desc,
				sizeof(usb_cfg_desc), wl);
			return;
		case 3:
			switch (wv & 0xff) {
			case 0: i9100_usb_e0reply(usb_str0, 4, wl); return;
			case 1: i9100_usb_e0reply(usb_str1, 30, wl); return;
			case 2: i9100_usb_e0reply(usb_str2, 26, wl); return;
			default: i9100_usb_e0reply(usb_str3, 20, wl); return;
			}
		}
		i9100_usb_e0stall();
		return;
	}
	if (rt == 0x00 && rq == 5) {
		i9100_usb_newaddr = wv & 0x7f;
		i9100_usb_e0sin();
		return;
	}
	if (rt == 0x00 && rq == 9) {
		UDIEPCTL(1) = UEPCTL_ACT | UEPCTL_EPTYPE(2) | (1 << 22) |
			UEPCTL_MPS(64) | UEPCTL_EPENA | UEPCTL_CNAK |
			UEPCTL_SD0;
		UDIEPCTL(2) = UEPCTL_ACT | UEPCTL_EPTYPE(3) | (2 << 22) |
			UEPCTL_MPS(8) | UEPCTL_SNAK;
		UDOEPCTL(1) = UEPCTL_ACT | UEPCTL_EPTYPE(2) |
			UEPCTL_MPS(64) | UEPCTL_EPENA | UEPCTL_CNAK;
		i9100_usb_configured = 1;
		i9100_usb_e0sin();
		return;
	}
	if (rt == 0x21 && rq == 0x20) {
		i9100_usb_e0st = UE0_DOUT;
		UDOEPTSIZ(0) = (1 << 19) | 7;
		UDOEPCTL(0) |= UEPCTL_EPENA | UEPCTL_CNAK;
		return;
	}
	if (rt == 0xa1 && rq == 0x21) {
		i9100_usb_e0reply(lc, 7, wl);
		return;
	}
	if (rt == 0x21 && rq == 0x22) {
		i9100_usb_hostopen = 1;
		i9100_usb_e0sin();
		return;
	}
	if (rq == 1 || rq == 3)
		i9100_usb_e0sin();
	else if (rt & 0x80)
		i9100_usb_e0reply((const unsigned char *)"\0\0", 2, wl);
	else
		i9100_usb_e0sin();
}

static void i9100_usb_e0indone(void)
{
	if (i9100_usb_e0st == UE0_DIN) {
		if (i9100_usb_e0len) {
			i9100_usb_e0tx(i9100_usb_e0len > 64 ? 64
							  : i9100_usb_e0len);
			return;
		}
		i9100_usb_e0st = UE0_SOUT;
		i9100_usb_e0arm();
		return;
	}
	if (i9100_usb_e0st == UE0_SIN) {
		if (i9100_usb_newaddr) {
			UDCFG = (UDCFG & ~(0x7f << 4)) |
				(i9100_usb_newaddr << 4);
			i9100_usb_newaddr = 0;
		}
		i9100_usb_e0st = UE0_WAIT;
	}
}

static void i9100_usb_rxlvl(void)
{
	unsigned int gs = UGRXSTSP, ps = URX_PKTSTS(gs), bc = URX_BYTECNT(gs);
	unsigned int i;

	if (ps == 6) {
		unsigned int lo = UGRXSTSP, hi = UGRXSTSP;
		memcpy(i9100_usb_setup, &lo, 4);
		memcpy(i9100_usb_setup + 4, &hi, 4);
	} else if (ps == 4) {
		i9100_usb_e0setup();
	} else if (ps == 2) {
		for (i = 0; i < (bc + 3) / 4; i++)
			(void)UGRXSTSP;
		if (i9100_usb_e0st == UE0_DOUT)
			i9100_usb_e0sin();
	} else if (ps == 3) {
		if (i9100_usb_e0st == UE0_SOUT)
			i9100_usb_e0st = UE0_WAIT;
		i9100_usb_e0arm();
	} else {
		for (i = 0; i < (bc + 3) / 4; i++)
			(void)UGRXSTSP;
	}
}

static void i9100_usb_drain(void)
{
	unsigned char pkt[64];
	unsigned int n = 0, i, w;

	if (i9100_usb_busy1 || !i9100_usb_configured ||
	    !i9100_usb_hostopen || i9100_usb_h == i9100_usb_t)
		return;
	while (n < sizeof(pkt) && i9100_usb_t != i9100_usb_h) {
		pkt[n++] = i9100_usb_ring[i9100_usb_t];
		i9100_usb_t = (i9100_usb_t + 1) & (UTXRING - 1);
	}
	if ((UDTXFSTS(1) & 0xffff) < (n + 3) / 4)
		return;
	UDIEPTSIZ(1) = (1 << 19) | n;
	for (i = 0; i < (n + 3) / 4; i++) {
		w = pkt[i * 4] | (pkt[i * 4 + 1] << 8) |
		    (pkt[i * 4 + 2] << 16) |
		    ((i * 4 + 3 < n ? pkt[i * 4 + 3] : 0) << 24);
		UFIFO(1) = w;
	}
	UDIEPCTL(1) |= UEPCTL_EPENA | UEPCTL_CNAK;
	i9100_usb_busy1 = 1;
}

static void i9100_usb_poll(void)
{
	unsigned int st;

	if (!i9100_usb_probed)
		return;
	st = UGINTSTS;
	if (st & UGINT_USBRST) {
		UGINTSTS = UGINT_USBRST;
		i9100_usb_newaddr = 0;
		i9100_usb_mode = USB_OURS;
		i9100_usb_devinit();
	}
	if (st & UGINT_ENUM) {
		UGINTSTS = UGINT_ENUM;
		i9100_usb_enum = 1;
		UDIEPCTL(0) = (UDIEPCTL(0) & ~3u) | UEPCTL_CNAK;
		UDOEPCTL(0) = (UDOEPCTL(0) & ~3u) | UEPCTL_CNAK;
		i9100_usb_e0arm();
	}
	if (st & UGINT_RXFLVL) {
		UGINTSTS = UGINT_RXFLVL;
		i9100_usb_rxlvl();
	}
	if (st & UGINT_IEP) {
		unsigned int d = UDAINT & 0xffff;
		if (d & 1) {
			unsigned int e = UDIEPINT(0);
			UDIEPINT(0) = e;
			if (e & UEPINT_XFC)
				i9100_usb_e0indone();
		}
		if (d & 2) {
			unsigned int e = UDIEPINT(1);
			UDIEPINT(1) = e;
			if (e & (UEPINT_XFC | UEPINT_AHBERR))
				i9100_usb_busy1 = 0;
		}
	}
	i9100_usb_drain();
}

void i9100_usbcdc_putc(char c)
{
	unsigned int nx;

	if (i9100_usb_mode == USB_DEAD)
		return;
	nx = (i9100_usb_h + 1) & (UTXRING - 1);
	if (nx != i9100_usb_t) {
		i9100_usb_ring[i9100_usb_h] = c;
		i9100_usb_h = nx;
	}
	if (i9100_usb_in)
		return;
	i9100_usb_in = 1;
	i9100_usb_poll();
	i9100_usb_in = 0;
}

/* Probe/adopt or hard-init.  Called lazily on the first putc and again
 * after ml_io_map() provided a real mapping (keeps an adopted
 * uniLoader session alive - the COM port stays open). */
void i9100_usbcdc_init(void)
{
	unsigned int ctl1;

	UPCGCCTL = 0;
	i9100_usb_spin(10);
	if ((UGSNPSID & 0xffff0000) != 0x4f540000) {
		i9100_usb_mode = USB_DEAD;
		i9100_usb_probed = 1;
		return;
	}
	ctl1 = UDIEPCTL(1);
	if ((UDCFG & (0x7f << 4)) && (ctl1 & UEPCTL_ACT)) {
		i9100_usb_mode = USB_ADOPT;
		i9100_usb_configured = 1;
		i9100_usb_hostopen = 1;
	} else {
		i9100_usb_hardinit();
	}
	i9100_usb_probed = 1;
}
