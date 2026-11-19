#ifndef I9100_PANEL_SPI_H
#define I9100_PANEL_SPI_H
#include <stdint.h>

/* U1 EUR panel wiring from mach-u1.c / gpio-exynos4.c and S-Boot:
 * GPY3.1 CLK, GPY3.3 bidirectional SI; GPY4.3 CS. Reset GPY4.5 and
 * fuel-gauge GPY4.0/1 are never changed. Each transfer saves/restores only
 * these three pins while the caller excludes same-core GPIO transactions. */
struct i9100_panel_spi_io {
 void *cookie;
 uint32_t (*read)(void *,unsigned);
 void (*write)(void *,unsigned,uint32_t);
 void (*delay_us)(void *,unsigned);
 unsigned (*enter)(void *);
 void (*leave)(void *,unsigned);
};
struct i9100_panel_spi {
 struct i9100_panel_spi_io io;
 uint32_t saved_con3,saved_dat3,saved_con4,saved_dat4;
 unsigned token,active,error;
};
#define I9P_CLK (1U<<1)
#define I9P_SI (1U<<3)
#define I9P_CS (1U<<3)
#define I9P_MUX3 ((15U<<4)|(15U<<12))
#define I9P_MUX4 (15U<<12)

static void i9100_panel_spi_bit(struct i9100_panel_spi *s,unsigned bank,
 unsigned pin,unsigned high)
{
 unsigned offset=bank==3?0x184U:0x1a4U;
 uint32_t value=s->io.read(s->io.cookie,offset);
 s->io.write(s->io.cookie,offset,high?value|pin:value&~pin);
 if((s->io.read(s->io.cookie,offset)&pin)!=(high?pin:0))s->error=1;
}
static void i9100_panel_spi_si_mode(struct i9100_panel_spi *s,unsigned output)
{
 uint32_t value=s->io.read(s->io.cookie,0x180U)&~(15U<<12);
 s->io.write(s->io.cookie,0x180U,value|(output?1U<<12:0));
 if((s->io.read(s->io.cookie,0x180U)&(15U<<12))!=(output?1U<<12:0))s->error=1;
}
static int i9100_panel_spi_finish(struct i9100_panel_spi *s)
{
 i9100_panel_spi_bit(s,4,I9P_CS,1);
 i9100_panel_spi_bit(s,3,I9P_CLK,1);
 /* Restore data before mux, preserving freshly read unrelated pins. */
 s->io.write(s->io.cookie,0x184U,(s->io.read(s->io.cookie,0x184U)&~(I9P_CLK|I9P_SI))|
    (s->saved_dat3&(I9P_CLK|I9P_SI)));
 s->io.write(s->io.cookie,0x1a4U,(s->io.read(s->io.cookie,0x1a4U)&~I9P_CS)|(s->saved_dat4&I9P_CS));
 s->io.write(s->io.cookie,0x180U,(s->io.read(s->io.cookie,0x180U)&~I9P_MUX3)|(s->saved_con3&I9P_MUX3));
 s->io.write(s->io.cookie,0x1a0U,(s->io.read(s->io.cookie,0x1a0U)&~I9P_MUX4)|(s->saved_con4&I9P_MUX4));
 int ok=!s->error && (s->io.read(s->io.cookie,0x180U)&I9P_MUX3)==(s->saved_con3&I9P_MUX3) &&
    (s->io.read(s->io.cookie,0x1a0U)&I9P_MUX4)==(s->saved_con4&I9P_MUX4) &&
    (s->io.read(s->io.cookie,0x184U)&I9P_CLK)==(s->saved_dat3&I9P_CLK) &&
    (s->io.read(s->io.cookie,0x1a4U)&I9P_CS)==(s->saved_dat4&I9P_CS);
 s->active=0;s->io.leave(s->io.cookie,s->token);return ok;
}
static int i9100_panel_spi_begin(struct i9100_panel_spi *s)
{
 if(!s || !s->io.read || !s->io.write || !s->io.delay_us || !s->io.enter || !s->io.leave || s->active)return 0;
 s->token=s->io.enter(s->io.cookie);s->active=1;s->error=0;
 s->saved_con3=s->io.read(s->io.cookie,0x180U);s->saved_dat3=s->io.read(s->io.cookie,0x184U);
 s->saved_con4=s->io.read(s->io.cookie,0x1a0U);s->saved_dat4=s->io.read(s->io.cookie,0x1a4U);
 /* Adopt only the observed GPIO-output setup already used by firmware. */
 if((s->saved_con3&I9P_MUX3)!=((1U<<4)|(1U<<12)) ||
    (s->saved_con4&I9P_MUX4)!=(1U<<12) || !(s->saved_dat4&I9P_CS)){
  s->active=0;s->io.leave(s->io.cookie,s->token);return 0;
 }
 i9100_panel_spi_bit(s,3,I9P_CLK,1);i9100_panel_spi_bit(s,4,I9P_CS,0);
 if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
 s->io.delay_us(s->io.cookie,1);return 1;
}
static int i9100_panel_spi_word(struct i9100_panel_spi *s,unsigned word)
{
 if(!s || word>0x1ffU || !i9100_panel_spi_begin(s))return 0;
 for(int bit=8;bit>=0;--bit){
  i9100_panel_spi_bit(s,3,I9P_CLK,0);
  i9100_panel_spi_bit(s,3,I9P_SI,(word>>(unsigned)bit)&1U);
  if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
  s->io.delay_us(s->io.cookie,1);
  i9100_panel_spi_bit(s,3,I9P_CLK,1);s->io.delay_us(s->io.cookie,1);
  if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
 }
 return i9100_panel_spi_finish(s);
}
static int i9100_panel_spi_read_byte(struct i9100_panel_spi *s,unsigned command,uint8_t *out)
{
 if(!s || !out || command>255U || !i9100_panel_spi_begin(s))return 0;
 for(int bit=8;bit>=0;--bit){
  i9100_panel_spi_bit(s,3,I9P_CLK,0);
  i9100_panel_spi_bit(s,3,I9P_SI,(command>>(unsigned)bit)&1U);
  if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
  s->io.delay_us(s->io.cookie,1);
  i9100_panel_spi_bit(s,3,I9P_CLK,1);s->io.delay_us(s->io.cookie,1);
  if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
 }
 i9100_panel_spi_si_mode(s,0);s->io.delay_us(s->io.cookie,1);
 if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
 uint8_t value=0;
 for(unsigned bit=0;bit<16;bit++){
  i9100_panel_spi_bit(s,3,I9P_CLK,0);s->io.delay_us(s->io.cookie,1);
  i9100_panel_spi_bit(s,3,I9P_CLK,1);s->io.delay_us(s->io.cookie,1);
  if(s->error){(void)i9100_panel_spi_finish(s);return 0;}
  if(bit>=8)value=(uint8_t)((value<<1)|((s->io.read(s->io.cookie,0x184U)>>3)&1U));
 }
 if(!i9100_panel_spi_finish(s))return 0;*out=value;return 1;
}
#endif
