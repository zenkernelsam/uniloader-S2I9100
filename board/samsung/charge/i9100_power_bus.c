/* Dedicated U1 power buses only: GPB[6:7] MAX8997 and GPY4[0:1] MAX17042.
 * No address/pin scanning. All waits are bounded; GPIO fields are preserved. */
#include "i9100_power.h"
#include "i9100_rtc_time.h"
#include <string.h>
struct bus {
 struct i9100_power_hw *hw;
 unsigned region,base,sda,scl;
 uint32_t con,dat,pull;
};
static uint32_t rd(struct bus *b,unsigned off)
{return b->hw->read32(b->hw->cookie,b->region,b->base+off);}
static void wr(struct bus *b,unsigned off,uint32_t v)
{b->hw->write32(b->hw->cookie,b->region,b->base+off,v);}
static void delay(struct bus *b,unsigned us){b->hw->delay_us(b->hw->cookie,us);}
static void low(struct bus *b,unsigned pin)
{wr(b,4,rd(b,4)&~(1U<<pin));wr(b,0,(rd(b,0)&~(15U<<(pin*4)))|(1U<<(pin*4)));}
static void release(struct bus *b,unsigned pin){wr(b,0,rd(b,0)&~(15U<<(pin*4)));}
static int clock_high(struct bus *b)
{
 release(b,b->scl);
 for(unsigned n=0;n<200;n++){
  if(rd(b,4)&(1U<<b->scl)){delay(b,5);return 1;}
  delay(b,1);
 }
 return 0;
}
static int stop(struct bus *b)
{
 low(b,b->scl);low(b,b->sda);delay(b,5);
 int ok=clock_high(b);release(b,b->sda);delay(b,5);return ok;
}
static int start(struct bus *b)
{
 release(b,b->sda);delay(b,5);
 if(!clock_high(b))return 0;
 low(b,b->sda);delay(b,5);low(b,b->scl);return 1;
}
static int send(struct bus *b,unsigned byte)
{
 for(int bit=7;bit>=0;bit--){
  if(byte&(1U<<bit))release(b,b->sda);else low(b,b->sda);
  delay(b,5);if(!clock_high(b))return 0;low(b,b->scl);delay(b,5);
 }
 release(b,b->sda);delay(b,5);if(!clock_high(b))return 0;
 int ack=!(rd(b,4)&(1U<<b->sda));low(b,b->scl);delay(b,5);return ack;
}
static int receive(struct bus *b,uint8_t *byte,int last)
{
 unsigned value=0;release(b,b->sda);
 for(unsigned n=0;n<8;n++){
  delay(b,5);if(!clock_high(b))return 0;
  value=(value<<1)|((rd(b,4)>>b->sda)&1U);low(b,b->scl);delay(b,5);
 }
 if(last)release(b,b->sda);else low(b,b->sda);
 delay(b,5);if(!clock_high(b))return 0;low(b,b->scl);release(b,b->sda);
 *byte=(uint8_t)value;return 1;
}
static int transfer(struct i9100_power_hw *hw,unsigned fuel,unsigned slave,unsigned reg,
                    uint8_t *data,unsigned count,int writing)
{
 if(!hw || !data || reg>255 || !count ||
    (count>2 && !(count==7 && !fuel && slave==0x06U && reg==0x10U && !writing)) ||
    (fuel && writing) || slave>127)return 0;
 struct bus b={hw,fuel?1U:0U,fuel?0x1a0U:0x40U,fuel?0U:6U,fuel?1U:7U,0,0,0};
 hw->enter(hw->cookie);
 b.con=rd(&b,0);b.dat=rd(&b,4);b.pull=rd(&b,8);
 uint32_t pins=(1U<<b.sda)|(1U<<b.scl);
 uint32_t mux=(15U<<(b.sda*4))|(15U<<(b.scl*4));
 uint32_t pulls=(3U<<(b.sda*2))|(3U<<(b.scl*2));
 release(&b,b.sda);release(&b,b.scl);wr(&b,8,(b.pull&~pulls)|pulls);
 int ok=clock_high(&b);
 if(ok && !(rd(&b,4)&(1U<<b.sda))){
  for(unsigned n=0;n<9;n++){low(&b,b.scl);delay(&b,5);if(!clock_high(&b)){ok=0;break;}}
  if(!stop(&b))ok=0;
  if(!(rd(&b,4)&(1U<<b.sda)))ok=0;
 }
 if(ok)ok=start(&b) && send(&b,slave<<1) && send(&b,reg);
 if(ok && !writing)ok=start(&b) && send(&b,(slave<<1)|1U);
 if(ok)for(unsigned n=0;n<count;n++){
  if(writing)ok=send(&b,data[n]);else ok=receive(&b,data+n,n+1==count);
  if(!ok)break;
 }
 if(!stop(&b))ok=0;
 release(&b,b.sda);release(&b,b.scl);
 wr(&b,4,(rd(&b,4)&~pins)|(b.dat&pins));
 wr(&b,8,(rd(&b,8)&~pulls)|(b.pull&pulls));
 wr(&b,0,(rd(&b,0)&~mux)|(b.con&mux));
 hw->leave(hw->cookie);return ok;
}
int i9100_power_pmic_read(void *hw,unsigned reg,uint8_t *value)
{uint8_t data=0;if(!value || !transfer(hw,0,0x66,reg,&data,1,0))return 0;*value=data;return 1;}
int i9100_power_pmic_write(void *hw,unsigned reg,uint8_t value)
{return transfer(hw,0,0x66,reg,&value,1,1);}
/* MAX8997 MUIC lives at 0x25 (0x4a>>1) on the same GPB[6:7] bus as the PMIC. */
int i9100_power_muic_read(void *hw,unsigned reg,uint8_t *value)
{uint8_t data=0;if(!value || !transfer(hw,0,0x25,reg,&data,1,0))return 0;*value=data;return 1;}
int i9100_power_muic_write(void *hw,unsigned reg,uint8_t value)
{return transfer(hw,0,0x25,reg,&value,1,1);}
int i9100_power_fuel_read(void *hw,unsigned reg,uint16_t *value)
{uint8_t data[2];if(!value || !transfer(hw,1,0x36,reg,data,2,0))return 0;*value=data[0]|((uint16_t)data[1]<<8);return 1;}
volatile uint32_t i9100_rtc_read_diag[12]={2};
static uint32_t rtc_bytes(const uint8_t *data,unsigned count)
{
 uint32_t result=0;for(unsigned n=0;n<count;n++)result|=(uint32_t)data[n]<<(n*8U);
 return result;
}
int i9100_power_rtc_snapshot(void *hw,uint64_t *value,struct i9100_rtc_read *raw)
{
 struct i9100_rtc_read observation={0};uint8_t control=0,again=0,first[7]={0},last[7]={0};
 uint64_t a=0,b=0;int ok=0;
 uint32_t serial=(i9100_rtc_read_diag[1]+2U)&~1U;if(!serial)serial=2U;
 observation.version=2;observation.sequence=serial;observation.status=2;
 i9100_rtc_read_diag[1]=serial-1U;__sync_synchronize();
 if(!hw || !value)goto done;
 if(!transfer(hw,0,0x06,0x03,&control,1,0))goto done;
 observation.read_mask|=1U;observation.status=3;
 if(!transfer(hw,0,0x06,0x10,first,7,0))goto done;
 observation.read_mask|=2U;observation.status=4;
 if(!transfer(hw,0,0x06,0x10,last,7,0))goto done;
 observation.read_mask|=4U;observation.status=5;
 if(!transfer(hw,0,0x06,0x03,&again,1,0))goto done;
 observation.read_mask|=8U;observation.status=6;
 if(control!=again)goto done;
 observation.status=7;if(!i9100_rtc_decode(first,control,&a))goto done;
 observation.status=8;if(!i9100_rtc_decode(last,control,&b))goto done;
 observation.status=9;if(b<a || b-a>1U)goto done;
 *value=b;observation.status=1;observation.seconds_low=(uint32_t)b;
 observation.seconds_high=(uint32_t)(b>>32);ok=1;
done:
 observation.controls=control|((uint32_t)again<<8);
 observation.first_low=rtc_bytes(first,4);observation.first_high=rtc_bytes(first+4,3);
 observation.last_low=rtc_bytes(last,4);observation.last_high=rtc_bytes(last+4,3);
 /* Seal the complete even-sequence frame before publishing it. A later
  * valid tick must not make this already coherent observation ambiguous. */
 const uint8_t *sealed=(const uint8_t *)&observation;uint32_t checksum=2166136261U;
 for(unsigned n=0;n<44U;n++)checksum=(checksum^sealed[n])*16777619U;
 observation.reserved=checksum;
 uint32_t words[12];memcpy(words,&observation,sizeof(words));
 for(unsigned n=0;n<12;n++)if(n!=1)i9100_rtc_read_diag[n]=words[n];
 __sync_synchronize();i9100_rtc_read_diag[1]=serial;__sync_synchronize();
 if(raw)memcpy(raw,&observation,sizeof(observation));
 return ok;
}
int i9100_power_rtc_seconds(void *hw,uint64_t *value)
{return i9100_power_rtc_snapshot(hw,value,0);}
unsigned i9100_power_revision(struct i9100_power_hw *hw)
{
 /* Bootloader leaves revision straps as GPIO inputs; never change their mux. */
 if(hw->read32(hw->cookie,0,0x100)&0xffffU)return UINT32_MAX;
 unsigned revision=hw->read32(hw->cookie,0,0x104)&15U;
 for(unsigned n=0;n<4;n++){
  hw->delay_us(hw->cookie,10);
  if((hw->read32(hw->cookie,0,0x104)&15U)!=revision)return UINT32_MAX;
 }
 return revision;
}
static int i9100_power_adc_sample(void *cookie,unsigned channel,unsigned *value)
{
 struct i9100_power_hw *hw=cookie;
 if(!hw || !value || (channel!=1 && channel!=6 && channel!=7))return 0;
 uint32_t gate=hw->read32(hw->cookie,2,0xc950);
 hw->write32(hw->cookie,2,0xc950,gate|(1U<<15));
 uint32_t con=hw->read32(hw->cookie,3,0),mux=hw->read32(hw->cookie,3,0x1c);
 unsigned total=0,minimum=4095,maximum=0;int ok=1;
 for(unsigned sample=0;sample<5;sample++){
  hw->write32(hw->cookie,3,0x1c,channel);
  hw->write32(hw->cookie,3,0x18,0);
  /* Exynos4210 12-bit ADC, 50:1 prescaler, no read-start/standby. */
  uint32_t config=(1U<<16)|(1U<<14)|(49U<<6);
  hw->write32(hw->cookie,3,0,config);
  hw->write32(hw->cookie,3,0,config|1U);
  unsigned n;
  for(n=0;n<1000;n++){
   uint32_t status=hw->read32(hw->cookie,3,0);
   if(!(status&1U) && (status&(1U<<15)))break;
   hw->delay_us(hw->cookie,1);
  }
  if(n==1000){ok=0;break;}
  unsigned adc=hw->read32(hw->cookie,3,0xc)&4095U;
  if(adc<minimum)minimum=adc;if(adc>maximum)maximum=adc;total+=adc;
 }
 hw->write32(hw->cookie,3,0x18,0);
 hw->write32(hw->cookie,3,0x1c,mux);hw->write32(hw->cookie,3,0,con);
 if(!(gate&(1U<<15)))hw->write32(hw->cookie,2,0xc950,hw->read32(hw->cookie,2,0xc950)&~(1U<<15));
 if(ok)*value=(total-minimum-maximum)/3U;return ok;
}
int i9100_power_adc_read(void *cookie,unsigned channel,unsigned *value)
{
 if(channel!=6 && channel!=7)return 0;
 return i9100_power_adc_sample(cookie,channel,value);
}
int i9100_power_charge_adc_read(void *cookie,unsigned *value)
{
 return i9100_power_adc_sample(cookie,1,value);
}
int i9100_power_sub_read(void *cookie,unsigned *connected,unsigned *charging)
{
 struct i9100_power_hw *hw=cookie;
 if(!connected || !charging)return 0;
 /* GPL2[4,5] are the MAX8922 CHG/POK outputs on EUR boards rev >= 8. */
 uint32_t con=hw->read32(hw->cookie,1,0x100);
 hw->write32(hw->cookie,1,0x100,con&~((15U<<16)|(15U<<20)));
 uint32_t pull=hw->read32(hw->cookie,1,0x108);
 hw->write32(hw->cookie,1,0x108,pull&~((3U<<8)|(3U<<10)));
 uint32_t pins=hw->read32(hw->cookie,1,0x104);
 *connected=!(pins&(1U<<5));*charging=*connected && !(pins&(1U<<4));return 1;
}
int i9100_power_sub_enable(void *cookie,unsigned enable)
{
 struct i9100_power_hw *hw=cookie;if(enable>1)return 0;
 /* Samsung board inversion: GPIO high enables default USB rate. Deliberately
  * do not generate the 300us high-current programming pulse. */
 uint32_t dat=hw->read32(hw->cookie,1,0x104);
 /* Keep a real disable interval before a fresh enable. Otherwise a short
  * off/on retry could be interpreted as a current-programming pulse. */
 if(enable && !(dat&4U)){
  hw->delay_us(hw->cookie,5000);
  dat=hw->read32(hw->cookie,1,0x104);
 }
 hw->write32(hw->cookie,1,0x104,(dat&~4U)|(enable?4U:0));
 uint32_t con=hw->read32(hw->cookie,1,0x100);
 hw->write32(hw->cookie,1,0x100,(con&~(15U<<8))|(1U<<8));
 /* mach-u1 max8922_cfg_gpio() leaves CHG_EN without an internal pull.
  * Preserve the other seven pins, including the adjacent status inputs. */
 uint32_t pull=hw->read32(hw->cookie,1,0x108);
 hw->write32(hw->cookie,1,0x108,pull&~(3U<<4));
 return ((hw->read32(hw->cookie,1,0x104)>>2)&1U)==enable &&
        ((hw->read32(hw->cookie,1,0x100)>>8)&15U)==1U &&
        !(hw->read32(hw->cookie,1,0x108)&(3U<<4));
}
