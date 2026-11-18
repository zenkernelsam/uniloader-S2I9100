#ifndef I9100_LPM_H
#define I9100_LPM_H
#include <main/i9100-boot-source.h>
#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffU
#endif
/* Standalone charger: portable U1 policy, original S-Boot picture, no SD or
 * userspace launch. MCT/GIC addresses and handshake match the verified kernel. */
#include "charge/i9100_power.c"
#include "charge/i9100_power_bus.c"
#ifndef LPM_BARRIER
#define LPM_BARRIER() __asm__ volatile("dsb sy" ::: "memory")
#define LPM_MASK_IRQ() __asm__ volatile("cpsid if" ::: "memory")
#define LPM_WAIT() __asm__ volatile("wfi" ::: "memory")
#endif
static struct i9100_power_state i9100_lpm_battery;
static int lpm_boot_requested(const struct I9100BootSource *source)
{return source && source->magic==I9100_BOOT_SOURCE_MAGIC && source->version==1 &&
 source->flags==3 && source->sboot_mode==1 && source->inform2==1;}
static unsigned i9100_lpm_timer_ready;
static uint32_t lpm_read(unsigned base,unsigned off)
{return readl((void*)(base+off));}
static void lpm_write(unsigned base,unsigned off,uint32_t value)
{writel(value,(void*)(base+off));LPM_BARRIER();}
static uint64_t lpm_ticks(void)
{
 uint32_t hi,lo,again;
 do{hi=lpm_read(0x10050000U,0x104);lo=lpm_read(0x10050000U,0x100);
    again=lpm_read(0x10050000U,0x104);}while(hi!=again);
 return ((uint64_t)hi<<32)|lo;
}
static int lpm_mct_write(unsigned off,uint32_t value,uint32_t mask)
{
 lpm_write(0x10050000U,off,value);
 for(unsigned n=0;n<65536;n++)if(lpm_read(0x10050000U,0x24c)&mask){
  lpm_write(0x10050000U,0x24c,mask);return 1;}
 return 0;
}
static void lpm_delay(void *cookie,unsigned us)
{
 (void)cookie;uint64_t start=lpm_ticks(),ticks=(uint64_t)us*24U;
 while(lpm_ticks()-start<ticks)__asm__ volatile("nop");
}
static uint64_t lpm_now(void *cookie)
{(void)cookie;return (lpm_ticks()/24U)*1000U;}
static int lpm_timer_init(void)
{
 LPM_MASK_IRQ();
 lpm_write(0x10490000U,0,0);
 unsigned groups=(lpm_read(0x10490000U,4)&31U)+1U;
 if(groups<3 || groups>8)return 0;
 for(unsigned n=0;n<groups*32;n+=32){lpm_write(0x10490000U,0x180+(n/32)*4,0xffffffffU);
  lpm_write(0x10490000U,0x280+(n/32)*4,0xffffffffU);}
 unsigned off=(89U/4)*4,shift=(89U%4)*8;
 lpm_write(0x10490000U,0x800+off,(lpm_read(0x10490000U,0x800+off)&~(255U<<shift))|(1U<<shift));
 lpm_write(0x10490000U,0x400+off,(lpm_read(0x10490000U,0x400+off)&~(255U<<shift))|(0x80U<<shift));
 lpm_write(0x10490000U,0xc00+(89U/16)*4,lpm_read(0x10490000U,0xc00+(89U/16)*4)|(2U<<((89U%16)*2)));
 lpm_write(0x10480000U,4,0xf0);lpm_write(0x10480000U,0,1);lpm_write(0x10490000U,0,1);
 lpm_write(0x10050000U,0x10,1);lpm_write(0x10050000U,0x248,0);
 if(!lpm_mct_write(0x240,256,1U<<16))return 0;
 uint64_t before=lpm_ticks();unsigned n;
 for(n=0;n<65536 && lpm_ticks()==before;n++);
 if(n==65536)return 0;
 uint64_t match=lpm_ticks()+240000U;
 if(!lpm_mct_write(0x200,(uint32_t)match,1) ||
    !lpm_mct_write(0x204,(uint32_t)(match>>32),2) ||
    !lpm_mct_write(0x208,240000,4) || !lpm_mct_write(0x240,259,1U<<16))return 0;
 lpm_write(0x10050000U,0x244,1);lpm_write(0x10050000U,0x248,1);
 lpm_write(0x10490000U,0x108,1U<<25);
 i9100_lpm_timer_ready=1;return 1;
}
static void lpm_sleep_tick(void)
{
 LPM_BARRIER();LPM_WAIT();
 unsigned token=lpm_read(0x10480000U,0x0c),irq=token&1023U;
 if(irq==89)lpm_write(0x10050000U,0x244,1);
 if(irq<1020)lpm_write(0x10480000U,0x10,token);
}
static uint32_t lpm_hw_read(void *cookie,unsigned region,unsigned off)
{
 static const unsigned bases[4]={0x11400000U,0x11000000U,0x10030000U,0x13910000U};
 (void)cookie;if(region>=4 || (off&3) || off>=(region==2?65536U:4096U))return 0xffffffffU;
 return lpm_read(bases[region],off);
}
static void lpm_hw_write(void *cookie,unsigned region,unsigned off,uint32_t value)
{
 static const unsigned bases[4]={0x11400000U,0x11000000U,0x10030000U,0x13910000U};
 (void)cookie;if(region<4 && !(off&3) && off<(region==2?65536U:4096U))lpm_write(bases[region],off,value);
}
static void lpm_enter(void *cookie){(void)cookie;}
static void lpm_leave(void *cookie){(void)cookie;}
static unsigned lpm_revision(void)
{
 unsigned address=boot_reg_r2?boot_reg_r2:0x40000100U;
 if(address<0x40000000U || address>0x4000f000U || (address&3))return 0xffffffffU;
 unsigned end=address+4096U;volatile uint32_t *p=(void*)address;
 while((unsigned)p+8<=end){unsigned size=p[0],tag=p[1];
  if(size<2 || size>(end-(unsigned)p)/4)break;
  if(tag==0x54410007U && size>=3 && p[2]<=15)return p[2];p+=size;}
 return 0xffffffffU;
}
static void lpm_download(void)
{
 lpm_write(0x10020000U,0x808,0x12345678U);lpm_write(0x10020000U,0x80c,0x12345671U);
 lpm_write(0x10020000U,0x400,1);for(;;)LPM_WAIT();
}
void i9100_standalone_charge_gate(void)
{
#ifdef I9100_STANDALONE_CHARGE_BUILD
 if(!lpm_boot_requested(&i9100_boot_source))return;
 if(!lpm_timer_init())lpm_download();
 /* Bootloader watchdog must not reset a supervised charger every few seconds. */
 lpm_write(0x10060000U,0,lpm_read(0x10060000U,0)&~((1U<<5)|1U));
 struct i9100_power_hw hw={0,lpm_hw_read,lpm_hw_write,lpm_delay,lpm_enter,lpm_leave};
 struct i9100_power_io io={0};io.cookie=&hw;io.pmic_read=i9100_power_pmic_read;
 io.pmic_write=i9100_power_pmic_write;io.fuel_read=i9100_power_fuel_read;
 io.adc_read=i9100_power_adc_read;io.sub_read=i9100_power_sub_read;
 io.sub_enable=i9100_power_sub_enable;io.muic_read=i9100_power_muic_read;
 io.muic_write=i9100_power_muic_write;io.now_ns=lpm_now;
 if(i9100_power_init(&i9100_lpm_battery,&io,lpm_revision()))lpm_download();
#if defined(CONFIG_EXYNOS_CDCACM4210)
 extern void usbcdc4210_charge_identity(int);
 extern void usbcdc4210_charge_report(unsigned,unsigned,unsigned,int,unsigned,int);
 usbcdc4210_charge_identity(1);usbcdc4210_init();
#endif
 uint64_t next=0,pressed=0,show_until=lpm_ticks()+720000000U;unsigned polls=0;
 unsigned saved_map=lpm_read(0x11c00000U,0x180),blanked=0;
 for(;;){
  uint64_t now=lpm_ticks();
  if(now>=next){i9100_power_poll(&i9100_lpm_battery);next=now+24000000U;
#if defined(CONFIG_EXYNOS_CDCACM4210)
   if((polls++%30)==0)usbcdc4210_charge_report(i9100_lpm_battery.valid,
    i9100_lpm_battery.percent,i9100_lpm_battery.millivolts,
    i9100_lpm_battery.temperature_deci_c,i9100_lpm_battery.charging,i9100_lpm_battery.reason);
#endif
  }
  unsigned keys=lpm_read(0x11000000U,0xc44),home=lpm_read(0x11000000U,0xc64);
  if(!(keys&1U) && !(home&(1U<<5)))lpm_download();
  if(!(keys&(1U<<7))){if(!pressed)pressed=now;
   show_until=now+720000000U;
   if(blanked){lpm_write(0x11c00000U,0x180,saved_map);blanked=0;}
   if(now-pressed>=48000000U && i9100_lpm_battery.valid && i9100_lpm_battery.millivolts>=3500)break;
  }else pressed=0;
  if(!blanked && now>=show_until){
   lpm_write(0x11c00000U,0x180,(saved_map&~0x01ffffffU)|0x01000000U);blanked=1;
  }
  if(i9100_lpm_battery.valid && !i9100_lpm_battery.connected){
   i9100_power_stop(&i9100_lpm_battery);
   lpm_write(0x10020000U,0x330c,lpm_read(0x10020000U,0x330c)&~256U);
  }
#if defined(CONFIG_EXYNOS_CDCACM4210)
  usbcdc_poll();
#endif
  lpm_sleep_tick();
 }
 if(blanked)lpm_write(0x11c00000U,0x180,saved_map);
 i9100_power_stop(&i9100_lpm_battery);
 lpm_write(0x10020000U,0x808,0x12345678U);
 lpm_write(0x10020000U,0x80c,0x12345670U);
#if defined(CONFIG_EXYNOS_CDCACM4210)
 usbcdc4210_charge_identity(0);
#endif
 lpm_write(0x10050000U,0x248,0);lpm_write(0x10490000U,0x188,1U<<25);
#endif
}
#endif
