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
#include "i9100-charge-screen.h"
#include "i9100-charge-report.h"
#include "i9100-charge-start.h"
#include <main/i9100-boot-charge.h>
#include "charge/i9100_panel_spi.h"
#include "charge/i9100_panel_sleep.h"
#ifndef LPM_BARRIER
#define LPM_BARRIER() __asm__ volatile("dsb sy" ::: "memory")
#define LPM_MASK_IRQ() __asm__ volatile("cpsid if" ::: "memory")
#define LPM_WAIT() __asm__ volatile("wfi" ::: "memory")
#endif
static struct i9100_power_state i9100_lpm_battery;
static struct i9100_power_hw i9100_lpm_hw;
static struct i9100_charge_start i9100_lpm_boot_gate;
static unsigned i9100_lpm_boot_active,i9100_lpm_resume_charge,i9100_lpm_boot_in_service;
static unsigned i9100_lpm_boot_polls,i9100_lpm_boot_phase;
static uint64_t i9100_lpm_boot_next;
static int lpm_boot_requested(const struct I9100BootSource *source)
{return source && source->magic==I9100_BOOT_SOURCE_MAGIC && source->version==1 &&
 source->flags==3 && source->sboot_mode==1 && source->inform2==1;}
static unsigned i9100_lpm_timer_ready;
static unsigned i9100_lpm_timer_rearms,i9100_lpm_timer_faults;
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
 /* A large first draw or a USB setup can outlast the comparator period.
  * Never enter WFI against a comparator which is already behind the MCT.
  * Rebase only that expired comparator; the charge/USB/Power loop remains
  * live even if a write handshake fails. IRQ89 is still the only wake IRQ. */
 uint64_t now=lpm_ticks();
 uint32_t high=lpm_read(0x10050000U,0x204),low=lpm_read(0x10050000U,0x200);
 uint64_t match=((uint64_t)high<<32)|low;
 if(!i9100_lpm_timer_ready || match<=now+24000U ||
    !(lpm_read(0x10050000U,0x248)&1U) || (lpm_read(0x10050000U,0x240)&259U)!=259U){
  i9100_lpm_timer_rearms++;
  lpm_write(0x10050000U,0x248,0);
  if(!lpm_mct_write(0x240,256,1U<<16))goto no_wait;
  lpm_write(0x10050000U,0x244,1);lpm_write(0x10490000U,0x288,1U<<25);
  match=lpm_ticks()+240000U;
  if(!lpm_mct_write(0x200,(uint32_t)match,1) ||
     !lpm_mct_write(0x204,(uint32_t)(match>>32),2) ||
     !lpm_mct_write(0x240,259,1U<<16))goto no_wait;
  lpm_write(0x10050000U,0x248,1);
  if(lpm_ticks()>=match)goto no_wait;
  i9100_lpm_timer_ready=1;
 }
 LPM_BARRIER();LPM_WAIT();
 unsigned token=lpm_read(0x10480000U,0x0c),irq=token&1023U;
 if(irq==89)lpm_write(0x10050000U,0x244,1);
 if(irq<1020)lpm_write(0x10480000U,0x10,token);
 return;
no_wait:
 i9100_lpm_timer_ready=0;i9100_lpm_timer_faults++;
 /* Fail awake: future main-loop iterations still monitor temperature,
  * timeout, cable and USB. Do not reset the cell's charging deadline. */
}
#ifdef I9100_PANEL_SLEEP_BUILD
static uint32_t lpm_panel_gpio_read(void *cookie,unsigned off)
{(void)cookie;return lpm_read(0x11000000U,off);}
static void lpm_panel_gpio_write(void *cookie,unsigned off,uint32_t value)
{(void)cookie;lpm_write(0x11000000U,off,value);}
static void lpm_panel_delay(void *cookie,unsigned us){lpm_delay(cookie,us);}
static unsigned lpm_panel_enter(void *cookie){(void)cookie;return 0;}
static void lpm_panel_leave(void *cookie,unsigned token){(void)cookie;(void)token;}
static int lpm_panel_read_byte(void *cookie,unsigned command,uint8_t *value)
{return i9100_panel_spi_read_byte(cookie,command,value);}
static int lpm_panel_command(void *cookie,unsigned command)
{return i9100_panel_spi_word(cookie,command);}
static uint32_t lpm_panel_scan_read(void *cookie){(void)cookie;return lpm_read(0x11c00000U,0);}
static void lpm_panel_scan_write(void *cookie,uint32_t value){(void)cookie;lpm_write(0x11c00000U,0,value);}
static void lpm_panel_wait(void *cookie,unsigned ms)
{
 (void)cookie;uint64_t end=lpm_ticks()+(uint64_t)ms*24000U;
 while(lpm_ticks()<end)lpm_sleep_tick();
}
static int lpm_panel_awake(struct i9100_panel_sleep *panel)
{return !panel->qualified || !i9100_panel_sleep_change(panel,1);}
#endif
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
static int lpm_screen_bind(struct i9100_charge_screen *screen,unsigned *window)
{
 /* S-Boot 4d4209f8 programs window2/ARGB8888; XNU uses window0/RGB888.
  * Only the original full-screen sole enabled layer is eligible. */
 unsigned selected=5;
 for(unsigned n=0;n<5;n++)if(lpm_read(0x11c00000U,0x20+n*4)&1U){
  if(selected!=5)return 0;selected=n;
 }
 if(selected!=0 && selected!=2)return 0;
 unsigned con=lpm_read(0x11c00000U,0x20+selected*4);
 unsigned base=lpm_read(0x11c00000U,0xa0+selected*8),pitch=lpm_read(0x11c00000U,0x100+selected*4);
 unsigned xy=lpm_read(0x11c00000U,0x44+selected*16),end=lpm_read(0x11c00000U,0xd0+selected*8);
 if(!i9100_charge_bind(screen,con,base,pitch,xy,end) || !i9100_charge_screen_valid(screen))return 0;
 *window=selected;return 1;
}
#ifdef I9100_STANDALONE_CHARGE_BUILD
void i9100_boot_charge_service(void)
{
 if(!i9100_lpm_boot_active || i9100_lpm_boot_in_service)return;
 uint64_t now=lpm_ticks();if(now<i9100_lpm_boot_next)return;
 i9100_lpm_boot_in_service=1;
 unsigned result=i9100_power_poll(&i9100_lpm_battery);
 uint64_t sampled=lpm_ticks();
 i9100_charge_start_update(&i9100_lpm_boot_gate,&i9100_lpm_battery,result,(sampled/24U)*1000U);
 i9100_lpm_boot_polls++;i9100_lpm_boot_next=sampled+24000000U;
 i9100_lpm_boot_in_service=0;
}
static void lpm_boot_report(unsigned stage)
{
 i9100_lpm_boot_phase=stage;
#if defined(CONFIG_EXYNOS_CDCACM4210)
 extern void usbcdc4210_charge_boot_report(const unsigned[8]);
 unsigned fields[8]={stage,i9100_lpm_boot_polls,i9100_lpm_battery.valid,
  i9100_lpm_battery.percent,i9100_lpm_battery.millivolts,i9100_lpm_battery.charging,
  (unsigned)i9100_lpm_battery.reason,i9100_lpm_battery.timeout};
 usbcdc4210_charge_boot_report(fields);
#endif
}
void i9100_boot_charge_stage(unsigned stage)
{
 if(!i9100_lpm_boot_active)return;
 i9100_boot_charge_service();lpm_boot_report(stage);
}
#endif
void i9100_standalone_charge_gate(void)
{
#ifdef I9100_STANDALONE_CHARGE_BUILD
 unsigned resuming=i9100_lpm_resume_charge;
 i9100_lpm_resume_charge=0;
 if(!resuming && !lpm_boot_requested(&i9100_boot_source))return;
 if(!lpm_timer_init())lpm_download();
 /* Bootloader watchdog must not reset a supervised charger every few seconds. */
 lpm_write(0x10060000U,0,lpm_read(0x10060000U,0)&~((1U<<5)|1U));
 /* The IO cookie must outlive this gate while bootstrap supervision runs. */
 i9100_lpm_hw=(struct i9100_power_hw){0,lpm_hw_read,lpm_hw_write,lpm_delay,lpm_enter,lpm_leave};
 struct i9100_power_io io={0};io.cookie=&i9100_lpm_hw;io.pmic_read=i9100_power_pmic_read;
 io.pmic_write=i9100_power_pmic_write;io.fuel_read=i9100_power_fuel_read;
 io.adc_read=i9100_power_adc_read;io.sub_read=i9100_power_sub_read;
 io.sub_enable=i9100_power_sub_enable;io.muic_read=i9100_power_muic_read;
 io.muic_write=i9100_power_muic_write;io.now_ns=lpm_now;
 if(!resuming){
  if(i9100_power_init(&i9100_lpm_battery,&io,lpm_revision()))lpm_download();
  i9100_lpm_boot_gate=(struct i9100_charge_start){0};i9100_lpm_boot_polls=0;
 }
 /* Enable and supervise the safe charger BEFORE lengthy USB setup. Resume
  * keeps the original full/timeout/thermal latches and charge_start epoch. */
 i9100_lpm_boot_active=1;i9100_lpm_boot_next=0;i9100_boot_charge_service();
#if defined(CONFIG_EXYNOS_CDCACM4210)
   extern void usbcdc4210_charge_render_report(const unsigned[8]);
   extern void usbcdc4210_charge_start_report(const unsigned[8]);
   extern void usbcdc4210_charge_transport_report(void);
 extern void usbcdc4210_charge_identity(int);
 extern void usbcdc4210_charge_timed_report(const struct i9100_charge_report *);
 extern void usbcdc4210_charge_screen_report(unsigned,unsigned,unsigned,unsigned);
 extern void usbcdc4210_charge_fimd_report(const unsigned[8]);
 extern unsigned usbcdc4210_charge_take_action(void);
 extern unsigned usbcdc4210_charge_release_action(unsigned);
 extern void usbcdc4210_charge_set_boot_ready(unsigned);
 usbcdc4210_charge_identity(1);usbcdc4210_init();
#endif
 uint64_t next=0,pressed=0,show_until=lpm_ticks()+720000000U;unsigned polls=0,report_sequence=0;
 unsigned window=0,blanked=0;
 i9100_charge_renderer_reset(); /* Normal boot may have reused this scanout. */
 struct i9100_charge_screen screen={0};unsigned screen_ok=lpm_screen_bind(&screen,&window),animation=0,drawn=0;
#ifdef I9100_PANEL_SLEEP_BUILD
 struct i9100_panel_spi panel_spi={0};struct i9100_panel_sleep panel={0};
 panel_spi.io=(struct i9100_panel_spi_io){0,lpm_panel_gpio_read,lpm_panel_gpio_write,
  lpm_panel_delay,lpm_panel_enter,lpm_panel_leave};
 panel.io=(struct i9100_panel_sleep_io){&panel_spi,lpm_panel_read_byte,lpm_panel_command,
  lpm_panel_scan_read,lpm_panel_scan_write,lpm_panel_wait};
 /* Unknown wiring/state uses the original supervised black-map path. Its
  * qualification error remains visible; no sleep command is sent. */
 if(screen_ok)(void)i9100_panel_probe(&panel);
#endif
 if(!screen_ok && (lpm_read(0x11c00000U,0x28)&1U))window=2;
 unsigned winmap=0x180+window*4,saved_map=lpm_read(0x11c00000U,winmap);
 uint64_t next_draw=0,remote_deadline=0;unsigned remote_action=0;
 struct i9100_charge_start start_gate={0};unsigned denied_press=0;
 for(;;){
  uint64_t now=lpm_ticks();
  if(now>=next){unsigned poll_result=i9100_power_poll(&i9100_lpm_battery);next=now+24000000U;
   i9100_charge_start_update(&start_gate,&i9100_lpm_battery,poll_result,lpm_now(0));
#if defined(CONFIG_EXYNOS_CDCACM4210)
   unsigned boot_ready=i9100_charge_start_ready(&start_gate,lpm_now(0));
#ifdef I9100_PANEL_SLEEP_BUILD
   if(panel.qualified && panel.stage==I9P_FAULT)boot_ready=0;
#endif
   usbcdc4210_charge_set_boot_ready(boot_ready);
   if((polls++%30)==0){
    uint64_t measured=lpm_ticks();
    struct i9100_charge_report report={0};
    report.sequence=++report_sequence;report.milliseconds=measured/24000U;
    report.valid=i9100_lpm_battery.valid;report.percent=i9100_lpm_battery.percent;
    report.millivolts=i9100_lpm_battery.millivolts;report.temperature_deci_c=i9100_lpm_battery.temperature_deci_c;
    report.charging=i9100_lpm_battery.charging;report.reason=i9100_lpm_battery.reason;
    report.full=i9100_lpm_battery.full;report.timeout=i9100_lpm_battery.timeout;report.recharging=i9100_lpm_battery.recharging;
    if(i9100_lpm_battery.charge_start && measured/24U*1000U>=i9100_lpm_battery.charge_start)
      report.elapsed_seconds=(measured/24U*1000U-i9100_lpm_battery.charge_start)/1000000000ULL;
    usbcdc4210_charge_timed_report(&report);
    usbcdc4210_charge_screen_report(drawn,(unsigned)screen.pixels,screen.stride,screen.bpp);
    unsigned fb[8]={lpm_read(0x11c00000U,0x20),lpm_read(0x11c00000U,0x28),
      lpm_read(0x11c00000U,0xb0),lpm_read(0x11c00000U,0x108),
      lpm_read(0x11c00000U,0x64),lpm_read(0x11c00000U,0xe0),
      lpm_read(0x11c00000U,0x188),blanked};
    usbcdc4210_charge_fimd_report(fb);
    unsigned render[8]={i9100_charge_render.art_ok,i9100_charge_render.art_frame,
      i9100_charge_render.frames,i9100_charge_render.stores,i9100_charge_render.last_stores,
      i9100_charge_render.unchanged,i9100_lpm_timer_rearms,i9100_lpm_timer_faults};
    usbcdc4210_charge_render_report(render);
    unsigned startup[8]={start_gate.ready,start_gate.samples,start_gate.blocked_presses,
      i9100_lpm_battery.present,i9100_lpm_battery.millivolts,i9100_lpm_battery.percent,
      i9100_lpm_battery.errors,(unsigned)i9100_lpm_battery.reason};
    usbcdc4210_charge_start_report(startup);
    usbcdc4210_charge_transport_report();
#ifdef I9100_PANEL_SLEEP_BUILD
    extern void usbcdc4210_charge_panel_report(const unsigned[8]);
    extern void usbcdc4210_charge_panel_identity_report(const unsigned[4]);
    extern void usbcdc4210_charge_panel_recovery_report(const unsigned[4]);
    unsigned panel_fields[8]={panel.qualified,panel.stage,panel.error,panel.mode,panel.commands,
      panel.saved_scanout,panel.owned_scanout,lpm_panel_scan_read(0)};
    usbcdc4210_charge_panel_report(panel_fields);
    unsigned panel_identity[4]={panel.identity_reads,panel.id[0],panel.id[1],panel.id[2]};
    usbcdc4210_charge_panel_identity_report(panel_identity);
    unsigned panel_recovery[4]={panel.recovery_attempts,panel.recovery_commands,panel.cleanup_error,panel.stage};
    usbcdc4210_charge_panel_recovery_report(panel_recovery);
#endif
   }
#endif
  }
  unsigned keys=lpm_read(0x11000000U,0xc44),home=lpm_read(0x11000000U,0xc64);
  if(!(keys&1U) && !(home&(1U<<5)))lpm_download();
  if(!(keys&(1U<<7))){if(!pressed)pressed=now;
   show_until=now+720000000U;
   if(blanked){
#ifdef I9100_PANEL_SLEEP_BUILD
    if(lpm_panel_awake(&panel)){
#endif
     lpm_write(0x11c00000U,winmap,saved_map);blanked=0;
#ifdef I9100_PANEL_SLEEP_BUILD
    }
#endif
   }
   if(now-pressed>=48000000U && i9100_charge_start_ready(&start_gate,lpm_now(0)) && !denied_press){
#ifdef I9100_PANEL_SLEEP_BUILD
    if(!lpm_panel_awake(&panel))lpm_download(); /* Power requested boot but panel is faulted. */
#endif
    break;
   }
   if(now-pressed>=48000000U && !i9100_charge_start_ready(&start_gate,lpm_now(0)) && !denied_press){
    start_gate.blocked_presses++;denied_press=1;
   }
  }else{pressed=0;denied_press=0;}
  if(!blanked && now>=show_until){
   lpm_write(0x11c00000U,winmap,(saved_map&~0x01ffffffU)|0x01000000U);blanked=1;
#ifdef I9100_PANEL_SLEEP_BUILD
   if(panel.qualified)(void)i9100_panel_sleep_change(&panel,0);
#endif
  }
  /* A panel wake may sleep120ms; schedule the next draw from the actual
   * post-transition MCT value, not the loop's earlier timestamp. */
  now=lpm_ticks();
  if(screen_ok && !blanked && now>=next_draw){
   if(i9100_charge_draw(&screen,i9100_lpm_battery.valid,i9100_lpm_battery.percent,
      i9100_lpm_battery.connected,i9100_lpm_battery.charging,i9100_lpm_battery.reason,
      i9100_lpm_battery.full,animation++)){
    /* Refresh only after actual final-pixel changes. No transfer is needed
     * for an unchanged SOC/charger state or a sleeping display. */
    if(i9100_charge_render.last_stores){LPM_BARRIER();lpm_write(0x11c00000U,0x1a4,3);}drawn=1;
   }else screen_ok=0;
   next_draw=now+24000000U; /* At most 1Hz and no framebuffer work while blanked. */
  }
  if(i9100_lpm_battery.valid && !i9100_lpm_battery.connected){
   i9100_power_stop(&i9100_lpm_battery);
   lpm_write(0x10020000U,0x330c,lpm_read(0x10020000U,0x330c)&~256U);
  }
#if defined(CONFIG_EXYNOS_CDCACM4210)
  usbcdc_poll();
  unsigned received_action=usbcdc4210_charge_take_action();
  /* Drawing, panel transitions and USB polling may have consumed time.
   * The grace period starts after the completed ACK is actually leased,
   * never from the older timestamp taken before those operations. */
  now=lpm_ticks();
  if(received_action && !remote_action){remote_action=received_action;remote_deadline=now+12000000U;}
  if(remote_action && now>=remote_deadline){
   if(remote_action==2)lpm_download();
   if(remote_action==1 && i9100_charge_start_ready(&start_gate,lpm_now(0))){
#ifdef I9100_PANEL_SLEEP_BUILD
    if(lpm_panel_awake(&panel))break;
#else
    break;
#endif
   }
   (void)usbcdc4210_charge_release_action(remote_action);
   remote_action=0;
  }
#endif
  lpm_sleep_tick();
 }
#ifdef I9100_PANEL_SLEEP_BUILD
 if(!lpm_panel_awake(&panel))lpm_download();
#endif
 if(blanked)lpm_write(0x11c00000U,winmap,saved_map);
 i9100_lpm_boot_gate=start_gate;
 i9100_lpm_boot_next=0;i9100_lpm_boot_phase=1;
 /* The plain bootstrap supervisor replaces the standalone periodic gate;
  * retaining an enabled comparator without its loop leaves pending IRQ89. */
 (void)lpm_mct_write(0x240,256,1U<<16);
 lpm_write(0x10050000U,0x244,1);lpm_write(0x10050000U,0x248,0);
 lpm_write(0x10490000U,0x188,1U<<25);lpm_write(0x10490000U,0x288,1U<<25);
 lpm_write(0x10020000U,0x808,0x12345678U);
 lpm_write(0x10020000U,0x80c,0x12345670U);
#if defined(CONFIG_EXYNOS_CDCACM4210)
 usbcdc4210_charge_identity(0);
#endif
#endif
}
#ifdef I9100_STANDALONE_CHARGE_BUILD
void i9100_boot_charge_finish(void)
{
 if(!i9100_lpm_boot_active)return;
 for(;;){
  /* Force one fresh supervised sample immediately before the actual jump,
   * after staging/decode and the host wait, not before either operation. */
  i9100_lpm_boot_next=0;i9100_boot_charge_service();
  if(i9100_charge_start_ready(&i9100_lpm_boot_gate,lpm_now(0)) &&
     i9100_power_stop(&i9100_lpm_battery))break;
  /* No low-cell reset loop: return to the same charging policy and wait for
   * another qualified Power/remote boot. The cell's deadline is not reset. */
  i9100_boot_charge_stage(8);i9100_lpm_resume_charge=1;
  i9100_standalone_charge_gate();
#if defined(CONFIG_EXYNOS_CDCACM4210)
  usbcdc4210_init(); /* Re-establish normal-loader USB after the held charger. */
#endif
 }
 /* No callback may re-enable the charger after the final checked stop. */
 lpm_write(0x10050000U,0x248,0);lpm_write(0x10490000U,0x188,1U<<25);
 i9100_lpm_boot_active=0;lpm_boot_report(7);
}
#endif
#endif
