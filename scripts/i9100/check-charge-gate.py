#!/usr/bin/env python3
"""Run the production standalone-charger gate with bounded hardware facades.

Real draw code and gate execute; MCT/keys/USB/PMU and battery measurements are
modeled. No actual phone, reset or flash. Output remains in this repository.
"""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import subprocess
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('charge-gate-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
text=(repo/'board/samsung/i9100-lpm.h').read_text();start=text.index('void i9100_standalone_charge_gate(void)');begin=text.index('{',start);depth=1;end=begin+1
while depth:
    depth+=(text[end]=='{')-(text[end]=='}');end+=1
gate=text[start:end]
code=r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>
#include "charge/i9100_power.h"
#include "i9100-charge-screen.h"
#include "i9100-charge-report.h"
#include "i9100-charge-start.h"
#include "charge/i9100_panel_spi.h"
#include "charge/i9100_panel_sleep.h"
#define I9100_STANDALONE_CHARGE_BUILD 1
#define CONFIG_EXYNOS_CDCACM4210 1
#define LPM_BARRIER() do{}while(0)
static struct i9100_power_state i9100_lpm_battery;
static unsigned i9100_boot_source,scenario,draws,late_draws,blanked,last_unblank,remote_issued,stops,reports,usb_calls;
static uint64_t ticks,last_draw_ticks,reset_ticks,action_taken_ticks;static uint32_t fb[480*800];static jmp_buf escaped;
static unsigned pmu2,pmu3,wait_ticks,panel_mode=0x9c,panel_scan=0x1003,panel_commands;
static unsigned i9100_lpm_timer_rearms,i9100_lpm_timer_faults;
static int lpm_boot_requested(const unsigned*p){return *p==1;}
static int lpm_timer_init(void){return 1;}
static uint64_t lpm_ticks(void){return ticks;}
static unsigned lpm_revision(void){return 14;}
static unsigned seconds(void){return (unsigned)(ticks/24000000ULL);}
static uint32_t lpm_read(unsigned base,unsigned off){
 if(base==0x10060000 && off==0)return 33;
 if(base==0x11000000 && off==0xc44){
  if((scenario==1 || scenario==6 || scenario==7 || scenario==9) && seconds()>=35 && seconds()<38)return 0x7f;
  return 0xff;
 }
 if(base==0x11000000 && off==0xc64)return 0xff;
 if(base==0x10020000 && off==0x330c)return 256;
 if(base==0x11c00000){
  if(off==0x20)return 0;
  if(off==0x28)return 0x8035;
  if(off==0xb0)return 0x5ec00000;
  if(off==0x108)return 1920;
  if(off==0x64)return (479U<<11)|799U;
  if(off==0xe0)return 0x5ed77000;
  if(off==0x188)return blanked?0x1000000:0;
  return 0;
 }
 assert(0);return 0;
}
static void lpm_write(unsigned base,unsigned off,uint32_t value){
 if(base==0x11c00000){
  if(off==0x1a4){assert(value==3);return;}
  assert(off==0x188);blanked=value&0x1000000; if(!blanked)last_unblank=seconds();return;
 }
 if(base==0x10060000){assert(off==0 && !(value&33));return;}
 if(base==0x10020000){
  if(off==0x808)pmu2=value;
  else if(off==0x80c)pmu3=value;
  else if(off==0x330c){assert(!(value&256));longjmp(escaped,3);}
  else assert(0);return;
 }
 assert(base==0x10050000 || base==0x10490000);
}
static uint32_t lpm_hw_read(void*c,unsigned r,unsigned o){(void)c;(void)r;(void)o;return 0;}
static void lpm_hw_write(void*c,unsigned r,unsigned o,uint32_t v){(void)c;(void)r;(void)o;(void)v;}
static void lpm_delay(void*c,unsigned n){(void)c;(void)n;}
static void lpm_enter(void*c){(void)c;}static void lpm_leave(void*c){(void)c;}
static uint64_t lpm_now(void*c){(void)c;return ticks*1000/24;}
int i9100_power_init(struct i9100_power_state*s,const struct i9100_power_io*io,unsigned r){(void)io;assert(r==14);memset(s,0,sizeof(*s));s->valid=s->present=s->connected=s->charging=1;s->millivolts=scenario==4?3400:4000;s->percent=50;s->temperature_deci_c=250;return 0;}
int i9100_power_poll(struct i9100_power_state*s){if(scenario==5 && seconds()>=35)s->connected=0;return 0;}
int i9100_power_stop(struct i9100_power_state*s){(void)s;stops++;return 0;}
int i9100_power_pmic_read(void*c,unsigned r,uint8_t*v){(void)c;(void)r;(void)v;return 0;}
int i9100_power_pmic_write(void*c,unsigned r,uint8_t v){(void)c;(void)r;(void)v;return 0;}
int i9100_power_fuel_read(void*c,unsigned r,uint16_t*v){(void)c;(void)r;(void)v;return 0;}
int i9100_power_adc_read(void*c,unsigned r,unsigned*v){(void)c;(void)r;(void)v;return 0;}
int i9100_power_sub_read(void*c,unsigned*v,unsigned*w){(void)c;(void)v;(void)w;return 0;}
int i9100_power_sub_enable(void*c,unsigned v){(void)c;(void)v;return 0;}
int i9100_power_muic_read(void*c,unsigned r,uint8_t*v){(void)c;(void)r;(void)v;return 0;}
int i9100_power_muic_write(void*c,unsigned r,uint8_t v){(void)c;(void)r;(void)v;return 0;}
int usbcdc4210_init(void){return 0;}void usbcdc4210_charge_identity(int n){assert(n==0 || n==1);}
void usbcdc4210_charge_timed_report(const struct i9100_charge_report *r){
 assert(r->sequence==reports+1 && r->milliseconds==ticks/24000 && r->percent==50);reports++;
}
void usbcdc4210_charge_screen_report(unsigned d,unsigned b,unsigned s,unsigned p){(void)d;(void)b;assert(s==1920 && p==32);}
void usbcdc4210_charge_fimd_report(const unsigned p[8]){assert(p[1]==0x8035 && p[6]==(blanked?0x1000000:0));}
void usbcdc4210_charge_render_report(const unsigned p[8]){assert(p[0]<=1 && p[4]<=480*800);}
void usbcdc4210_charge_start_report(const unsigned p[8]){assert(p[0]<=1 && p[1]<=11 && p[3]==1);}
void usbcdc_poll(void){usb_calls++;
 if(scenario==10 && seconds()>=35 && !remote_issued)ticks+=7200000ULL;
}
void usbcdc4210_charge_set_boot_ready(unsigned available){
#ifdef I9100_PANEL_SLEEP_BUILD
 assert(available==(seconds()>=11 && scenario!=4 && !(scenario==6 && seconds()>=31 && seconds()<36) &&
  !((scenario==8 || scenario==9) && seconds()>=31)));
#else
 assert(available==(seconds()>=11 && scenario!=4));
#endif
}
unsigned usbcdc4210_charge_take_action(void){
 if(((scenario>=2 && scenario<=4) || scenario==8 || scenario==10) && seconds()>=35 && !remote_issued){
  remote_issued=1;action_taken_ticks=ticks;return scenario==3||scenario==8||scenario==10?2:1;
 }
 return 0;
}
unsigned usbcdc4210_charge_release_action(unsigned action){assert(action==1);return 1;}
static void lpm_download(void){reset_ticks=ticks;longjmp(escaped,2);}
static int lpm_screen_bind(struct i9100_charge_screen*s,unsigned*w){s->pixels=fb;s->bytes=sizeof(fb);s->stride=1920;s->bpp=32;*w=2;return 1;}
static int wrapped_draw(const struct i9100_charge_screen*s,unsigned valid,unsigned percent,unsigned connected,unsigned charging,int reason,unsigned full,unsigned frame){
 assert(!blanked);if(draws)assert(ticks-last_draw_ticks>=24000000ULL);last_draw_ticks=ticks;draws++;
 if(seconds()>=30 && seconds()<35)late_draws++;
 return i9100_charge_draw(s,valid,percent,connected,charging,reason,full,frame);
}
#define i9100_charge_draw wrapped_draw
static void lpm_sleep_tick(void){ticks+=240000;wait_ticks++;if(seconds()>40 && scenario==4)longjmp(escaped,4);}
static uint32_t lpm_panel_gpio_read(void*c,unsigned o){(void)c;(void)o;return 0;}
static void lpm_panel_gpio_write(void*c,unsigned o,uint32_t v){(void)c;(void)o;(void)v;}
static void lpm_panel_delay(void*c,unsigned us){(void)c;(void)us;}
static unsigned lpm_panel_enter(void*c){(void)c;return 0;}
static void lpm_panel_leave(void*c,unsigned n){(void)c;(void)n;}
static int lpm_panel_read_byte(void*c,unsigned reg,uint8_t*v){(void)c;
 *v=reg==0xda?(scenario==7?0x00:0xa1):reg==0xdb?0x12:reg==0xdc?0x11:
  scenario==9 && seconds()>=35?0xff:panel_mode;return 1;}
static int lpm_panel_command(void*c,unsigned cmd){(void)c;++panel_commands;
 if(scenario!=6 && scenario!=8 && scenario!=9){if(cmd==0x28)panel_mode&=~4U;else if(cmd==0x10)panel_mode&=~16U;
  else if(cmd==0x11)panel_mode|=16U;else if(cmd==0x29)panel_mode|=4U;}
 return 1;}
static uint32_t lpm_panel_scan_read(void*c){(void)c;return panel_scan;}
static void lpm_panel_scan_write(void*c,uint32_t v){(void)c;panel_scan=v;}
static void lpm_panel_wait(void*c,unsigned ms){(void)c;ticks+=(uint64_t)ms*24000U;}
static int lpm_panel_awake(struct i9100_panel_sleep*p){return !p->qualified || !i9100_panel_sleep_change(p,1);}
void usbcdc4210_charge_panel_report(const unsigned values[8]){
 assert(values[0]<=1 && values[1]<=4 && values[7]==panel_scan);
 if(values[0] && values[1]==I9P_SLEEP)assert(!(values[7]&3));
}
void usbcdc4210_charge_panel_identity_report(const unsigned values[4]){
 assert(values[0]==0x3f && values[1]==(scenario==7?0:0xa1) && values[2]==0x12 && values[3]==0x11);
}
void usbcdc4210_charge_panel_recovery_report(const unsigned values[4]){
 assert(values[0]<=1 && values[1]<=2 && values[3]<=4);
}
'''+gate+r'''
int main(void){
 for(scenario=1;scenario<=
#ifdef I9100_PANEL_SLEEP_BUILD
 10
#else
 10
#endif
 ;scenario++){
#ifndef I9100_PANEL_SLEEP_BUILD
  if(scenario>=6 && scenario<=9)continue;
#endif
  panel_mode=0x9c;panel_scan=0x1003;panel_commands=0;
  ticks=action_taken_ticks=draws=late_draws=blanked=last_unblank=remote_issued=stops=reports=usb_calls=pmu2=pmu3=wait_ticks=0;i9100_boot_source=1;i9100_charge_renderer_reset();
  unsigned result=setjmp(escaped);if(!result){i9100_standalone_charge_gate();result=1;}
  assert(late_draws==0 && draws>=30 && usb_calls>1000 && reports>=2);
  if(scenario!=6 && scenario!=8 && scenario!=10)assert(panel_scan==0x1003 || scenario>=3 && scenario<=5);
  if(scenario==1){assert(result==1 && ticks>=37ULL*24000000 && last_unblank==35);assert(pmu2==0x12345678 && pmu3==0x12345670 && stops==1);}
  if(scenario==2){assert(result==1 && ticks>=35ULL*24000000+12000000ULL && pmu3==0x12345670 && stops==1);}
  if(scenario==3){assert(result==2 && reset_ticks>=35ULL*24000000+12000000ULL && !pmu3);}
  if(scenario==4){assert(result==4 && !stops && !pmu2 && !pmu3);}
  if(scenario==5){assert(result==3 && stops==1 && seconds()>=35);}
  if(scenario==6){assert(result==1 && !blanked && panel_commands==1 && stops==1 && last_unblank==35);}
  if(scenario==7){assert(result==1 && panel_commands==0 && last_unblank==35);}
  if(scenario==8){assert(result==2 && blanked && panel_commands==1);}
  if(scenario==9){assert(result==2 && blanked && panel_commands==1 && !stops);}
  if(scenario==10){assert(result==2 && reset_ticks>=action_taken_ticks+12000000ULL);}
 }
 puts("PASS production standalone gate: window2 blank/unblank, 1Hz draw then no drawing asleep, long press/remote 500ms fence, low voltage refusal, panel-sleep retained scanout/fault/unknown fallbacks and unplug poweroff");
}
'''
for variant in ('legacy','panel'):
    actual=code if variant=='legacy' else code.replace('#define I9100_STANDALONE_CHARGE_BUILD 1','#define I9100_STANDALONE_CHARGE_BUILD 1\n#define I9100_PANEL_SLEEP_BUILD 1')
    (out/(variant+'.c')).write_text(actual)
    for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wno-pointer-to-int-cast','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'board/samsung'),str(out/(variant+'.c')),'-o',str(out/variant)],[str(out/variant)])):
        r=subprocess.run(cmd,text=True,capture_output=True);(out/f'{variant}-command-{n}.log').write_text(r.stdout+r.stderr)
        if r.returncode:print((r.stdout+r.stderr)[-3000:],file=sys.stderr);r.check_returncode()
        if r.stdout:print(variant,r.stdout.strip(),flush=True)
print('EVIDENCE',out,flush=True)
