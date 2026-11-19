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
#define I9100_STANDALONE_CHARGE_BUILD 1
#define CONFIG_EXYNOS_CDCACM4210 1
#define LPM_BARRIER() do{}while(0)
static struct i9100_power_state i9100_lpm_battery;
static unsigned i9100_boot_source,scenario,draws,late_draws,blanked,last_unblank,remote_issued,stops,reports,usb_calls;
static uint64_t ticks,last_draw_ticks,reset_ticks;static uint32_t fb[480*800];static jmp_buf escaped;
static unsigned pmu2,pmu3,wait_ticks;
static int lpm_boot_requested(const unsigned*p){return *p==1;}
static int lpm_timer_init(void){return 1;}
static uint64_t lpm_ticks(void){return ticks;}
static unsigned lpm_revision(void){return 14;}
static unsigned seconds(void){return (unsigned)(ticks/24000000ULL);}
static uint32_t lpm_read(unsigned base,unsigned off){
 if(base==0x10060000 && off==0)return 33;
 if(base==0x11000000 && off==0xc44){
  if(scenario==1 && seconds()>=35 && seconds()<38)return 0x7f;
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
int i9100_power_init(struct i9100_power_state*s,const struct i9100_power_io*io,unsigned r){(void)io;assert(r==14);memset(s,0,sizeof(*s));s->valid=s->connected=s->charging=1;s->millivolts=scenario==4?3400:4000;s->percent=50;return 0;}
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
void usbcdc_poll(void){usb_calls++;}
void usbcdc4210_charge_set_boot_ready(unsigned available){assert(available==(scenario!=4));}
unsigned usbcdc4210_charge_take_action(void){
 if(scenario>=2 && scenario<=4 && seconds()>=35 && !remote_issued){remote_issued=1;return scenario==3?2:1;}
 return 0;
}
static void lpm_download(void){reset_ticks=ticks;longjmp(escaped,2);}
static int lpm_screen_bind(struct i9100_charge_screen*s,unsigned*w){s->pixels=fb;s->bytes=sizeof(fb);s->stride=1920;s->bpp=32;*w=2;return 1;}
static int wrapped_draw(const struct i9100_charge_screen*s,unsigned valid,unsigned percent,unsigned connected,unsigned charging,int reason,unsigned full,unsigned frame){
 assert(!blanked);if(draws)assert(ticks-last_draw_ticks>=24000000ULL);last_draw_ticks=ticks;draws++;
 if(seconds()>=30 && seconds()<35)late_draws++;
 return i9100_charge_draw(s,valid,percent,connected,charging,reason,full,frame);
}
#define i9100_charge_draw wrapped_draw
static void lpm_sleep_tick(void){ticks+=240000;wait_ticks++;if(seconds()>40 && scenario==4)longjmp(escaped,4);}
'''+gate+r'''
int main(void){
 for(scenario=1;scenario<=5;scenario++){
  ticks=draws=late_draws=blanked=last_unblank=remote_issued=stops=reports=usb_calls=pmu2=pmu3=wait_ticks=0;i9100_boot_source=1;
  unsigned result=setjmp(escaped);if(!result){i9100_standalone_charge_gate();result=1;}
  assert(late_draws==0 && draws>=30 && usb_calls>1000 && reports>=2);
  if(scenario==1){assert(result==1 && ticks>=37ULL*24000000 && last_unblank==35);assert(pmu2==0x12345678 && pmu3==0x12345670 && stops==1);}
  if(scenario==2){assert(result==1 && ticks>=35ULL*24000000+12000000ULL && pmu3==0x12345670 && stops==1);}
  if(scenario==3){assert(result==2 && reset_ticks>=35ULL*24000000+12000000ULL && !pmu3);}
  if(scenario==4){assert(result==4 && !stops && !pmu2 && !pmu3);}
  if(scenario==5){assert(result==3 && stops==1 && seconds()>=35);}
 }
 puts("PASS production standalone gate: window2 blank/unblank, 1Hz draw then no drawing asleep, long press/remote 500ms fence, low voltage refusal and unplug poweroff");
}
'''
(out/'check.c').write_text(code)
for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wno-pointer-to-int-cast','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],[str(out/'check')])):
    r=subprocess.run(cmd,text=True,capture_output=True);(out/f'command-{n}.log').write_text(r.stdout+r.stderr)
    if r.returncode:print((r.stdout+r.stderr)[-3000:],file=sys.stderr);r.check_returncode()
    if r.stdout:print(r.stdout.strip(),flush=True)
print('EVIDENCE',out,flush=True)
