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
import subprocess,importlib.util
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('charge-gate-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
text=(repo/'board/samsung/i9100-lpm.h').read_text();start=text.index('void i9100_standalone_charge_gate(void)');begin=text.index('{',start);depth=1;end=begin+1
while depth:
    depth+=(text[end]=='{')-(text[end]=='}');end+=1
gate=text[start:end]
def function(name):
    prefixes=('void '+name+'(','static int '+name+'(')
    start=next(text.index(prefix) for prefix in prefixes if prefix in text);begin=text.index('{',start);depth=1;end=begin+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]
service=function('i9100_boot_charge_service')
finish=function('i9100_boot_charge_finish')
boot_report=function('lpm_boot_report')
stage=function('i9100_boot_charge_stage')
failure=function('i9100_boot_charge_failure')
prepare_download=function('lpm_prepare_download')
render_progress=text[text.index('static void lpm_charge_render_progress(void)\n'):]
begin=render_progress.index('{');depth=1;end=begin+1
while depth:depth+=(render_progress[end]=='{')-(render_progress[end]=='}');end+=1
render_progress=render_progress[:end]
spec=importlib.util.spec_from_file_location('charge_gate_tree',Path(__file__).with_name('prepare-payloads.py'))
dt=importlib.util.module_from_spec(spec);spec.loader.exec_module(dt)
tree=dt.device_tree();(out/'tree.bin').write_bytes(tree)
code=r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>
#include <unistd.h>
static void lpm_charge_render_progress(void);
#define I9100_CHARGE_RENDER_PROGRESS() lpm_charge_render_progress()
#include "charge/i9100_power.h"
#include "i9100-charge-screen.h"
#include "i9100-charge-report.h"
#include "i9100-charge-sense.h"
#include "i9100-charge-start.h"
#include "main/i9100-charge-handoff.h"
#include "main/i9100-boot-source.h"
#include "charge/i9100_charge_epoch.h"
#include "charge/i9100_panel_spi.h"
#include "charge/i9100_panel_sleep.h"
#define I9100_STANDALONE_CHARGE_BUILD 1
#define CONFIG_EXYNOS_CDCACM4210 1
#define LPM_BARRIER() do{}while(0)
static struct i9100_power_state i9100_lpm_battery;
static struct i9100_power_hw i9100_lpm_hw;
static struct i9100_charge_start i9100_lpm_boot_gate;
static unsigned i9100_lpm_boot_active,i9100_lpm_boot_owned,i9100_lpm_resume_charge,i9100_lpm_boot_in_service;
static unsigned i9100_lpm_boot_polls,i9100_lpm_boot_phase;
static unsigned i9100_lpm_boot_fault,i9100_lpm_fault_phase;
static uint64_t i9100_lpm_boot_next;
static uint64_t i9100_lpm_boot_sample_ticks;
static struct I9100ChargeEpoch i9100_lpm_prior_epoch;
static unsigned i9100_lpm_epoch_marked,i9100_lpm_epoch_match,i9100_lpm_epoch_result;
static uint64_t i9100_lpm_epoch_rtc;
static unsigned i9100_lpm_download_attempts,i9100_lpm_download_denied,i9100_lpm_download_confirmed;
static unsigned power_init_calls,failed_stop,sense_sequence,slow_render;
static unsigned gate_duplicate_polls,policy_polls,report_delayed;
static struct i9100_charge_report group_report;
static uint64_t last_policy_ticks;
static unsigned stop_sequence,last_boot_stage,fault_reports,boot_admission,slow_sample;
static uint64_t first_key_seen,last_key_seen,unblank_ticks,last_blank_ticks;
struct I9100BootSource i9100_boot_source;
static unsigned scenario,draws,late_draws,blanked,last_unblank,remote_issued,stops,reports,usb_calls;
static uint64_t ticks,last_draw_ticks,reset_ticks,action_taken_ticks;static uint32_t fb[480*800];static jmp_buf escaped;
static unsigned pmu2,pmu3,wait_ticks,panel_mode=0x9c,panel_scan=0x1003,panel_commands;
static unsigned i9100_lpm_timer_rearms,i9100_lpm_timer_faults;
static uint8_t device_tree[4096] __attribute__((aligned(4)));
static unsigned device_tree_bytes;
void i9100_boot_charge_failure(unsigned);
void i9100_boot_charge_service(void);
static int lpm_boot_requested(const struct I9100BootSource*p){return p->flags==1;}
static int lpm_timer_init(void){return 1;}
static int lpm_mct_write(unsigned offset,uint32_t value,uint32_t mask){assert(offset==0x240 && value==256 && mask==65536);return 1;}
static uint64_t lpm_ticks(void){return ticks;}
static unsigned lpm_revision(void){return 14;}
static unsigned seconds(void){return (unsigned)(ticks/24000000ULL);}
static uint32_t lpm_read(unsigned base,unsigned off){
 if(base==0x10060000 && off==0)return 33;
 if(base==0x11000000 && off==0xc44){
  if(scenario==24 && seconds()>=35 && seconds()<38)return 0xfe;
  if(scenario==17 && seconds()>=35 && seconds()<40){if(!first_key_seen)first_key_seen=ticks;return 0x7f;}
  if((scenario==18 && ticks>=35ULL*24000000 && ticks<35ULL*24000000+16800000ULL) ||
     (scenario==19 && ticks>=35ULL*24000000 && ticks<35ULL*24000000+1200000ULL)){
   if(!first_key_seen)first_key_seen=ticks;last_key_seen=ticks;return 0x7f;
  }
  if(scenario==12 && seconds()>=66 && seconds()<70)return 0x7f;
  if(scenario>=11 && scenario<=16 && seconds()>=54 && seconds()<57)return 0x7f;
  if(scenario>=11 && scenario<=16 && seconds()>=35 && seconds()<38)return 0x7f;
  if((scenario==1 || scenario==6 || scenario==7 || scenario==9) && seconds()>=35 && seconds()<38)return 0x7f;
  return 0xff;
 }
 if(base==0x11000000 && off==0xc64)return scenario==24 && seconds()>=35 && seconds()<38?0xdf:0xff;
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
  if(off==0x1a4){assert(value==3 && !blanked);return;}
  assert(off==0x188);blanked=value&0x1000000;
  if(!blanked){last_unblank=seconds();unblank_ticks=ticks;}else last_blank_ticks=ticks;
  return;
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
static void lpm_capture_charge_epoch(void){}
static void lpm_restore_charge_epoch(void){}
static void lpm_charge_epoch_report(void){}
int i9100_power_init(struct i9100_power_state*s,const struct i9100_power_io*io,unsigned r){power_init_calls++;assert(r==14);memset(s,0,sizeof(*s));s->io=*io;s->revision=14;s->use_sub=1;s->ready=s->enabled=s->valid=s->present=s->connected=s->charging=1;s->millivolts=scenario==4?3400:4000;s->percent=50;s->temperature_deci_c=250;s->charge_start=12345;return 0;}
int i9100_power_stop(struct i9100_power_state*);
int i9100_power_poll(struct i9100_power_state*s){assert(s->io.cookie==&i9100_lpm_hw);
 if(policy_polls && i9100_lpm_boot_phase==0 && ticks>=last_policy_ticks && ticks-last_policy_ticks<24000000ULL)
  gate_duplicate_polls++;
 policy_polls++;last_policy_ticks=ticks;
 if(scenario>=11)ticks+=2400U; /* Each real bus sample advances the MCT. */
 if((scenario==17 || scenario==18) && seconds()>=35 && !slow_sample){ticks+=9600000U;slow_sample=1;}
 if((scenario==5 && seconds()>=35) || (scenario==16 && seconds()>=62) ||
    (scenario>=18 && seconds()>=68))s->connected=0;
 if(scenario==11){s->millivolts=seconds()>=40 && seconds()<44?3400:4000;}
 if(s->stop_uncertain){assert(i9100_power_stop(s));s->valid=1;s->reason=0;}
 if(scenario==13 && seconds()>=40){s->timeout=1;s->reason=-5;s->enabled=s->charging=0;}
 else if(s->connected && !s->timeout)s->enabled=s->charging=1;
 if(scenario==21 && report_delayed){s->percent=51;s->millivolts=3990;}
 if(scenario==22 && report_delayed){s->percent=0;s->millivolts=3199;}
 return 0;}
int i9100_power_stop(struct i9100_power_state*s){s->enabled=s->charging=0;stops++;stop_sequence++;
 if((scenario==12 || scenario==23 || scenario==24) && !failed_stop){failed_stop=1;s->stop_uncertain=1;return 0;}
 s->stop_uncertain=0;return 1;}
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
 assert(r->milliseconds==ticks/24000 && r->percent==(scenario==21 && report_delayed?51U:
   scenario==22 && report_delayed?0U:50U));
 reports++;sense_sequence=r->sequence;group_report=*r;
 if(scenario==21 && !report_delayed){
  ticks+=24000000ULL;report_delayed=1;i9100_boot_charge_service();
 }
 if(scenario==22 && r->sequence==2 && !report_delayed){
  assert(boot_admission);ticks+=24000000ULL;report_delayed=1;i9100_boot_charge_service();
  assert(!boot_admission); /* The callback revoked ready before any later RX. */
 }
}
int i9100_power_charge_adc_read(void*c,unsigned*v){assert(c==&i9100_lpm_hw);*v=974;return 1;}
void usbcdc4210_charge_sense_report(const unsigned timing[8],const unsigned registers[8]){
 assert(timing[0]==sense_sequence && registers[0]==timing[0]);
 assert(timing[4]==(ticks?0x381U:0U) && timing[5]==(ticks?974U:0xffffffffU));
 assert(timing[6]<=1 && timing[7]<=1);
 assert(((uint64_t)timing[2]<<32|timing[1])==group_report.milliseconds);
}
void usbcdc4210_charge_policy_report(const unsigned p[8]){
 assert(p[0]==group_report.sequence && p[1]>0 && p[6]<=11 && p[7]<=1);
 assert((((uint64_t)p[5]<<32)|p[4])-(((uint64_t)p[3]<<32)|p[2])==24000000ULL);
}
void usbcdc4210_charge_download_report(const unsigned p[8]){
 assert(p[0]==group_report.sequence && p[1]>=p[2] && p[3]<=1 && p[4]<=1 && p[5]<=1 && p[6]<=1);
 assert(p[4]==group_report.valid && p[7]==(unsigned)group_report.reason);
}
void usbcdc4210_charge_screen_report(unsigned d,unsigned b,unsigned s,unsigned p){(void)d;(void)b;assert(s==1920 && p==32);}
void usbcdc4210_charge_fimd_report(const unsigned p[8]){assert(p[1]==0x8035 && p[6]==(blanked?0x1000000:0));}
void usbcdc4210_charge_render_report(const unsigned p[8]){assert(p[0]<=1 && p[4]<=480*800);}
void usbcdc4210_charge_dirty_report(const unsigned p[8]){
 assert(p[2]<=396U*258U+96U*28U && p[5]<=1 && p[6]<=1 && p[7]<=1);
 if(p[6])assert(p[5] && p[7]);
}
void usbcdc4210_charge_start_report(const unsigned p[8]){
 assert(p[0]<=1 && p[1]<=11 && p[3]==1);
 assert(p[4]==group_report.millivolts && p[5]==group_report.percent && p[7]==(unsigned)group_report.reason);
}
void usbcdc4210_charge_transport_report(void){}
void usbcdc4210_charge_fault_report(const unsigned p[8]){
 assert(i9100_lpm_boot_fault && p[0]==i9100_lpm_boot_fault && p[1]==i9100_lpm_fault_phase);
 assert(p[3]==i9100_lpm_battery.valid && p[7]==(unsigned)i9100_lpm_battery.reason);fault_reports++;
}
void usbcdc4210_charge_boot_report(const unsigned p[8]){
 assert(p[0]>=1 && p[0]<=9 && p[2]<=1 && p[7]<=1);last_boot_stage=p[0];
 if(p[0]==7){
  assert(stops && !i9100_lpm_boot_active && !i9100_lpm_battery.enabled);
  ticks+=9600000ULL; /* Host control IO can delay a synchronous status report. */
 }
}
void usbcdc4210_charge_boot_report_passive(const unsigned p[8]){
 assert(p[0]==7 && stops && !i9100_lpm_boot_active && !i9100_lpm_battery.enabled);
 last_boot_stage=7; /* Enqueue-only status: zero simulated time/hardware calls. */
}
void usbcdc_poll(void){usb_calls++;
 if(scenario==10 && seconds()>=35 && !remote_issued)ticks+=7200000ULL;
}
void usbcdc4210_charge_set_boot_ready(unsigned available){
 boot_admission=available;
 if(i9100_lpm_boot_fault)assert(!available);
 if(available)assert(i9100_charge_start_ready(&i9100_lpm_boot_gate,lpm_now(0)) && !i9100_lpm_boot_fault);
}
unsigned usbcdc4210_charge_take_action(void){
 if(scenario==23 && seconds()>=35 && !remote_issued){remote_issued=1;action_taken_ticks=ticks;return 2;}
 if(scenario==15 && seconds()>=65 && !remote_issued){remote_issued=1;action_taken_ticks=ticks;return 2;}
 if(((scenario>=2 && scenario<=4) || scenario==8 || scenario==10) && seconds()>=35 && !remote_issued){
  remote_issued=1;action_taken_ticks=ticks;return scenario==3||scenario==8||scenario==10?2:1;
 }
 return 0;
}
unsigned usbcdc4210_charge_release_action(unsigned action){assert(action==1 || action==2);return 1;}
static int lpm_prepare_download(void);
static int lpm_download(void){if(!lpm_prepare_download())return 0;reset_ticks=ticks;longjmp(escaped,2);}
static int lpm_screen_bind(struct i9100_charge_screen*s,unsigned*w){s->pixels=fb;s->bytes=sizeof(fb);s->stride=1920;s->bpp=32;*w=2;return 1;}
static int wrapped_draw(const struct i9100_charge_screen*s,unsigned valid,unsigned percent,unsigned connected,unsigned charging,int reason,unsigned full,unsigned frame){
 assert(!!blanked==(i9100_charge_previous_buffer==0));if(draws)assert(ticks-last_draw_ticks>=24000000ULL);last_draw_ticks=ticks;draws++;
 if(seconds()>=30 && seconds()<35)late_draws++;
 return i9100_charge_draw(s,valid,percent,connected,charging,reason,full,frame);
}
#define i9100_charge_draw wrapped_draw
static void lpm_sleep_tick(void){ticks+=240000;wait_ticks++;
 if((seconds()>40 && scenario==4) || (seconds()>70 && (scenario==13 || scenario==14)))longjmp(escaped,4);}
void i9100_boot_charge_service(void);
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
'''+prepare_download+'\n'+service+'\n'+boot_report+'\n'+stage+'\n'+render_progress.replace(
 ' i9100_boot_charge_service();',' if(scenario==20 && !slow_render){ticks+=24000000ULL;slow_render=1;}\n i9100_boot_charge_service();')+'\n'+gate+'\n'+finish+'\n'+failure+r'''
int main(int argc,char **argv){
 assert(argc==3);FILE *tree_file=fopen(argv[1],"rb");assert(tree_file);
 device_tree_bytes=fread(device_tree,1,sizeof(device_tree),tree_file);fclose(tree_file);
 assert(i9100_charge_handoff_slot(device_tree,device_tree_bytes));
 alarm(20); /* A stuck offline model cannot hold a CPU indefinitely. */
 for(scenario=1;scenario<=
#ifdef I9100_PANEL_SLEEP_BUILD
 24
#else
 24
#endif
 ;scenario++){
  fprintf(stderr,"SCENARIO %u begin\n",scenario);fflush(stderr);
#ifndef I9100_PANEL_SLEEP_BUILD
  if(scenario>=6 && scenario<=9)continue;
#endif
  panel_mode=0x9c;panel_scan=0x1003;panel_commands=0;
  ticks=action_taken_ticks=draws=late_draws=blanked=last_unblank=remote_issued=stops=reports=usb_calls=pmu2=pmu3=wait_ticks=0;i9100_boot_source.flags=1;i9100_charge_renderer_reset();
  i9100_lpm_boot_active=i9100_lpm_boot_owned=i9100_lpm_resume_charge=i9100_lpm_boot_in_service=i9100_lpm_boot_polls=0;
  i9100_lpm_boot_fault=i9100_lpm_fault_phase=0;
  i9100_lpm_download_attempts=i9100_lpm_download_denied=i9100_lpm_download_confirmed=0;
  i9100_lpm_boot_next=0;
  power_init_calls=failed_stop=stop_sequence=last_boot_stage=fault_reports=boot_admission=slow_sample=slow_render=0;
  gate_duplicate_polls=policy_polls=report_delayed=0;last_policy_ticks=0;
  first_key_seen=last_key_seen=unblank_ticks=last_blank_ticks=0;
  i9100_boot_charge_failure(99);assert(!i9100_lpm_boot_fault && !power_init_calls); /* ordinary boot */
  unsigned result=setjmp(escaped);if(!result){
   i9100_standalone_charge_gate();result=1;
   if(scenario>=11 && scenario<=16){
    ticks=40ULL*24000000;
    if(scenario>=14){i9100_lpm_boot_phase=5;i9100_boot_charge_failure(1);assert(0);}
    else i9100_boot_charge_finish(device_tree,device_tree_bytes);
   }
  }
  assert((scenario>=20 || late_draws==0) && draws>=30 && usb_calls>1000 && reports>=2);
  assert(!gate_duplicate_polls); /* One actual policy owner and one-second cadence. */
  if(scenario!=6 && scenario!=8 && scenario!=10 && scenario<18)assert(panel_scan==0x1003 || scenario>=3 && scenario<=5);
  if(scenario==1 || scenario==2 || scenario==6 || scenario==7){
   assert(i9100_lpm_boot_active && stops==0 && i9100_lpm_battery.enabled);
   assert(i9100_lpm_battery.io.cookie==&i9100_lpm_hw);
   unsigned previous_polls=i9100_lpm_boot_polls;
   ticks+=24000000ULL;i9100_boot_charge_service();assert(stops==0 && i9100_lpm_battery.enabled && i9100_lpm_boot_polls>previous_polls);
   previous_polls=i9100_lpm_boot_polls;i9100_boot_charge_service();assert(i9100_lpm_boot_polls==previous_polls);
   ticks+=24000000ULL;uint64_t finish_began=ticks;i9100_boot_charge_finish(device_tree,device_tree_bytes);
   assert(ticks-finish_began<=2400U); /* Only the modeled fresh cell sample, no USB wait after stop. */
   assert(stops==1 && !i9100_lpm_boot_active && !i9100_lpm_battery.enabled && i9100_lpm_boot_phase==7 && last_boot_stage==7);
   struct I9100ChargeHandoff *record=(void*)i9100_charge_handoff_slot(device_tree,device_tree_bytes);
   assert(record && record->magic==I9100_CHARGE_HANDOFF_MAGIC && record->bytes==128 && record->flags==7);
   assert(record->checksum==i9100_charge_handoff_checksum(record) && !record->enabled_after && !record->charging_after);
   assert(record->qualified_samples==11 && record->recovery_seconds>=10 && record->millivolts==4000);
   assert(record->revision==14 && record->sub_charger==1);
   if(scenario==1){
    char output[4096];snprintf(output,sizeof(output),"%s/%s-handoff.bin",argv[2],
#ifdef I9100_PANEL_SLEEP_BUILD
     "panel"
#else
     "legacy"
#endif
    );FILE *saved=fopen(output,"wb");assert(saved && fwrite(record,1,128,saved)==128);fclose(saved);
   }
  }
  if(scenario==1){assert(result==1 && ticks>=37ULL*24000000 && last_unblank==35);assert(pmu2==0x12345678 && pmu3==0x12345670 && stops==1);}
  if(scenario==2){assert(result==1 && ticks>=35ULL*24000000+12000000ULL && pmu3==0x12345670 && stops==1);}
  if(scenario==3){assert(result==2 && reset_ticks>=35ULL*24000000+12000000ULL && !pmu3);}
  if(scenario==4){assert(result==4 && !stops && !pmu2 && !pmu3);}
  if(scenario==5){assert(result==3 && stops==1 && seconds()>=35);}
  if(scenario==6){assert(result==1 && !blanked && panel_commands==1 && stops==1 && last_unblank==35);}
  if(scenario==7){assert(result==1 && panel_commands==0 && last_unblank==35);}
  if(scenario==8){assert(result==2 && blanked && panel_commands==1);}
  if(scenario==9){assert(result==2 && blanked && panel_commands==1 && stops==1);}
  if(scenario==10){assert(result==2 && reset_ticks>=action_taken_ticks+12000000ULL);}
  if(scenario==11 || scenario==12){
   assert(result==1 && power_init_calls==1 && !i9100_lpm_boot_active && i9100_lpm_boot_phase==7);
   assert(i9100_lpm_battery.charge_start==12345 && ticks>=56ULL*24000000);
   assert(stops==(scenario==12?3:1) && !i9100_lpm_battery.enabled);
  }
  if(scenario==13){
   assert(result==4 && power_init_calls==1 && i9100_lpm_boot_active && pmu2!=0);
   assert(i9100_lpm_battery.timeout==1 && i9100_lpm_battery.charge_start==12345);
   assert(stops==0 && i9100_lpm_boot_phase==8 && !i9100_lpm_battery.enabled);
  }
  if(scenario>=14 && scenario<=16){
   assert(power_init_calls==1 && i9100_lpm_boot_fault==1 && i9100_lpm_fault_phase==5);
   assert((i9100_lpm_boot_active || result==2) && !boot_admission && fault_reports>=1 && i9100_lpm_battery.charge_start==12345);
   if(scenario==14)assert(result==4 && stops==0 && i9100_lpm_battery.enabled && last_boot_stage==9);
   if(scenario==15)assert(result==2 && stops==1 && reset_ticks>=action_taken_ticks+12000000ULL);
   if(scenario==16)assert(result==3 && stops==1 && !i9100_lpm_battery.enabled);
  }
  if(scenario==17){
   assert(result==1 && slow_sample && first_key_seen && i9100_lpm_boot_active);
   assert(ticks-first_key_seen>=48000000ULL); /* Two actual seconds after key observation. */
  }
  if(scenario==18 || scenario==19){
   assert(result==3 && first_key_seen && unblank_ticks && stops==1);
   assert(last_blank_ticks>=unblank_ticks+720000000ULL && last_blank_ticks>=last_key_seen+720000000ULL);
   assert(!pmu2 && !pmu3); /* A real short wake does not start the kernel. */
#ifdef I9100_PANEL_SLEEP_BUILD
   assert(panel_scan==0x1000); /* Unplugging after the later blank stays asleep. */
#else
   assert(panel_scan==0x1003);
#endif
  }
  if(scenario==20){
   assert(result==3 && slow_render && i9100_lpm_boot_polls>=2 && stops==1);
   assert(i9100_charge_render.initial_hidden==1 && i9100_charge_render.initial_committed==1);
   assert(i9100_charge_render.progress_calls>100 && !pmu2 && !pmu3);
  }
  if(scenario==21){assert(result==3 && report_delayed && stops==1 && !pmu2 && !pmu3);}
  if(scenario==22){assert(result==3 && report_delayed && !boot_admission && stops==1 && !pmu2 && !pmu3);}
  if(scenario==23 || scenario==24){
   assert(result==3 && failed_stop && stops==3 && !pmu2 && !pmu3);
   assert(i9100_lpm_download_attempts==1 && i9100_lpm_download_denied==1 && !i9100_lpm_download_confirmed);
   assert(i9100_lpm_boot_active && i9100_lpm_boot_fault==12 && !boot_admission && fault_reports);
  }
  if(result==2)assert(stops==1 && i9100_lpm_download_confirmed==1 && !i9100_lpm_boot_active);
  fprintf(stderr,"SCENARIO %u done\n",scenario);fflush(stderr);
 }
 puts("PASS production charger startup/failure and Power timing: persistent IO, fresh two-second hold, thirty-second short wake, final checked stop, low/failed-stop hold, fault logs/download/unplug and ACK grace");
}
'''
for variant in ('legacy','panel'):
    actual=code if variant=='legacy' else code.replace('#define I9100_STANDALONE_CHARGE_BUILD 1','#define I9100_STANDALONE_CHARGE_BUILD 1\n#define I9100_PANEL_SLEEP_BUILD 1')
    (out/(variant+'.c')).write_text(actual)
    for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wno-pointer-to-int-cast','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'board/samsung'),'-I'+str(repo/'include'),str(out/(variant+'.c')),'-o',str(out/variant)],[str(out/variant),str(out/'tree.bin'),str(out)])):
        r=subprocess.run(cmd,text=True,capture_output=True);(out/f'{variant}-command-{n}.log').write_text(r.stdout+r.stderr)
        if r.returncode:print((r.stdout+r.stderr)[-3000:],file=sys.stderr);r.check_returncode()
        if r.stdout:print(variant,r.stdout.strip(),flush=True)
    spec=importlib.util.spec_from_file_location('production_gate_handoff',Path(__file__).with_name('charge-handoff.py'))
    decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
    decoded=decoder.decode((out/(variant+'-handoff.bin')).read_bytes())
    assert decoded['valid'] and decoded['enabled_before']==1 and decoded['enabled_after']==0
print('EVIDENCE',out,flush=True)
