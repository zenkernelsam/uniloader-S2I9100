#!/usr/bin/env python3
"""Check the production standalone charger MCT/GIC programming and bounds."""
import os,sys,subprocess
from pathlib import Path
from datetime import datetime
if os.environ.get('I9100_CPU_CAPPED')!='1':
 os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('lpm-timer-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
source=r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
static uint32_t mct[1024],dist[1024],cpu[1024],enabled[8],fimd[1024];
static uint64_t ticks;static unsigned stall,stuck,masked,waits,acks;
unsigned boot_reg_r2;
static uint32_t model_read32(void*a){uintptr_t p=(uintptr_t)a;
 if(p>=0x10050000 && p<0x10051000){unsigned o=p-0x10050000;
  if(o==0x100){if(!stuck)ticks++;return ticks;}if(o==0x104)return ticks>>32;
  return mct[o/4];}
 if(p>=0x10490000 && p<0x10491000)return dist[(p-0x10490000)/4];
 if(p>=0x10480000 && p<0x10481000){if(p==0x1048000c)return 89;return cpu[(p-0x10480000)/4];}
 if(p>=0x11c00000 && p<0x11c01000)return fimd[(p-0x11c00000)/4];
 assert(0);return 0;}
static void model_write32(uint32_t v,void*a){uintptr_t p=(uintptr_t)a;
 if(p>=0x10050000 && p<0x10051000){unsigned o=p-0x10050000;
  if(o==0x24c){mct[o/4]&=~v;return;}mct[o/4]=v;
  if(!stall){if(o==0x200)mct[0x24c/4]|=1;if(o==0x204)mct[0x24c/4]|=2;
   if(o==0x208)mct[0x24c/4]|=4;if(o==0x240)mct[0x24c/4]|=1<<16;}return;}
 if(p>=0x10490000 && p<0x10491000){unsigned o=p-0x10490000;
  if(o>=0x100&&o<0x120)enabled[(o-0x100)/4]|=v;
  if(o>=0x180&&o<0x1a0)enabled[(o-0x180)/4]&=~v;
  dist[o/4]=v;return;}
 if(p>=0x10480000 && p<0x10481000){cpu[(p-0x10480000)/4]=v;if(p==0x10480010){assert(v==89);acks++;}return;}
 assert(0);}
#define readl(a) model_read32(a)
#define writel(v,a) model_write32(v,a)
#define LPM_BARRIER() do{}while(0)
#define LPM_MASK_IRQ() do{masked=1;}while(0)
#define LPM_WAIT() do{ticks+=240000;waits++;}while(0)
#include "i9100-lpm.h"
static void reset(void){memset(mct,0,sizeof(mct));memset(dist,0,sizeof(dist));memset(cpu,0,sizeof(cpu));
 memset(enabled,255,sizeof(enabled));dist[1]=4;ticks=10;stall=stuck=masked=waits=acks=0;}
int main(void){
 struct i9100_charge_screen screen={0};unsigned window=0;
 memset(fimd,0,sizeof(fimd));fimd[0x28/4]=0x8035;fimd[0xb0/4]=0x5ec00000;
 fimd[0x108/4]=1920;fimd[0x64/4]=(479U<<11)|799U;fimd[0xe0/4]=0x5ed77000;
 assert(lpm_screen_bind(&screen,&window) && window==2 && screen.bpp==32 && screen.bytes==1536000);
 fimd[0x20/4]=1;assert(!lpm_screen_bind(&screen,&window));fimd[0x20/4]=0;
 fimd[0x108/4]|=4U<<13;assert(!lpm_screen_bind(&screen,&window));fimd[0x108/4]=1920;
 fimd[0xb0/4]=0x5ed00000;assert(!lpm_screen_bind(&screen,&window));
 struct I9100BootSource s={I9100_BOOT_SOURCE_MAGIC,1,3,1,0,1,0xb16,0x40000100};
 assert(lpm_boot_requested(&s));s.sboot_mode=0;assert(!lpm_boot_requested(&s));
 s.sboot_mode=1;s.flags=1;assert(!lpm_boot_requested(&s));
 s.flags=3;s.inform2=0x12345678;assert(!lpm_boot_requested(&s));
 reset();assert(lpm_timer_init()&&masked&&i9100_lpm_timer_ready);
 for(unsigned n=0;n<5;n++)assert(enabled[n]==(n==2?(1U<<25):0));
 assert(mct[0x208/4]==240000&&mct[0x248/4]==1&&mct[0x240/4]==259);
 assert(((dist[(0x800+88)/4]>>8)&255)==1);
 lpm_sleep_tick();assert(waits==1&&acks==1);
 /* Real rendering/USB work can exceed 10ms. The old helper WFI waited
  * against an expired compare. Verify a future match before each wait. */
 ticks=2000000ULL;mct[0x200/4]=1000;mct[0x204/4]=0;
 lpm_sleep_tick();assert(waits==2 && i9100_lpm_timer_rearms==1 && mct[0x200/4]>2000000U);
 stall=1;mct[0x200/4]=1000;unsigned before_waits=waits;
 lpm_sleep_tick();assert(waits==before_waits && i9100_lpm_timer_faults==1);
 lpm_sleep_tick();assert(waits==before_waits && !i9100_lpm_timer_ready);
 stall=0;lpm_sleep_tick();assert(waits==before_waits+1 && i9100_lpm_timer_ready);
 mct[0x248/4]=0;lpm_sleep_tick();assert(waits==before_waits+2 && mct[0x248/4]==1);
 reset();stall=1;assert(!lpm_timer_init());
 reset();stuck=1;assert(!lpm_timer_init());
 reset();dist[1]=31;assert(!lpm_timer_init());
 puts("PASS production MCT/GIC: IRQ89/10ms, wait/ACK, expired-draw compare rebased, failed rearm stays awake, handshake/counter/controller refusal");
}
'''
(out/'check.c').write_text(source)
for cmd,name in [(['clang','-O1','-g','-fno-pie','-no-pie','-fsanitize=address,undefined','-Wno-int-to-void-pointer-cast','-Wno-pointer-to-int-cast','-I'+str(repo/'board/samsung'),'-I'+str(repo/'include'),str(out/'check.c'),'-o',str(out/'check')],'compile'),([str(out/'check')],'result')]:
 r=subprocess.run(cmd,text=True,capture_output=True);(out/(name+'.log')).write_text(r.stdout+r.stderr);r.check_returncode()
 if name=='result':print(r.stdout.strip())
print('EVIDENCE',out)
