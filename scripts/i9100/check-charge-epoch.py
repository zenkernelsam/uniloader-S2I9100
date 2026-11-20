#!/usr/bin/env python3
"""Exercise actual loader epoch helpers and the synced PE halt hook offline.

Production policy/wire code runs under ASan/UBSan. PMU, retained DDR, clock,
RTC read and the nonreturning reset are facades; no phone or flash access.
"""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
        sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import hashlib,importlib.util,json,subprocess
repo=Path(__file__).resolve().parents[2];xnu=repo.parent/'xnu-S2I9100'
out=repo/'out'/('charge-epoch-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
lpm=(repo/'board/samsung/i9100-lpm.h').read_text(encoding='utf-8')
pe=(xnu/'pexpert/arm/pe_exynos4210_i9100.c').read_text(encoding='utf-8')
def function(text,start):
    a=text.index(start);b=text.index('{',a);n=b+1;depth=1
    while depth:depth+=(text[n]=='{')-(text[n]=='}');n+=1
    return text[a:n]
capture=function(lpm,'static void lpm_capture_charge_epoch(')
restore=function(lpm,'static void lpm_restore_charge_epoch(')
halt=function(pe,'static int i9100_halt_restart(')
halt=halt.replace('__asm__ volatile("dsb sy" ::: "memory");','test_barrier();')
halt=halt.replace('__asm__ volatile("wfi");','test_wait();')
source=r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include "charge/i9100_charge_epoch.h"
#include "main/i9100-charge-handoff.h"
static uint32_t pmu[4096],cell[1024],gpio[1024];
static volatile uint32_t live[32];
static uint64_t current_ns=100000000000ULL,rtc_seconds=900000010ULL;
static unsigned read_ops,write_ops,rtc_ops,rtc_ok=1,wait_ops;
static struct I9100ChargeEpoch i9100_lpm_prior_epoch;
static unsigned i9100_lpm_epoch_marked,i9100_lpm_epoch_match,i9100_lpm_epoch_result;
static uint64_t i9100_lpm_epoch_rtc;
static uint64_t i9100_lpm_epoch_base;
static struct i9100_power_state i9100_lpm_battery;
static struct i9100_power_hw i9100_lpm_hw;
#define I9100_CHARGE_EPOCH_SLOT ((volatile uint32_t *)((uint8_t *)cell+I9100_CHARGE_EPOCH_OFFSET))
#define LPM_BARRIER() do{}while(0)
static uint32_t lpm_read(unsigned base,unsigned off){assert(base==0x10020000U && (off==0x818 || off==0x81c));read_ops++;return pmu[off/4];}
static void lpm_write(unsigned base,unsigned off,uint32_t value){assert(base==0x10020000U && (off==0x818 || off==0x81c));write_ops++;pmu[off/4]=value;}
static uint64_t lpm_now(void*c){(void)c;return current_ns;}
int i9100_power_rtc_seconds(void*c,uint64_t *value){assert(c==&i9100_lpm_hw);rtc_ops++;*value=rtc_seconds;return rtc_ok;}
static uintptr_t i9100_trace_pmu=(uintptr_t)pmu,i9100_trace_cell=(uintptr_t)cell,i9100_lpm_gpio=(uintptr_t)gpio;
static int i9100_lpm_loader_supported=1,i9100_os_reboot_download;
static unsigned i9100_power_connected=1;
#define i9100_charge_epoch_live live
#define kPEHaltCPU 0
#define kPERestartCPU 1
#define FALSE 0
static jmp_buf exit_hook;
static void test_wait(void){wait_ops++;longjmp(exit_hook,1);}
static void test_barrier(void){}
static int ml_set_interrupts_enabled(int n){assert(n==0);return 1;}
static uint64_t mach_absolute_time(void){return current_ns;}
static void i9100_pmu_reset_registers(uintptr_t base,int download){assert(base==(uintptr_t)pmu);pmu[0x808/4]=0x12345678;pmu[0x80c/4]=download?0x12345671:0x12345670;pmu[0x400/4]=1;}
'''+'\n'+capture+'\n'+restore+'\n'+halt+r'''
static void seed(void){
 memset(pmu,0,sizeof(pmu));memset(cell,0xa5,sizeof(cell));memset(gpio,0,sizeof(gpio));
 memset(&i9100_lpm_battery,0,sizeof(i9100_lpm_battery));
 i9100_lpm_battery.ready=1;i9100_lpm_battery.revision=14;i9100_lpm_battery.use_sub=1;
 i9100_lpm_epoch_marked=i9100_lpm_epoch_match=i9100_lpm_epoch_result=0;
 memset(&i9100_lpm_prior_epoch,0,sizeof(i9100_lpm_prior_epoch));
 read_ops=write_ops=rtc_ops=wait_ops=0;rtc_ok=1;
 current_ns=100000000000ULL;rtc_seconds=900000010ULL;
 struct i9100_power_state source={0};source.ready=source.valid=source.present=source.connected=1;
 source.revision=14;source.use_sub=1;source.percent=50;source.millivolts=4000;
 source.temperature_deci_c=250;source.enabled=source.charging=1;source.charge_start=1000000000ULL;
 source.charge_refresh=90000000000ULL;source.charge_elapsed_base=5000000000000ULL;
 struct I9100ChargeEpoch record;i9100_charge_epoch_encode(&record,&source,current_ns,7,1,900000000ULL);
 i9100_charge_epoch_publish(live,&record);
}
int main(int argc,char **argv){
 assert(argc==2);alarm(10);
 seed();current_ns+=20000000000ULL;
 int state=setjmp(exit_hook);if(!state){i9100_halt_restart(kPEHaltCPU);assert(0);}
 assert(wait_ops==1 && pmu[0x400/4]==1 && pmu[0x808/4]==0 && pmu[0x80c/4]==0);
 assert(pmu[0x818/4]==I9100_CHARGE_EPOCH_MARKER);
 for(unsigned n=0;n<64;n++)assert(cell[n]==0xa5a5a5a5U); // Existing panic record untouched.
 for(unsigned n=96;n<1024;n++)assert(cell[n]==0xa5a5a5a5U);
 struct I9100ChargeEpoch sealed;assert(i9100_charge_epoch_read(I9100_CHARGE_EPOCH_SLOT,&sealed));
 assert(sealed.route==1 && sealed.checksum==pmu[0x81c/4]);
 char path[4096];snprintf(path,sizeof(path),"%s/sealed.bin",argv[1]);FILE*f=fopen(path,"wb");assert(f);
 assert(fwrite(&sealed,1,sizeof(sealed),f)==sizeof(sealed));fclose(f);
 current_ns=8000000000ULL;rtc_seconds=900000030ULL; // Actual S-Boot resets MCT.
 lpm_capture_charge_epoch();assert(i9100_lpm_epoch_marked && i9100_lpm_epoch_match);
 assert(!I9100_CHARGE_EPOCH_SLOT[0] && !pmu[0x818/4] && !pmu[0x81c/4] && write_ops==2);
 lpm_restore_charge_epoch();assert(i9100_lpm_epoch_result==I9E_RESTORED && rtc_ops==1);
 assert(i9100_lpm_battery.charge_start==current_ns && i9100_lpm_battery.charge_elapsed_base==5131000000000ULL);
 for(unsigned mode=0;mode<4;mode++){
  seed();current_ns+=1000000000ULL;
  state=setjmp(exit_hook);if(!state){i9100_halt_restart(kPEHaltCPU);assert(0);}
  if(mode==0)pmu[0x81c/4]^=1;
  if(mode==1)I9100_CHARGE_EPOCH_SLOT[4]=7;
  if(mode==2)rtc_ok=0;
  if(mode==3)rtc_seconds=899999999ULL;
  current_ns=8000000000ULL;lpm_capture_charge_epoch();lpm_restore_charge_epoch();
  assert(i9100_lpm_epoch_result==I9E_REJECTED && i9100_lpm_battery.timeout && !i9100_lpm_battery.enabled);
 }
 seed();uint32_t previous[1024];memcpy(previous,cell,sizeof(cell));
 lpm_capture_charge_epoch();lpm_restore_charge_epoch();
 assert(!i9100_lpm_epoch_marked && !write_ops && !rtc_ops && !memcmp(previous,cell,sizeof(cell)));
 assert(i9100_lpm_epoch_result==I9E_NONE);
 seed();pmu[0x81c/4]=123;for(unsigned n=0;n<32;n++)I9100_CHARGE_EPOCH_SLOT[n]=live[n];
 lpm_capture_charge_epoch();lpm_restore_charge_epoch();
 assert(i9100_lpm_epoch_marked && !i9100_lpm_epoch_match && !write_ops && pmu[0x81c/4]==123);
 assert(i9100_lpm_epoch_result==I9E_REJECTED && i9100_lpm_battery.timeout && !I9100_CHARGE_EPOCH_SLOT[0]);
 seed();state=setjmp(exit_hook);if(!state){i9100_halt_restart(kPERestartCPU);assert(0);}
 assert(pmu[0x808/4]==0x12345678 && pmu[0x80c/4]==0x12345670 && !pmu[0x818/4]);
 puts("PASS production PE normal halt seal, panic-slot guard, loader single consume, MCT reset/RTC elapsed restore and uncertain-record stop");
}
'''
(out/'check.c').write_text(source,encoding='utf-8')
for index,command in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'include'),'-I'+str(repo/'board/samsung'),
    str(out/'check.c'),'-o',str(out/'check')],[str(out/'check'),str(out)])):
    result=subprocess.run(command,capture_output=True,text=True)
    (out/f'command-{index}.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode:print((result.stdout+result.stderr)[-3000:],file=sys.stderr);result.check_returncode()
    if result.stdout:print(result.stdout.strip(),flush=True)
spec=importlib.util.spec_from_file_location('charge_epoch_host',Path(__file__).with_name('charge-handoff.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
decoded=h.decode_epoch((out/'sealed.bin').read_bytes())
assert decoded['elapsed_ns']==5099000000000 and decoded['route']==1 and decoded['rtc_seconds']==900000000
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,decoded=decoded,
    source_sha256={str(p.relative_to(repo.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (
    repo/'board/samsung/i9100-lpm.h',repo/'board/samsung/charge/i9100_charge_epoch.h',xnu/'pexpert/arm/pe_exynos4210_i9100.c',
    repo/'scripts/i9100/charge-handoff.py')},
    limit='Actual production helpers/PE hook, explicit register/RTC/reset facades; no physical warm reset or cell recovery verified'),indent=2)+'\n',encoding='utf-8')
print('EVIDENCE',out,flush=True)
