#!/usr/bin/env python3
"""Run the real charger Download guard and reset code with production policy."""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
        sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import hashlib,json,subprocess
repo=Path(__file__).resolve().parents[2]
path=repo/'board/samsung/i9100-lpm.h';text=path.read_text(encoding='utf8')
def function(prefix):
    start=text.index(prefix);brace=text.index('{',start);at=brace+1;depth=1
    while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
    return text[start:at]
prepare=function('static int lpm_prepare_download(')
download=function('static int lpm_download(')
gate=function('void i9100_standalone_charge_gate(')
combo_start=gate.index('  if(!(keys&1U) && !(home&(1U<<5))){')
combo_end=gate.index('  if(!(keys&(1U<<7)))',combo_start)
combo=gate[combo_start:combo_end]
out=repo/'out'/('charge-download-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>
#include "charge/i9100_power.h"
#define I9100_STANDALONE_CHARGE_BUILD 1
#define CONFIG_EXYNOS_CDCACM4210 1
struct Model {uint8_t registers[256];unsigned stuck_sub,stuck_main,sub_on,stop_requests,register_reads,register_writes;};
static struct Model model;
static struct i9100_power_state i9100_lpm_battery;
struct Gate {unsigned samples,ready,blocked_presses;uint64_t first_ns,last_ns;};
static struct Gate i9100_lpm_boot_gate;
static unsigned i9100_lpm_boot_in_service,i9100_lpm_boot_active,i9100_lpm_boot_owned;
static unsigned i9100_lpm_download_attempts,i9100_lpm_download_denied,i9100_lpm_download_confirmed;
static unsigned i9100_lpm_boot_fault,i9100_lpm_fault_phase,i9100_lpm_boot_phase;
static unsigned boot_ready=1,pmu_writes,waiting;
static uint32_t pmu[1024];static jmp_buf escaped;
static int pmic_read(void*c,unsigned reg,uint8_t*v){
 struct Model*m=c;assert(c==&model&&reg==0x51);m->register_reads++;*v=m->registers[reg];return 1;
}
static int pmic_write(void*c,unsigned reg,uint8_t v){
 struct Model*m=c;assert(c==&model&&reg==0x51);m->register_writes++;
 if(!m->stuck_main)m->registers[reg]=v;return 1;
}
static int sub_enable(void*c,unsigned value){
 struct Model*m=c;assert(c==&model&&value==0&&i9100_lpm_boot_in_service);
 m->stop_requests++;if(m->stuck_sub)return 0;m->sub_on=0;return 1;
}
void usbcdc4210_charge_set_boot_ready(unsigned value){assert(value==0);boot_ready=value;}
static void lpm_write(unsigned base,unsigned offset,uint32_t value){
 assert(base==0x10020000U&&(offset==0x808||offset==0x80c||offset==0x400));
 if(i9100_lpm_boot_owned){
  assert(!i9100_lpm_boot_active&&i9100_lpm_download_confirmed&&!i9100_lpm_battery.stop_uncertain);
  assert(!model.sub_on&&!(model.registers[0x51]&0xc0));
 }
 pmu_writes++;pmu[offset/4]=value;
}
#define LPM_WAIT() do{waiting++;longjmp(escaped,1);}while(0)
'''+prepare+'\n'+download+r'''
static void seed(unsigned sub,unsigned main){
 memset(&model,0,sizeof(model));model.registers[0x51]=0xc5;model.sub_on=1;
 model.stuck_sub=sub;model.stuck_main=main;
 memset(&i9100_lpm_battery,0,sizeof(i9100_lpm_battery));
 i9100_lpm_battery.ready=i9100_lpm_battery.valid=i9100_lpm_battery.enabled=i9100_lpm_battery.charging=1;
 i9100_lpm_battery.use_sub=1;i9100_lpm_battery.revision=14;i9100_lpm_battery.charge_start=12345;
 i9100_lpm_battery.charge_elapsed_base=400000000000ULL;
 i9100_lpm_battery.io.cookie=&model;i9100_lpm_battery.io.pmic_read=pmic_read;
 i9100_lpm_battery.io.pmic_write=pmic_write;i9100_lpm_battery.io.sub_enable=sub_enable;
 i9100_lpm_boot_gate=(struct Gate){11,1,0,1000000000,11000000000ULL};
 i9100_lpm_download_attempts=i9100_lpm_download_denied=i9100_lpm_download_confirmed=0;
 i9100_lpm_boot_fault=i9100_lpm_fault_phase=0;i9100_lpm_boot_phase=4;
 i9100_lpm_boot_owned=i9100_lpm_boot_active=boot_ready=1;
 i9100_lpm_boot_in_service=pmu_writes=waiting=0;memset(pmu,0,sizeof(pmu));
}
static void keys(unsigned keys,unsigned home,unsigned*held){
 unsigned download_held=*held;
'''+combo+r'''
 *held=download_held;
}
int main(void){
 alarm(10);
 for(unsigned sub=0;sub<2;sub++)for(unsigned main=0;main<2;main++){
  seed(sub,main);unsigned result=setjmp(escaped);
  if(!result){int reset=lpm_download();assert(!reset&& (sub||main));}
  assert(i9100_lpm_download_attempts==1&&model.stop_requests==1);
  assert(i9100_lpm_battery.charge_start==12345&&i9100_lpm_battery.charge_elapsed_base==400000000000ULL);
  assert((model.registers[0x51]&~0xc0U)==5U);
  if(sub||main){
   assert(!pmu_writes&&!waiting&&i9100_lpm_download_denied==1&&i9100_lpm_battery.stop_uncertain);
   assert(i9100_lpm_boot_active&&!i9100_lpm_battery.valid&&!boot_ready&&i9100_lpm_boot_fault==12);
   assert(!i9100_lpm_boot_gate.samples&&!i9100_lpm_boot_gate.ready);
  }else{
   assert(pmu_writes==3&&waiting==1&&i9100_lpm_download_confirmed&&!i9100_lpm_boot_active);
   assert(pmu[0x808/4]==0x12345678U&&pmu[0x80c/4]==0x12345671U&&pmu[0x400/4]==1);
  }
 }
 seed(1,0);unsigned held=0;
 for(unsigned n=0;n<100;n++)keys(0xfe,0xdf,&held);
 assert(model.stop_requests==1&&i9100_lpm_download_attempts==1&&!pmu_writes);
 keys(0xff,0xff,&held);keys(0xfe,0xdf,&held);
 assert(model.stop_requests==2&&i9100_lpm_download_attempts==2);
 seed(1,1);i9100_lpm_boot_in_service=1;assert(!lpm_prepare_download()&&i9100_lpm_boot_in_service==1);
 seed(0,0);i9100_lpm_boot_owned=0;assert(lpm_prepare_download()&&!model.stop_requests&&!i9100_lpm_download_attempts);
 puts("PASS production Download reset: confirmed main/sub off before three PMU writes; four readback outcomes; failure stays supervised and forbids boot; held keys submit once; period preserved; pre-owner fallback unchanged");
}
'''
(out/'check.c').write_text(code,encoding='utf8')
commands=(['clang','-std=c99','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'board/samsung'),
    str(out/'check.c'),str(repo/'board/samsung/charge/i9100_power.c'),'-o',str(out/'check')], [str(out/'check')])
for n,args in enumerate(commands):
    result=subprocess.run(args,text=True,capture_output=True)
    (out/f'command-{n}.log').write_text(result.stdout+result.stderr,encoding='utf8')
    if result.returncode:print((result.stdout+result.stderr)[-2500:],file=sys.stderr);result.check_returncode()
    if result.stdout:print(result.stdout.strip())
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,
    source_sha256={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        path,repo/'board/samsung/charge/i9100_power.c',repo/'board/samsung/charge/i9100_power.h')},
    limit='Actual stop policy/prepare/reset/key code with PMU and register facades; no physical Download/current observation'),indent=2)+'\n',encoding='utf8')
print('EVIDENCE',out)
