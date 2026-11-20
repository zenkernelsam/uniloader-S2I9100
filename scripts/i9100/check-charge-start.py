#!/usr/bin/env python3
"""Exercise real startup admission against fast/repeated/stale measurements.

No device access. The production header runs with explicit time and cell
state; an alarm bounds any accidental model loop and all evidence is kept.
"""
import os
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
        sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from datetime import datetime
from pathlib import Path
import hashlib
import json
import subprocess

repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('charge-start-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
out.mkdir()
source=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "i9100-charge-start.h"
static struct i9100_power_state good(void){
 struct i9100_power_state b={0};b.valid=b.present=1;b.percent=3;
 b.millivolts=3600;b.temperature_deci_c=250;return b;
}
int main(void){
 alarm(10);
 struct i9100_power_state b=good();struct i9100_charge_start gate={0};
 uint64_t start=1000000000ULL,now=start;
 /* Ten seconds of healthy recovery cannot be compressed into 11 calls. */
 for(unsigned n=0;n<1000;n++){
  i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
  now+=1000000ULL;
 }
 assert(gate.samples==11);
 for(unsigned n=0;n<9;n++){
  i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
  now+=1000000000ULL;
 }
 assert(now-start==10000000000ULL);
 i9100_charge_start_update(&gate,&b,0,now);
 assert(gate.ready && i9100_charge_start_ready(&gate,now));
 b.stop_uncertain=1;now+=1000000000ULL;
 i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready&&!gate.samples);
 b.stop_uncertain=0;
 for(unsigned n=0;n<11;n++){now+=1000000000ULL;i9100_charge_start_update(&gate,&b,0,now);}
 assert(gate.ready);
 /* New errors revoke BOTH count and age: earlier good duration cannot
  * survive voltage collapse, absent cell, timeout or a bad bus read. */
 b.millivolts=3599;now+=1000000000ULL;
 i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
 b=good();now+=1000000000ULL;
 for(unsigned n=0;n<10;n++){
  i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
  now+=1000000000ULL;
 }
 i9100_charge_start_update(&gate,&b,0,now);assert(gate.ready);
 assert(!i9100_charge_start_ready(&gate,now+2500000001ULL));
 assert(!i9100_charge_start_ready(&gate,now-1));
 now+=1000000000ULL;i9100_charge_start_update(&gate,&b,1,now);assert(!gate.ready);
 now+=1000000000ULL;i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
 /* Duplicate timestamps and a backwards/reset clock are not new samples. */
 unsigned samples=gate.samples;i9100_charge_start_update(&gate,&b,0,now);
 assert(!gate.ready && gate.samples<samples);
 i9100_charge_start_update(&gate,&b,0,now-1);assert(!gate.ready && !gate.samples);
 now+=5000000000ULL;i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready && !gate.samples);
 b.present=0;now+=1000000000ULL;i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
 b=good();b.temperature_deci_c=401;now+=1000000000ULL;
 i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
 b=good();b.timeout=1;now+=1000000000ULL;
 i9100_charge_start_update(&gate,&b,0,now);assert(!gate.ready);
 puts("PASS production startup admission: actual 10-second recovery plus 11 valid samples; dense callbacks, stale/reset time, voltage and IO failures cannot bypass it");
}
'''
(out/'check.c').write_text(source,encoding='utf-8')
commands=(['clang','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'board/samsung'),
    str(out/'check.c'),'-o',str(out/'check')],[str(out/'check')])
for n,command in enumerate(commands):
    result=subprocess.run(command,capture_output=True,text=True)
    (out/f'command-{n}.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode:
        print((result.stdout+result.stderr)[-3000:],file=sys.stderr)
        result.check_returncode()
    if result.stdout:print(result.stdout.strip(),flush=True)
header=repo/'board/samsung/i9100-charge-start.h'
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,
    header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
    limit='Production admission logic with modeled time/measurements; no real battery recovery proved'),indent=2)+'\n')
print('EVIDENCE',out,flush=True)
