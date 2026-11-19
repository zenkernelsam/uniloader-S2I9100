#!/usr/bin/env python3
"""Check production timed charging formatter and exact Python segment decoding.

No serial access. Test output and failure artifacts stay in loader out.
"""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from datetime import datetime
from pathlib import Path
import importlib.util,json,subprocess
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('charge-report-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
source=r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "i9100-charge-report.h"
int main(void){
 char line[256];struct i9100_charge_report r={0};r.sequence=1;r.milliseconds=30000;
 r.valid=1;r.percent=99;r.millivolts=4183;r.temperature_deci_c=243;r.charging=1;r.elapsed_seconds=30;
 assert(i9100_charge_format(line,sizeof(line),&r));
 assert(!strcmp(line,"I9CHG2 seq=00000001 ms=0000000000007530 valid=1 soc=99 mv=4183 temp=243 charging=1 reason=0 full=0 timeout=0 recharging=0 elapsed=30\n"));
 puts(line);r.sequence=2;r.milliseconds+=30000;r.percent=100;r.full=1;r.charging=0;r.reason=-4;r.elapsed_seconds=0;
 assert(i9100_charge_format(line,sizeof(line),&r));puts(line);
 r.sequence=3;r.milliseconds+=30000;r.percent=95;r.full=0;r.reason=0;r.recharging=1;r.charging=1;r.elapsed_seconds=30;
 assert(i9100_charge_format(line,sizeof(line),&r));puts(line);
 r.temperature_deci_c=INT32_MIN;r.reason=INT32_MIN;r.sequence=UINT32_MAX;r.milliseconds=UINT64_MAX;r.elapsed_seconds=UINT64_MAX;
 unsigned length=i9100_charge_format(line,sizeof(line),&r);assert(length && line[length-1]=='\n');
 assert(strstr(line,"temp=-2147483648") && strstr(line,"reason=-2147483648") && strstr(line,"elapsed=18446744073709551615"));
 for(unsigned cap=1;cap<=length;cap++){
  char guard[256];memset(guard,0xa5,sizeof(guard));
  assert(!i9100_charge_format(guard,cap,&r));
  for(unsigned n=cap;n<256;n++)assert((unsigned char)guard[n]==0xa5);
 }
 r.sequence=0;assert(!i9100_charge_format(line,sizeof(line),&r));
 puts("PASS production bounded formatter, signed int32 minimum, 64-bit clock/elapsed and small output guards");
}
'''
(out/'check.c').write_text(source)
for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',
    '-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],[str(out/'check')])):
    result=subprocess.run(cmd,text=True,capture_output=True);(out/f'command-{n}.log').write_text(result.stdout+result.stderr)
    if result.returncode:print((result.stdout+result.stderr)[-2500:],file=sys.stderr);result.check_returncode()
    if n==1:raw=result.stdout.encode()
spec=importlib.util.spec_from_file_location('timed_charge_summary',repo/'scripts/i9100/summarize-charge-loader.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
samples=m.decode_status(raw,[dict(total=len(raw),bytes=len(raw),time='host-receipt')]);assert len(samples)==3
assert samples[0]['measured_ms']==30000 and not samples[0]['interval_available']
assert all(x['interval_available'] and x['interval_ms']==30000 for x in samples[1:])
assert samples[1]['reason']==-4 and samples[2]['recharging']==1
assert samples[2]['observed_soc_change']==-5 and samples[2]['observed_millivolts_change']==0
first=raw.splitlines()[0]
gap=first.replace(b'seq=00000001',b'seq=00000005').replace(b'ms=0000000000007530',b'ms=000000000001d4c0')
reset=first.replace(b'ms=0000000000007530',b'ms=0000000000000001')
legacy=b'I9CHG1 valid=1 soc=99 mv=4180 temp=250 charging=0 reason=4294967292\n'
cases=m.decode_status(first+b'\n'+gap+b'\n'+reset+b'\n'+legacy+first+b'\n',[])
assert len(cases)==5 and not any(x.get('interval_available',False) for x in cases)
assert cases[3]['reason']==-4 and cases[3]['reason_wire']==4294967292 and cases[3]['version']==1
assert m.decode_status(first,[])==[]
try:m.decode_status(first.replace(b'seq=00000001',b'seq=00000000')+b'\n',[])
except ValueError:pass
else:raise AssertionError('Zero sequence accepted')
(out/'result.json').write_text(json.dumps(dict(result='PASS',samples=samples,gap_reset_cases=cases,hardware=False),indent=2)+'\n')
print('PASS production timed formatter and actual decoder; signed/old wire, continuous times, gaps/reset, no host-clock rates')
print('EVIDENCE',out)
