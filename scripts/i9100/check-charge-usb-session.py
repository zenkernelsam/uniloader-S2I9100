#!/usr/bin/env python3
"""Check production USB deadlines, one recovery lease and retained trace bounds."""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import hashlib,json,subprocess
repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('charge-usb-session-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
source=r'''
#include <assert.h>
#include <stdio.h>
#include "i9100-charge-usb-session.h"
int main(void){
 struct i9100_charge_usb_session s;const uint64_t sec=I9U_TICKS_PER_SECOND;
 assert(!i9u_init(&s,119)&&!i9u_init(&s,601));
 assert(i9u_init(&s,0));i9u_configure(&s,1,sec);
 assert(!i9u_poll_deadline(&s,1000000ULL*sec));
 i9u_fault(&s,I9U_IO);assert(!i9u_take_recovery(&s));
 assert(i9u_init(&s,180));i9u_configure(&s,1,sec);
 assert(!i9u_poll_deadline(&s,180ULL*sec));
 i9u_reset_link(&s);i9u_configure(&s,1,150ULL*sec);
 assert(s.configured_at==sec && i9u_poll_deadline(&s,181ULL*sec)==I9U_NO_OPEN);
 assert(i9u_take_recovery(&s)==I9U_NO_OPEN && !i9u_take_recovery(&s));
 i9u_reset_link(&s);assert(!i9u_take_recovery(&s)&&s.fault==I9U_NO_OPEN);
 assert(i9u_init(&s,180));i9u_configure(&s,1,sec);i9u_setup(&s);
 i9u_dtr(&s,1,2ULL*sec);assert(!s.opened&&!s.ready_pending);
 i9u_setup(&s);i9u_status_done(&s,3ULL*sec);assert(!s.opened);
 i9u_dtr(&s,1,4ULL*sec);i9u_status_done(&s,5ULL*sec);
 assert(s.opened&&s.had_open&&s.ready_pending&&s.report_pending);
 i9u_in_start(&s,6ULL*sec);assert(!i9u_poll_deadline(&s,185ULL*sec));
 i9u_in_done(&s);assert(!i9u_poll_deadline(&s,1000000ULL*sec));
 i9u_in_start(&s,1000001ULL*sec);
 assert(i9u_poll_deadline(&s,1000181ULL*sec)==I9U_IN_STALL);
 assert(i9u_take_recovery(&s)==I9U_IN_STALL&&!i9u_take_recovery(&s));
 assert(i9u_init(&s,180));i9u_configure(&s,1,sec);i9u_setup(&s);
 i9u_dtr(&s,1,2ULL*sec);i9u_status_done(&s,3ULL*sec);
 i9u_setup(&s);i9u_dtr(&s,0,4ULL*sec);i9u_status_done(&s,5ULL*sec);
 assert(!s.opened&&!i9u_poll_deadline(&s,1000000ULL*sec));
 i9u_setup(&s);i9u_dtr(&s,1,1000001ULL*sec);
 assert(i9u_poll_deadline(&s,1000181ULL*sec)==I9U_CONTROL_STALL);
 assert(i9u_init(&s,180));i9u_configure(&s,1,sec);
 assert(i9u_poll_deadline(&s,sec-1)==I9U_CLOCK);
 uint32_t page[1024],words[32]={I9U_TRACE_MAGIC,1,128,1};
 for(unsigned n=0;n<1024;n++)page[n]=0xa5a5a5a5;
 words[31]=i9u_trace_checksum(words);i9u_trace_publish(page+I9U_TRACE_LIVE_OFFSET/4,words);
 words[3]=2;words[7]=0x101;words[31]=i9u_trace_checksum(words);
 i9u_trace_publish(page+I9U_TRACE_FAULT_OFFSET/4,words);
 assert(page[I9U_TRACE_LIVE_OFFSET/4+3]==1 && page[I9U_TRACE_FAULT_OFFSET/4+3]==2);
 for(unsigned n=0;n<1024;n++)if(!((n>=0xc0&&n<0xe0)||(n>=0x100&&n<0x120)))assert(page[n]==0xa5a5a5a5);
 puts("PASS default-off, real status gating, deadlines without reset extension, one recovery lease and panic/epoch RAM isolation");
}
'''
(out/'check.c').write_text(source)
for i,cmd in enumerate((['clang','-O1','-g','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],[str(out/'check')])):
    r=subprocess.run(cmd,text=True,capture_output=True);(out/f'command-{i}.log').write_text(r.stdout+r.stderr)
    if r.returncode:print((r.stdout+r.stderr)[-2500:],file=sys.stderr);r.check_returncode()
    if r.stdout:print(r.stdout.strip(),flush=True)
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,source_sha256={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (repo/'board/samsung/i9100-charge-usb-session.h',Path(__file__))},limit='Production state helper and RAM models, no actual USB, reset, watchdog or charge current'),indent=2)+'\n')
print('EVIDENCE',out)
