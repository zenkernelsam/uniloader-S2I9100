#!/usr/bin/env python3
"""Verify the original boot-source wire slot and defining SBL2 bytes."""
import os,sys,importlib.util,struct,subprocess
from pathlib import Path
from datetime import datetime
if os.environ.get('I9100_CPU_CAPPED')!='1':
 os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('boot-source-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
spec=importlib.util.spec_from_file_location('dt',Path(__file__).with_name('prepare-payloads.py'));dt=importlib.util.module_from_spec(spec);spec.loader.exec_module(dt)
blob=dt.device_tree();(out/'tree.bin').write_bytes(blob)
firm=(repo.parent/'assets/sbl2.bin').read_bytes()
expected=(0xe92d4800,0xe28db004,0xe24dd008,0xe50b0008,0xe59f3020,0xe51b2008,0xe5832000,0xe59f3018)
assert struct.unpack_from('<8I',firm,0x12b04)==expected
assert struct.unpack_from('<I',firm,0x12b3c)[0]==0x4d5ed924
source=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "main/i9100-boot-source.h"
int main(int argc,char**argv){
 assert(argc==2);unsigned char b[4096],before[4096],duplicate[8192];
 FILE*f=fopen(argv[1],"rb");assert(f);unsigned n=fread(b,1,sizeof(b),f);fclose(f);memcpy(before,b,n);
 struct I9100BootSource r={I9100_BOOT_SOURCE_MAGIC,1,3,1,0x12345670,1,0xdc4,0x40000100};
 assert(sizeof(r)==32 && !i9100_boot_source_patch(0,n,&r));
 assert(!i9100_boot_source_patch(b,67,&r)&&!memcmp(b,before,n));
 assert(i9100_boot_source_patch(b,n,&r));
 unsigned at=0;for(unsigned k=0;k+68<=n;k+=4)if(!memcmp(b+k,I9100_BOOT_SOURCE_PROPERTY,18)){at=k+36;break;}
 assert(at&& !memcmp(b+at,&r,32));
 assert(!memcmp(b,before,at)&&!memcmp(b+at+32,before+at+32,n-at-32));
 memcpy(duplicate,b,n);memcpy(duplicate+n,b,n);
 assert(!i9100_boot_source_patch(duplicate,n*2,&r));
 r.version=2;assert(!i9100_boot_source_patch(before,n,&r));
 puts("PASS production Apple DT boot-source slot, preserved surrounding/prior data, bounded writes and duplicate/version refusal");
}
'''
(out/'check.c').write_text(source)
for cmd,name in [(['clang','-O1','-g','-fno-pie','-no-pie','-fsanitize=address,undefined','-I'+str(repo/'include'),str(out/'check.c'),'-o',str(out/'check')],'compile'),([str(out/'check'),str(out/'tree.bin')],'result')]:
 r=subprocess.run(cmd,text=True,capture_output=True);(out/(name+'.log')).write_text(r.stdout+r.stderr);r.check_returncode()
 if name=='result':print(r.stdout.strip())
print('EVIDENCE',out)
