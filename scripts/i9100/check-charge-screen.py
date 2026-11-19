#!/usr/bin/env python3
"""Render the actual standalone charger UI and test exact buffer bounds.

No device access. Keep the generated pixel previews and all failure evidence.
"""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import subprocess,json,struct,zlib
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('charge-screen-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
code=r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "charge/i9100_power.h"
#include "i9100-charge-screen.h"
int main(int argc,char**argv){assert(argc==2);
 struct i9100_charge_screen bound={0};
 assert(i9100_charge_bind(&bound,0x8035,0x5ec00000,1920,(479U<<11)|799U,0x5ed77000));
 assert(!i9100_charge_bind(&bound,0x8035,0x5ed00000,1920,(479U<<11)|799U,0x5ee77000));
 for(unsigned mode=5;mode<=11;mode+=6){unsigned stride=mode==5?960:1920;
  assert(i9100_charge_bind(&bound,(mode<<2)|1,0x43e00000,stride,(479U<<11)|799U,0x43e00000+stride*800));
  assert(!i9100_charge_bind(&bound,mode<<2,0x43e00000,stride,(479U<<11)|799U,0x43e00000+stride*800));
  assert(!i9100_charge_bind(&bound,(mode<<2)|1,0x40008000,stride,(479U<<11)|799U,0x40008000+stride*800));
  assert(!i9100_charge_bind(&bound,(mode<<2)|1,0x43e00000,stride,(799U<<11)|479U,0x43e00000+stride*800));
  assert(!i9100_charge_bind(&bound,(mode<<2)|1,0x43e00000,stride|(4U<<13),(479U<<11)|799U,0x43e00000+stride*800));
 }
 for(unsigned bpp=16;bpp<=32;bpp+=16){unsigned bytes=480*800*bpp/8;
  uint8_t*allocation=malloc(bytes+128);assert(allocation);memset(allocation,0xa5,bytes+128);
  struct i9100_charge_screen s={allocation+64,bytes,480*bpp/8,bpp};
  for(unsigned percent=0;percent<=100;percent+=25){assert(i9100_charge_draw(&s,1,percent,1,1,0,0,3));
   if(percent==75 && bpp==32){char name[512];snprintf(name,sizeof(name),"%s/frame.bin",argv[1]);FILE*f=fopen(name,"wb");assert(f&&fwrite(s.pixels,1,bytes,f)==bytes);fclose(f);}
   for(unsigned n=0;n<64;n++)assert(allocation[n]==0xa5 && allocation[64+bytes+n]==0xa5);
  }
  assert(i9100_charge_draw(&s,0,0,1,0,-3,0,0));assert(!i9100_charge_draw(&s,1,101,1,1,0,0,0));
  struct i9100_charge_screen bad=s;bad.bytes--;assert(!i9100_charge_draw(&bad,1,1,1,1,0,0,0));
  bad=s;bad.bpp=24;assert(!i9100_charge_draw(&bad,1,1,1,1,0,0,0));
  bad=s;bad.stride++;assert(!i9100_charge_draw(&bad,1,1,1,1,0,0,0));
  bad=s;bad.pixels=(uint8_t*)s.pixels+1;assert(!i9100_charge_draw(&bad,1,1,1,1,0,0,0));
  free(allocation);
 }
 puts("PASS production charger percent/unknown/protected state, RGB565/BGRX32 and short/alignment/format guards");
}
'''
(out/'check.c').write_text(code)
for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',
    '-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],[str(out/'check'),str(out)])):
    r=subprocess.run(cmd,text=True,capture_output=True);(out/f'command-{n}.log').write_text(r.stdout+r.stderr)
    if r.returncode:print(r.stderr[-3000:],file=sys.stderr);r.check_returncode()
    if r.stdout:print(r.stdout.strip(),flush=True)
raw=(out/'frame.bin').read_bytes();rows=bytearray()
for y in range(800):
    rows.append(0)
    for x in range(480):
        b,g,r,_=raw[(y*480+x)*4:(y*480+x+1)*4];rows+=bytes((r,g,b))
def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>2I5B',480,800,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(rows))+chunk(b'IEND',b'')
(out/'preview.png').write_bytes(png);(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,preview='preview.png'),indent=2)+'\n')
print('EVIDENCE',out,flush=True)
