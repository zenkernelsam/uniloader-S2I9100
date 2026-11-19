#!/usr/bin/env python3
"""Verify actual packed iOS6 artwork, no-clear updates and startup refusal.

Runs production C under ASan/UBSan. Writes previews and original evidence;
no phone, USB, MMIO, flash or charging current is accessed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def main():
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
                    sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
    repo=Path(__file__).resolve().parents[2]
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--art',type=Path,required=True)
    args=parser.parse_args()
    pack=args.art.resolve()
    if not pack.is_relative_to(repo.parent/'assets') or not pack.is_file():
        parser.error('Local assets pack required')
    out=repo/'out'/('charge-art-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir()
    source=r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "charge/i9100_power.h"
#include "i9100-charge-screen.h"
#include "i9100-charge-start.h"
static void save(const char *directory,const char *name, const void *p,unsigned size){
 char path[1024];assert(snprintf(path,sizeof(path),"%s/%s",directory,name)>0);
 FILE*f=fopen(path,"wb");assert(f&&fwrite(p,1,size,f)==size);fclose(f);
}
int main(int argc,char**argv){
 assert(argc==2);unsigned bytes=(unsigned)(i9100_charge_art_end-i9100_charge_art_start);
 uint16_t*decoded=malloc((I9ART_PIXELS+64)*2);assert(decoded);
 for(unsigned n=0;n<18;n++){
  for(unsigned i=0;i<64;i++)decoded[I9ART_PIXELS+i]=0xa5a5;
  assert(i9100_charge_art_decode(i9100_charge_art_start,bytes,n,decoded,I9ART_PIXELS));
  char name[64];snprintf(name,sizeof(name),"decoded-%02u.rgb565",n);save(argv[1],name,decoded,I9ART_PIXELS*2);
  for(unsigned i=0;i<64;i++)assert(decoded[I9ART_PIXELS+i]==0xa5a5);
 }
 assert(!i9100_charge_art_decode(i9100_charge_art_start,bytes,18,decoded,I9ART_PIXELS));
 assert(!i9100_charge_art_decode(i9100_charge_art_start,bytes-1,0,decoded,I9ART_PIXELS));
 assert(!i9100_charge_art_decode(i9100_charge_art_start,bytes,0,decoded,I9ART_PIXELS-1));
 uint8_t *bad=malloc(bytes);assert(bad);memcpy(bad,i9100_charge_art_start,bytes);bad[32]=0;
 assert(!i9100_charge_art_decode(bad,bytes,0,decoded,I9ART_PIXELS));
 unsigned offset=i9100_art_u32(i9100_charge_art_start+32),length=i9100_art_u32(i9100_charge_art_start+36);
 assert(!i9100_art_lz4(i9100_charge_art_start+offset,length-1,(uint8_t*)decoded,I9ART_PIXELS*2));
 uint8_t nooffset[]={0,0,0};assert(!i9100_art_lz4(nooffset,sizeof(nooffset),(uint8_t*)decoded,8));
 uint8_t longliteral[]={0xf0,255};assert(!i9100_art_lz4(longliteral,sizeof(longliteral),(uint8_t*)decoded,8));
 uint8_t *snapshot=malloc(1536000);assert(snapshot);
 for(unsigned bpp=16;bpp<=32;bpp+=16){
  unsigned capacity=480*800*bpp/8;uint8_t*buffer=malloc(capacity+128);assert(buffer);
  memset(buffer,0xa5,capacity+128);struct i9100_charge_screen s={buffer+64,capacity,480*bpp/8,bpp};
  i9100_charge_renderer_reset();assert(i9100_charge_draw(&s,1,0,1,1,0,0,0));
  assert(i9100_charge_render.art_ok && i9100_charge_render.art_frame==17);
  memcpy(snapshot,s.pixels,capacity);
  assert(i9100_charge_draw(&s,1,0,1,1,0,0,1));
  assert(!memcmp(snapshot,s.pixels,capacity) && !i9100_charge_render.last_stores);
  assert(i9100_charge_draw(&s,1,6,1,1,0,0,2));
  assert(i9100_charge_render.last_stores<4000); /* Percentage only, body unchanged. */
  assert(i9100_charge_draw(&s,1,50,1,1,0,0,3));
  assert(i9100_charge_render.art_frame==8 && i9100_charge_render.last_stores<70000);
  memcpy(snapshot,s.pixels,capacity);
  assert(i9100_charge_draw(&s,1,51,1,1,0,0,4));
  for(unsigned y=284;y<542;y++)assert(!memcmp(snapshot+y*s.stride,(uint8_t*)s.pixels+y*s.stride,s.stride));
  assert(i9100_charge_render.last_stores<4000); /* No glass erase in next percentage. */
  assert(i9100_charge_draw(&s,1,50,1,0,I9100_POWER_TEMPERATURE,0,5));
  assert(i9100_charge_render.last_stores<4000); /* Keep actual battery level while protected. */
  memcpy(snapshot,s.pixels,capacity);
  assert(i9100_charge_draw(&s,1,50,1,0,I9100_POWER_TEMPERATURE,0,6));
  assert(!memcmp(snapshot,s.pixels,capacity) && !i9100_charge_render.last_stores);
  assert(!i9100_charge_draw(&s,1,101,1,1,0,0,0));
  struct i9100_charge_screen short_buffer=s;short_buffer.bytes--;
  assert(!i9100_charge_draw(&short_buffer,1,25,1,1,0,0,0));
  for(unsigned n=0;n<64;n++)assert(buffer[n]==0xa5 && buffer[64+capacity+n]==0xa5);
  if(bpp==32){
   const unsigned levels[]={0,6,50,100};
   for(unsigned n=0;n<4;n++){assert(i9100_charge_draw(&s,1,levels[n],1,1,0,levels[n]==100,0));
    char name[64];snprintf(name,sizeof(name),"screen-%03u.bgra",levels[n]);save(argv[1],name,s.pixels,capacity);
   }
   assert(i9100_charge_draw(&s,0,0,1,0,I9100_POWER_IO,0,0));save(argv[1],"screen-unknown.bgra",s.pixels,capacity);
  }
  free(buffer);
 }
 struct i9100_charge_start gate={0};struct i9100_power_state battery={0};
 battery.valid=battery.present=battery.connected=1;battery.percent=0;battery.millivolts=3199;battery.temperature_deci_c=250;
 uint64_t ns=1000000000ULL;
 for(unsigned n=0;n<20;n++){i9100_charge_start_update(&gate,&battery,0,ns);ns+=1000000000ULL;assert(!gate.ready);}
 battery.percent=3;battery.millivolts=3600;
 for(unsigned n=0;n<10;n++){i9100_charge_start_update(&gate,&battery,0,ns);ns+=1000000000ULL;assert(!gate.ready);}
 i9100_charge_start_update(&gate,&battery,0,ns);assert(gate.ready);
 assert(i9100_charge_start_ready(&gate,ns) && !i9100_charge_start_ready(&gate,ns+3000000000ULL));
 assert(!i9100_charge_start_ready(&gate,ns-1));
 battery.millivolts=3599;ns+=1000000000ULL;i9100_charge_start_update(&gate,&battery,0,ns);assert(!gate.ready);
 battery.millivolts=4000;
 for(unsigned n=0;n<11;n++){ns+=1000000000ULL;i9100_charge_start_update(&gate,&battery,0,ns);}assert(gate.ready);
 ns+=1000000000ULL;i9100_charge_start_update(&gate,&battery,1,ns);assert(!gate.ready);
 gate.samples=11;gate.ready=1;ns+=4000000000ULL;i9100_charge_start_update(&gate,&battery,0,ns);assert(!gate.ready);
 battery.timeout=1;ns+=1000000000ULL;i9100_charge_start_update(&gate,&battery,0,ns);assert(!gate.ready);
 free(snapshot);free(bad);free(decoded);
 puts("PASS actual 18 iOS6 sprite blocks; malformed/bounded decode; RGB565/ARGB final-only updates; unchanged zero stores; low/stale/thermal startup refusal");
}
'''
    (out/'check.c').write_text(source)
    for index,command in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra',
        '-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all',
        '-DI9100_CHARGE_ART_BLOB="'+str(pack)+'"','-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],
        [str(out/'check'),str(out)])):
        result=subprocess.run(command,text=True,capture_output=True)
        (out/f'command-{index}.log').write_text(result.stdout+result.stderr)
        if result.returncode:
            print((result.stdout+result.stderr)[-4000:],file=sys.stderr)
            result.check_returncode()
        if result.stdout:print(result.stdout.strip(),flush=True)
    manifest=json.loads(pack.with_name('manifest.json').read_text())
    for frame in manifest['frames']:
        actual=hashlib.sha256((out/f"decoded-{frame['index']:02d}.rgb565").read_bytes()).hexdigest()
        if actual!=frame['raw_sha256']:raise ValueError('Production C decode differs from original packed sprite')
    spec=importlib.util.spec_from_file_location('png',Path(__file__).with_name('extract-charge-art.py'))
    png=importlib.util.module_from_spec(spec);spec.loader.exec_module(png)
    for path in out.glob('screen-*.bgra'):
        raw=path.read_bytes();rgb=bytearray()
        for i in range(0,len(raw),4):b,g,r,a=raw[i:i+4];rgb+=bytes((r,g,b))
        path.with_suffix('.png').write_bytes(png.png_rgb(480,800,bytes(rgb)))
    result=dict(result='PASS',hardware=False,art_sha256=hashlib.sha256(pack.read_bytes()).hexdigest(),
                source_sha256={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                 (repo/'board/samsung/i9100-charge-art.h',repo/'board/samsung/i9100-charge-screen.h',repo/'board/samsung/i9100-charge-start.h')},
                scope='Production C and original firmware assets; no display timing or cell recovery proven')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('EVIDENCE',out,flush=True)


if __name__=='__main__':main()
