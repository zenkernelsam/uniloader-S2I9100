#!/usr/bin/env python3
"""Execute production charge sense/ADC/format code without phone access."""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
        sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import hashlib,importlib.util,json,subprocess

repo=Path(__file__).resolve().parents[2]
out=repo/'out'/('charge-sense-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
source=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "i9100-charge-sense.h"
#include "i9100-charge-report.h"
struct Model {uint32_t con,mux,clock,adc,gpl[3];uint64_t ns;unsigned failure,samples,adc_writes,reads;};
static uint32_t read32(void*c,unsigned r,unsigned off){
 struct Model*m=c;
 if(r==2 && off==0xc950)return m->clock;
 if(r==3 && off==0)return m->con;
 if(r==3 && off==0x1c)return m->mux;
 if(r==3 && off==0xc)return m->adc;
 if(r==1 && off>=0x100 && off<=0x108 && !(off&3))return m->failure==8+(off-0x100)/4?0xffffffffU:m->gpl[(off-0x100)/4];
 assert(0);return 0;
}
static void write32(void*c,unsigned r,unsigned off,uint32_t value){
 struct Model*m=c;m->adc_writes++;m->ns+=10000;
 assert((r==2 && off==0xc950)||(r==3 && (off==0 || off==0x18 || off==0x1c)));
 if(r==2)m->clock=value;
 else if(off==0x1c)m->mux=value;
 else if(off==0){
  m->con=value;
  if(value&1U){
   assert(m->mux==1 && (value&(1U<<16)) && (value&(1U<<14)));
   const unsigned data[5]={900,999,1000,1001,1100};assert(m->samples<5);
   m->adc=data[m->samples++];
   if(m->failure!=1)m->con=(value&~1U)|(1U<<15);
  }
 }
}
static void delay(void*c,unsigned us){((struct Model*)c)->ns+=(uint64_t)us*1000;}
static int fuel(void*c,unsigned reg,uint16_t*v){
 struct Model*m=c;assert(reg==9 || reg==0xff);m->reads++;m->ns+=100000;
 if(m->failure==(reg==9?2:3))return 0;*v=reg==9?51200:75*256;return 1;
}
static int pmic(void*c,unsigned reg,uint8_t*v){
 struct Model*m=c;assert(reg==0x10 || reg==0x51);m->reads++;m->ns+=100000;
 if(m->failure==(reg==0x10?4:5))return 0;*v=reg==0x10?0x32:0;return 1;
}
static int muic(void*c,unsigned reg,uint8_t*v){
 struct Model*m=c;assert(reg==0x0d || reg==5);m->reads++;m->ns+=100000;
 if(m->failure==(reg==0x0d?6:7))return 0;*v=reg==0x0d?4:1;return 1;
}
static uint64_t now(void*c){return ((struct Model*)c)->ns;}
int main(void){
 alarm(10);
 for(unsigned fail=0;fail<=10;fail++)for(unsigned clock_on=0;clock_on<2;clock_on++){
  struct Model m={0};m.ns=10000000000ULL;m.failure=fail;m.con=4;m.mux=7;
  m.clock=0xa501U|(clock_on?1U<<15:0);m.gpl[0]=0x100;m.gpl[1]=4;m.gpl[2]=0xaab;
  struct i9100_power_hw hw={0};hw.cookie=&m;hw.read32=read32;hw.write32=write32;hw.delay_us=delay;
  struct i9100_power_state b={0};b.ready=b.valid=b.present=b.connected=b.enabled=b.charging=1;
  b.revision=14;b.use_sub=1;b.percent=75;b.millivolts=4000;b.charge_start=12345;
  b.stop_uncertain=fail==1;b.io.cookie=&m;b.io.now_ns=now;
  b.io.fuel_read=fuel;b.io.pmic_read=pmic;b.io.muic_read=muic;
  struct i9100_power_state original=b;struct i9100_charge_sense sample;
  assert(i9100_charge_sense_capture(&sample,&b,&hw,1));
  assert(!memcmp(&original,&b,sizeof(b)) && m.reads==6);
  assert(m.con==4 && m.mux==7 && m.clock==(0xa501U|(clock_on?1U<<15:0)));
  assert(sample.mask==(fail?0x3ffU&~(1U<<(fail-1)):0x3ffU));
  assert(sample.adc==(fail==1?0xffffffffU:1000U));
  assert(m.samples==(fail==1?1U:5U));
  assert(sample.started_ns==10000000000ULL && sample.finished_ns>=sample.started_ns);
  unsigned timing[8],registers[8];i9100_charge_sense_words(&sample,timing,registers);
  assert(timing[0]==1 && timing[1]==10000 && !timing[2] && timing[3]<500000 && timing[7]==(fail==1));
  assert(registers[4]==(0x010e0000U|((fail==7?0xffU:1U)<<8)|(fail==6?0xffU:4U)) && registers[0]==timing[0]);
  if(!fail && !clock_on){
   struct i9100_charge_report report={0};report.sequence=1;report.milliseconds=sample.finished_ns/1000000;
   report.valid=report.charging=1;report.percent=75;report.millivolts=4000;report.temperature_deci_c=250;
   char line[256];assert(i9100_charge_format(line,sizeof(line),&report));printf("%s",line);
   printf("I9CS1");for(unsigned n=0;n<8;n++)printf(" %08x",timing[n]);puts("");
   printf("I9RG1");for(unsigned n=0;n<8;n++)printf(" %08x",registers[n]);puts("");
  }
 }
 struct i9100_charge_sense none;assert(!i9100_charge_sense_capture(&none,0,0,1));assert(none.adc==0xffffffffU);
 puts("PASS real sense/ADC1: register reads only, ten faults, five-conversion trim, clock/mux/control restored, policy/deadline unchanged");
}
'''
(out/'check.c').write_text(source,encoding='utf8')
includes=['-I'+str(repo/'board/samsung'),'-I'+str(repo/'board/samsung/charge')]
command=['clang','-std=c99','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
    '-fsanitize=address,undefined','-fno-sanitize-recover=all',*includes,str(out/'check.c'),
    str(repo/'board/samsung/charge/i9100_power_bus.c'),'-o',str(out/'check')]
for n,args in enumerate((command,[str(out/'check')])):
    result=subprocess.run(args,text=True,capture_output=True)
    (out/f'command-{n}.log').write_text(result.stdout+result.stderr,encoding='utf8')
    if result.returncode:print((result.stdout+result.stderr)[-2500:],file=sys.stderr);result.check_returncode()
raw=(out/'command-1.log').read_bytes()
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
decoder=load('charge_sense_test_decoder','charge-sense.py')
summary=load('charge_sense_test_summary','summarize-charge-loader.py')
sample=summary.decode_status(raw,[])[0]
observed=decoder.decode(raw[sample['end_offset']:],sample)
assert observed['charge_current_adc']==1000 and observed['observed_millivolts']==4000 and observed['observed_soc']==75
assert observed['sub_enable_output'] is True and observed['main_charger_enable_bits']==0
assert not observed['net_charging_verified']
assert observed['readback_consistent']
for mutation in ('sequence','stale','missing','partial','duplicate','mask','adc','revision','duration','newline'):
    changed=raw
    if mutation=='sequence':changed=changed.replace(b'I9RG1 00000001',b'I9RG1 00000002')
    if mutation=='stale':changed=changed.replace(b'I9CS1 00000001 00002710',b'I9CS1 00000001 00000001')
    if mutation=='missing':changed=changed.replace(b'I9CS1',b'X9CS1')
    if mutation=='partial':changed=changed.replace(b'00000100 00000004 00000aab',b'00000100')
    if mutation=='duplicate':changed+=next(line+b'\n' for line in raw.splitlines() if line.startswith(b'I9CS1'))
    if mutation=='mask':changed=changed.replace(b'000003ff 000003e8',b'00000400 000003e8')
    if mutation=='adc':changed=changed.replace(b'000003ff 000003e8',b'000003ff 00001000')
    if mutation=='revision':changed=changed.replace(b'010e0104',b'01ff0104')
    if mutation=='duration':
        line=next(line for line in raw.splitlines() if line.startswith(b'I9CS1'));words=line.split();words[4]=b'ffffffff'
        changed=changed.replace(line,b' '.join(words))
    if mutation=='newline':changed=raw.split(b'\nPASS')[0]
    try:decoder.decode(changed[sample['end_offset']:],sample)
    except ValueError:pass
    else:raise AssertionError('Bad evidence accepted: '+mutation)
for mutation,before,after in (
    ('voltage',b'0000c800',b'0000b000'),
    ('soc',b'00004b00',b'00000f00'),
    ('both-enabled',b'00000032 010e0104',b'0000c032 010e0104'),
    ('pin-low',b'00000100 00000004',b'00000100 00000000'),
    ('pin-mux',b'00000100 00000004',b'00000200 00000004')):
    result=decoder.decode(raw.replace(before,after)[sample['end_offset']:],sample)
    assert not result['readback_consistent'] and result['readback_issues'], mutation
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,observed=observed,
    source_sha256={str(path.relative_to(repo)):hashlib.sha256(path.read_bytes()).hexdigest() for path in (
        repo/'board/samsung/i9100-charge-sense.h',repo/'board/samsung/charge/i9100_power_bus.c',
        repo/'board/samsung/charge/i9100_power.h',Path(__file__).with_name('charge-sense.py'))},
    limit='Actual ADC/register observer, format and host decoder with register callbacks; no physical current/calibration proven'),indent=2)+'\n',encoding='utf8')
print('PASS production observer and native wire decoder, fault/sentinel/identity/time rejection; no mA claim')
print('EVIDENCE',out)
