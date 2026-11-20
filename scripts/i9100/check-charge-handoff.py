#!/usr/bin/env python3
"""Check the actual DT slot parser and host handoff reader without a phone.

Runs production C under ASan/UBSan, compares its checksum with the host,
and verifies single-reader refusal against malformed/duplicate/partial trees.
"""
import os
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
        sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from datetime import datetime
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import subprocess

repo=Path(__file__).resolve().parents[2]
here=Path(__file__).resolve().parent
out=repo/'out'/('charge-handoff-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
out.mkdir()
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,here/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
dt=module('charge_dt','prepare-payloads.py')
m=module('charge_host','charge-handoff.py')
chosen=[('name',b'chosen\0'),(m.PROPERTY,bytes(128))]
fixtures={
 'valid':dt.device_tree(),
 'duplicate':dt.node([('name',b'device-tree\0')],[dt.node(chosen+[(m.PROPERTY,bytes(128))])]),
 'wrong-node':dt.node([('name',b'device-tree\0')],[dt.node([('name',b'chosen\0')]),dt.node([('name',b'other\0'),(m.PROPERTY,bytes(128))])]),
 'duplicate-chosen':dt.node([('name',b'device-tree\0')],[dt.node(chosen),dt.node(chosen)]),
 'duplicate-property':dt.node([('name',b'device-tree\0')],[dt.node(chosen+[('extra',b'x'),('extra',b'x')])]),
 'nested-fake':dt.node([('name',b'device-tree\0')],[dt.node([('name',b'chosen\0'),('payload',dt.property_bytes(m.PROPERTY,bytes(128)))])]),
 'wrong-size':dt.node([('name',b'device-tree\0')],[dt.node([('name',b'chosen\0'),(m.PROPERTY,bytes(124))])]),
 'truncated':dt.device_tree()[:-4],
 'extra-tail':dt.device_tree()+b'\0'*4,
 'bad-root':dt.node([('name',b'other\0')],[dt.node(chosen)]),
}
for name,raw in fixtures.items():(out/(name+'.bin')).write_bytes(raw)
source=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "main/i9100-charge-handoff.h"
static unsigned load(const char *directory,const char *name,uint8_t *out){
 char path[1024];snprintf(path,sizeof(path),"%s/%s.bin",directory,name);
 FILE*f=fopen(path,"rb");assert(f);unsigned bytes=fread(out,1,32768,f);fclose(f);return bytes;
}
int main(int argc,char **argv){
 assert(argc==2);alarm(10);uint8_t tree[32768] __attribute__((aligned(4))),before[32768];
 unsigned bytes=load(argv[1],"valid",tree);memcpy(before,tree,bytes);
 uint8_t *slot=i9100_charge_handoff_slot(tree,bytes);assert(slot && !memcmp(before,tree,bytes));
 assert(!i9100_charge_handoff_slot(0,bytes) && !i9100_charge_handoff_slot(tree+1,bytes));
 struct I9100ChargeHandoff record={0};assert(sizeof(record)==128);
 record.magic=I9100_CHARGE_HANDOFF_MAGIC;record.version=1;record.bytes=128;record.flags=7;
 record.revision=14;record.sub_charger=1;record.polls=15;record.valid=record.present=record.connected=1;
 record.percent=50;record.millivolts=4000;record.temperature_deci_c=250;
 record.enabled_before=record.charging_before=1;record.sampled_low=0xfffffff0U;record.sampled_high=1;
 record.stopped_low=100;record.stopped_high=2;record.published_low=200;record.published_high=2;
 record.elapsed_seconds=14;record.qualified_samples=11;record.recovery_seconds=13;
 record.checksum=i9100_charge_handoff_checksum(&record);memcpy(slot,&record,128);
 assert(i9100_charge_handoff_slot(tree,bytes)==slot);
 char path[1024];snprintf(path,sizeof(path),"%s/record.bin",argv[1]);FILE*f=fopen(path,"wb");assert(f);
 assert(fwrite(&record,1,sizeof(record),f)==sizeof(record));fclose(f);
 const char *bad[]={"duplicate","wrong-node","duplicate-chosen","duplicate-property","nested-fake","wrong-size","truncated","extra-tail","bad-root"};
 for(unsigned n=0;n<sizeof(bad)/sizeof(bad[0]);n++){
  unsigned length=load(argv[1],bad[n],tree);memcpy(before,tree,length);
  assert(!i9100_charge_handoff_slot(tree,length));assert(!memcmp(before,tree,length));
 }
 puts("PASS production charger DT parser: unique actual /chosen slot, bounded structure, no write on duplicate/nested/truncated/misaligned trees and fixed checksum ABI");
}
'''
(out/'check.c').write_text(source,encoding='utf-8')
for n,command in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(repo/'include'),str(out/'check.c'),'-o',str(out/'check')],
    [str(out/'check'),str(out)])):
    result=subprocess.run(command,capture_output=True,text=True)
    (out/f'command-{n}.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode:
        print((result.stdout+result.stderr)[-3000:],file=sys.stderr);result.check_returncode()
    if result.stdout:print(result.stdout.strip(),flush=True)
for name,raw in fixtures.items():
    try:parsed=m.tree_properties(raw)
    except ValueError:assert name!='valid'
    else:assert name=='valid'
record=(out/'record.bin').read_bytes();decoded=m.decode(record)
assert decoded['valid'] and decoded['stopped_ticks']>decoded['sampled_ticks'] and decoded['recovery_seconds']==13
assert not m.decode(bytes(128))['published']
observed=dict(decoded,root_stable=True)
first=dict(polls=1,measurements_valid=True,revision=14,sub_charger=1,enabled=1,connected=1,charging=1,
    time_ns=decoded['stopped_ticks']*1000//24+2000000000,reason=0,sequence=1)
interval=m.first_kernel_sample(observed,[first])
assert interval['usable'] and interval['observed_interval_ns']==2000000000 and not interval['net_charging_verified']
assert not m.first_kernel_sample(observed,[dict(first,polls=30)])['usable']
assert not m.first_kernel_sample(observed,[dict(first,revision=7)])['usable']
assert not m.first_kernel_sample(observed,[dict(first,time_ns=1)])['usable']
assert not m.first_kernel_sample(dict(observed,root_stable=False),[first])['usable']
assert not m.first_kernel_sample(observed,[first,first])['usable']
bad=bytearray(record);bad[44]^=1
try:m.decode(bad)
except ValueError:pass
else:raise AssertionError('Bad checksum accepted')
for field,value in ((0,0),(19,1),(24,1),(28,10),(29,9)):
    bad=bytearray(record);struct.pack_into('<I',bad,field*4,value);struct.pack_into('<I',bad,124,m.checksum(bad))
    try:m.decode(bad)
    except ValueError:pass
    else:raise AssertionError('Invalid handoff accepted '+str(field))
reference=fixtures['valid'];offset=m.tree_properties(reference)['/chosen']['offsets'][m.PROPERTY]
epoch_raw=bytearray(128);struct.pack_into('<4I',epoch_raw,0,0x45433949,2,128,3)
struct.pack_into('<13I',epoch_raw,16,14,1,1,1,1,0,0,0,0,0,1,1,50)
struct.pack_into('<4I',epoch_raw,68,4000,250,0,0)
struct.pack_into('<10I',epoch_raw,84,1000000000,0,4000000000,0,1000000000,0,900000000,0,1,7)
struct.pack_into('<I',epoch_raw,124,m.checksum(epoch_raw))
epoch_wrapper=struct.pack('<8I',0x57453949,1,160,1,1,1,900000020,0)+epoch_raw
assert m.decode_epoch_return(epoch_wrapper)['valid']
class Symbols:
    tag='0123456789abcdef';values={'_DTRootNode':0x80002000}
    path=out/'package/mach_kernel'
    def __getitem__(self,name):return self.values[name]
Symbols.path.parent.mkdir();(Symbols.path.parent/'dtb').write_bytes(reference)
(Symbols.path.parent/'manifest.json').write_text(json.dumps(dict(control_tag=Symbols.tag,
    standalone_charge_handoff=True,standalone_charge_handoff_tree=dict(bytes=len(reference),sha256=hashlib.sha256(reference).hexdigest()),
    artifacts={'mach_kernel':dict(sha256=Symbols.tag+'0'*48)}))+'\n')
class Kernel:
    def __init__(self,raw,changed=False):self.raw=raw;self.changed=changed;self.root_reads=0;self.calls=[]
    def u32(self,address):
        assert address==Symbols.values['_DTRootNode'];self.root_reads+=1;self.calls.append(('root',address))
        return 0x80010000+(4 if self.changed and self.root_reads>1 else 0)
    def read(self,address,length):
        assert (address,length)==(0x80010000,len(reference));self.calls.append(('tree',address,length));return self.raw
for name,raw,changed in (('live-valid',record,False),('live-partial',bytes(bad),False),('live-empty',bytes(128),False),('live-root-changed',record,True)):
    target=out/name;target.mkdir();tree=bytearray(reference);tree[offset:offset+128]=raw;kernel=Kernel(bytes(tree),changed)
    result=m.capture(kernel,Symbols(),target)
    assert result['valid']==(name=='live-valid')
    assert len(kernel.calls)==3 and (target/'charge-handoff-tree.bin').read_bytes()==tree
target=out/'live-shutdown-epoch';target.mkdir();tree=bytearray(reference);tree[offset:offset+128]=record
epoch_offset=m.tree_properties(reference)['/chosen']['offsets']['i9100-charge-epoch']
tree[epoch_offset:epoch_offset+160]=epoch_wrapper
result=m.capture(Kernel(bytes(tree)),Symbols(),target)
assert result['valid'] and result['shutdown_charge_epoch']['valid'] and (target/'charge-epoch-return.bin').read_bytes()==epoch_wrapper
changed=bytearray(reference);changed[40]^=1
(Symbols.path.parent/'dtb').write_bytes(changed)
target=out/'changed-local-tree';target.mkdir();kernel=Kernel(reference)
try:m.capture(kernel,Symbols(),target)
except ValueError as error:assert 'artifact changed' in str(error) and not kernel.calls
else:raise AssertionError('Changed local tree permitted a device read')
(Symbols.path.parent/'dtb').write_bytes(reference)
legacy=out/'legacy';legacy.mkdir()
class Legacy:
    values={}
assert m.capture(Kernel(reference),Legacy(),legacy) is None
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,
    c_header_sha256=hashlib.sha256((repo/'include/main/i9100-charge-handoff.h').read_bytes()).hexdigest(),
    host_sha256=hashlib.sha256((here/'charge-handoff.py').read_bytes()).hexdigest(),
    actual_record_sha256=hashlib.sha256(record).hexdigest(),decoded=decoded,
    limit='Actual C parser/checksum and actual host reader with modeled memory; no phone or XNU takeover observed'),indent=2)+'\n',encoding='utf-8')
print('PASS actual host handoff/checksum and one-read tree/reference/partial/root-change refusals',flush=True)
print('EVIDENCE',out,flush=True)
