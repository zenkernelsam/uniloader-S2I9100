#!/usr/bin/env python3
"""Exercise optional setup diagnostics against a real retained charger fixture.

No device access. Keep the evidence directory; never delete test artifacts.
"""
import argparse, importlib.util, json, struct
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('charge_capture',here/'inspect-charge-health.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
repo=here.parents[1];out=a.output.resolve();fixture=a.fixture.resolve()
assert fixture.is_relative_to(repo/'out') and out.is_relative_to(repo/'out') and not out.exists()
raw=fixture.read_bytes();version,count,stride,capacity=struct.unpack_from('<4I',raw)
assert version==2 and stride==40 and capacity==16
out.mkdir(parents=True)
for state in range(5):
    words=[1,state,14,1000000000 if state in (1,4) else 0,0,0,int(state in (3,4)),0,3000000000,0,0,1]
    decoded=m.decode_charge_adopt(struct.pack('<12I',*words))
    assert decoded['consistent'] and decoded['state']==state and decoded['deadline_seconds']==18000
    if state==1:assert decoded['elapsed_ns']==2000000000
assert not m.decode_charge_adopt(struct.pack('<12I',1,0,0,0,0,0,0,0,0,0,0,0))['consistent']
for slot,value in ((0,2),(1,5),(2,16),(6,0),(10,1),(11,2)):
    words=[1,4,14,1000000000,0,0,1,0,3000000000,0,0,1];words[slot]=value
    try:m.decode_charge_adopt(struct.pack('<12I',*words))
    except ValueError:pass
    else:raise AssertionError('Invalid charge adoption accepted: '+str(slot))
class Symbols:
    values={'_i9100_charge_diag':0x1000,'_i9100_setup_dev_finish_diag':0x3000,'_i9100_charge_adopt_diag':0x4000,'_i9100_cdc_liveness_diag':0x5000}
    def __getitem__(self,name):return self.values[name]
class Kernel:
    def __init__(self,setup_version):self.calls=[];self.setup_version=setup_version;self.header_reads=0
    def u32(self,address):
        assert address==0x4000;self.calls.append((address,4));return 1
    def read(self,address,size):
        self.calls.append((address,size))
        if address==0x1000:
            if size==16:
                self.header_reads+=1
                return struct.pack('<4I',version,count+(self.header_reads>1),stride,capacity)
            assert size==len(raw);return raw
        if address==0x3000 and size==48:
            return struct.pack('<12I',self.setup_version,2,88,0x19000,88,0,0,0,0,0,0x1b76c,0x1af84)
        if address==0x3030 and size==16 and self.setup_version==2:
            return struct.pack('<4I',0x98000,132,0x79068,0x78430)
        if address==0x4000 and size==48:
            return struct.pack('<12I',1,1,14,1000000000,0,0,0,0,3000000000,0,0,1)
        if address==0x5000 and size in (140,8):
            words=[1,2,27,5,56,8,3000000000,0]+[0]*27
            words[8]=2;words[10]=60000;words[16]=words[17]=words[29]=words[34]=1
            data=struct.pack('<35I',*words);return data if size==140 else data[:8]
        raise AssertionError((address,size))
for setup_version in (1,2):
    target=out/f'setup-v{setup_version}';target.mkdir();kernel=Kernel(setup_version)
    result=m.capture(kernel,Symbols(),target)
    assert kernel.calls[-1]==(0x1000,16),'Optional diagnostics replaced the original charger address'
    assert result['version']==version and result['producer_count_after']==count+1
    assert result['producer_advanced_after_snapshot'] and not result['net_charging_verified']
    assert ((0x3030,16) in kernel.calls)==(setup_version==2)
    assert result['setup_development_finish']['version']==setup_version
    assert result['charger_deadline_adoption']['consistent'] and result['charger_deadline_adoption']['state']==1
    assert result['charger_deadline_adoption']['elapsed_ns']==2000000000 and (target/'charge-adopt.bin').is_file()
    assert result['cdc_liveness']['consistent'] and result['cdc_liveness']['emitted']==5 and result['cdc_liveness']['suppressed']==56
    assert len(result['cdc_liveness']['stats'])==27 and (target/'cdc-liveness.bin').is_file()
    if setup_version==2:assert result['setup_development_finish']['code_bytes']==132
words=[2,1,14,1,0,0,0,0,3000000000,0,0,1000000000,0,0,0,1]
decoded=m.decode_charge_adopt(struct.pack('<16I',*words))
assert decoded['consistent'] and decoded['elapsed_base_ns']==1000000000 and decoded['elapsed_ns']==3999999999
class SymbolsV2(Symbols):pass
class KernelV2(Kernel):
    def u32(self,address):assert address==0x4000;return 2
    def read(self,address,size):
        if address==0x4000 and size==64:self.calls.append((address,size));return struct.pack('<16I',*words)
        return super().read(address,size)
target=out/'adoption-v2';target.mkdir();kernel=KernelV2(1)
actual=m.capture(kernel,SymbolsV2(),target)
assert actual['charger_deadline_adoption']['elapsed_base_ns']==1000000000
assert kernel.calls[-1]==(0x1000,16)
cdc=(out/'setup-v1/cdc-liveness.bin').read_bytes()
assert not m.decode_cdc_liveness(cdc,struct.pack('<2I',1,4))['consistent']
for slot,value in ((0,2),(2,26),(5,0x8000)):
    malformed=bytearray(cdc);struct.pack_into('<I',malformed,slot*4,value)
    try:m.decode_cdc_liveness(malformed)
    except ValueError:pass
    else:raise AssertionError('Unknown CDC diagnostic accepted: '+str(slot))
raw3=bytearray(raw);struct.pack_into('<I',raw3,0,3)
source=m.decode(raw);sequence=source['samples'][-1]['sequence'];slot=(sequence-1)&15
struct.pack_into('<I',raw3,16+slot*160+39*4,1)
decoded=m.decode(raw3)
assert decoded['version']==3 and decoded['samples'][-1]['stop_uncertain']==1
assert decoded['samples'][-1]['stop_confirmation_available']
assert not source['samples'][-1]['stop_confirmation_available'] and 'stop_uncertain' not in source['samples'][-1]
bad3=bytearray(raw3);struct.pack_into('<I',bad3,16+slot*160+39*4,2)
try:m.decode(bad3)
except ValueError:pass
else:raise AssertionError('Bad v3 stop-confirmation state accepted')
class SymbolsStop(Symbols):
    values=dict(Symbols.values,_i9100_power_stop_uncertain=0x6000,_i9100_power_valid=0x6010)
class KernelStop(Kernel):
    def u32(self,address):
        if address==0x6000:self.calls.append((address,4));return 1
        if address==0x6010:self.calls.append((address,4));return 1
        return super().u32(address)
    def read(self,address,size):
        if address==0x1000:
            self.calls.append((address,size))
            if size==16:
                self.header_reads+=1;return struct.pack('<4I',3,count+(self.header_reads>1),40,16)
            assert size==len(raw3);return bytes(raw3)
        return super().read(address,size)
target=out/'stop-confirmation-v3';target.mkdir();kernel=KernelStop(1)
actual=m.capture(kernel,SymbolsStop(),target)
assert actual['version']==3 and actual['stop_confirmation']['uncertain'] is True
assert actual['stop_confirmation']['measurement_valid'] is True
assert actual['samples'][-1]['stop_uncertain']==1 and kernel.calls[-1]==(0x1000,16)
class SymbolsLow(SymbolsStop):
    values=dict(SymbolsStop.values,_i9100_low_battery_retreat_diag=0x7000)
class KernelLow(KernelStop):
    def read(self,address,size):
        if address==0x7000:
            self.calls.append((address,size))
            first,last=1000000000,5000000000
            values=[1,2,1,2,5,1,3,3400,first&0xffffffff,first>>32,last&0xffffffff,last>>32,
                last&0xffffffff,last>>32,3,3400,5,4]
            data=struct.pack('<18I',*values)
            assert size in (72,8);return data if size==72 else data[:8]
        return super().read(address,size)
target=out/'low-battery-retreat';target.mkdir();kernel=KernelLow(1)
actual=m.capture(kernel,SymbolsLow(),target)
assert actual['low_battery_retreat']['consistent'] and actual['low_battery_retreat']['admitted']
assert (target/'low-battery-retreat.bin').is_file() and kernel.calls[-1]==(0x1000,16)
class SymbolsPC(SymbolsLow):
    values=dict(SymbolsLow.values,_i9100_irq_pc_sample=0x8000)
class KernelPC(KernelLow):
    def read(self,address,size):
        if address==0x8000:
            self.calls.append((address,size));assert size==4*(7+64*4)
            words=[2,2,0,0,0,37,1]+[0]*(64*4)
            return struct.pack('<'+str(len(words))+'I',*words)
        return super().read(address,size)
target=out/'v3-with-pc-histogram';target.mkdir();kernel=KernelPC(1)
actual=m.capture(kernel,SymbolsPC(),target)
assert actual['version']==3 and actual['irq_pc_sample']['version']==2
assert actual['producer_count_after']==count+1 and kernel.calls[-1]==(0x1000,16)
class SymbolsRTC(SymbolsPC):
    values=dict(SymbolsPC.values,_i9100_rtc_read_diag=0x9000)
class KernelRTC(KernelPC):
    def __init__(self,unstable=False):super().__init__(1);self.unstable=unstable
    def read(self,address,size):
        if address==0x9000:
            self.calls.append((address,size));assert size in (8,48)
            words=[1,2,15,0x303,0x02130129,0x202611,0x02130129,0x202611,1,1234,0,0]
            if size==8 and self.unstable:words[1]=4
            return struct.pack('<12I',*words)[:size]
        return super().read(address,size)
for unstable in (False,True):
    target=out/('rtc-moving' if unstable else 'rtc-stable');target.mkdir();kernel=KernelRTC(unstable)
    result=m.capture(kernel,SymbolsRTC(),target)
    assert result['rtc_read']['consistent']==(not unstable)
    assert result['rtc_read']['raw_format']=='BCD24' and result['rtc_read']['seconds']==1234
    assert (target/'rtc-read.bin').is_file() and (target/'rtc-read-after.bin').is_file()
(out/'result.json').write_text(json.dumps(dict(result='PASS',cases=2,fixture=str(fixture),
    evidence='Real charger snapshot, separate optional addresses, v1/v2 decoding, inherited deadline publication and later producer advancement'),indent=2)+'\n')
print('PASS real charger fixture; v1/v2 setup address isolation; final charger header and producer advancement')
