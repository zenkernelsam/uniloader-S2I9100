#!/usr/bin/env python3
"""Execute original H4 reset to its actual POSIX write boundary, offline only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'assets/py-native-hid'))
spec=importlib.util.spec_from_file_location('original_bt_uart',Path(__file__).with_name('verify-ios6-btserver.py'))
original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)


class Reset(original.Native):
    def __init__(self,image,failure=False):
        super().__init__(image)
        self.failure=failure;self.writes=[]
        state=original.HEAP+0x3000
        self.uc.mem_write(0x15ea70,struct.pack('<I',state))
        self.uc.mem_write(0x15b964,struct.pack('<II',0x15b9e8,0x15bb8c))
        self.uc.mem_write(0x15bbbc,struct.pack('<IH',original.HEAP+0x4000,0))
        self.uc.mem_write(0x15bbc8,struct.pack('<H',2032))
        self.uc.mem_write(0x15dd70,struct.pack('<I',11))

    def code(self,uc,address,size,user):
        if address in (0xe7394,0xe30d4):
            r=[uc.reg_read(reg) for reg in original.REGS]
            self.calls.append(dict(name='reset timer/diagnostic facade',address=hex(address),args=r))
            self.executed.add(address);self.returned();return
        if self.image.stubs.get(address)=='_write':
            r=[uc.reg_read(reg) for reg in original.REGS]
            assert r[0]==11 and r[2]==4
            packet=bytes(uc.mem_read(r[1],r[2]))
            assert packet==bytes.fromhex('01030c00')
            self.writes.append(packet.hex());self.executed.add(address)
            self.returned(-1 if self.failure else r[2]);return
        super().code(uc,address,size,user)


class ResetReply(Reset):
    def __init__(self,image):
        super().__init__(image);self.completions=0;self.diagnostics=[]

    def code(self,uc,address,size,user):
        r=[uc.reg_read(reg) for reg in original.REGS]
        if address==0xe3e58:
            self.completions+=1;self.executed.add(address);self.returned();return
        if address==0xe30d4:
            self.diagnostics.append(r);self.executed.add(address);self.returned();return
        if self.image.stubs.get(address)=='_memmove':
            assert r[2]<=2032;uc.mem_write(r[0],bytes(uc.mem_read(r[1],r[2])));self.executed.add(address);self.returned(r[0]);return
        if address==0xe3504:
            uc.mem_write(r[0],struct.pack('<IhH',0,0,0));self.executed.add(address);self.returned();return
        if address==0x1256ec:
            self.timer_ms=r[1]*100;self.executed.add(address);self.returned();return
        super().code(uc,address,size,user)

    def feed(self,packet):
        self.uc.mem_write(original.HEAP+0x6000,packet)
        return self.call(0xe7080,original.HEAP+0x6000,len(packet))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--handoff',type=Path,help='Run original decoder on emitted actual C/native-worker model bytes')
    a=p.parse_args()
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'uniloader-S2I9100/out') or out.exists():p.error('Fresh loader/out only')
    image=original.CATALOG.MachO(original.IMAGE)
    assert image.uuid==original.UUID and hashlib.sha256(image.raw).hexdigest()==original.IMAGE_SHA
    result={}
    for label,failure in [('actual-write',False),('write-error',True)]:
        n=Reset(image,failure);returned=n.call(0xe7464)
        assert n.writes==['01030c00']
        assert all(address in n.executed for address in (0xe7464,0xdaf7c,0xe6ed8,0xdaed0,0xdf48c,0x14f918))
        result[label]=dict(return_value=returned,packets=n.writes,calls=n.calls,
                           path=['e7464','daf7c','e6ed8','daed0','df48c','14f918'])
    timer=Reset(image)
    timer.uc.mem_write(original.HEAP+0x3000+0x7fc,struct.pack('<II',4,1))
    returned=timer.call(0xe73d4)
    assert timer.writes==['01030c00'] and 0xe7464 in timer.executed
    result['native-recovery-timer']=dict(return_value=returned,packets=timer.writes,calls=timer.calls,
        precondition='Original transport state4/error flag1 with valid modeled POSIX socket; not asserted to be the first command of a running daemon')
    native_reply={}
    for label,packet in [('success',bytes.fromhex('040e0401030c00')),('rejected',bytes.fromhex('040e0401030c01'))]:
        n=ResetReply(image);n.call(0xe7464);state=original.HEAP+0x3000;n.feed(packet)
        if label=='success':assert n.completions==1 and n.u32(state+0x800)==0 and n.u32(state+0x7fc)==1
        else:assert not n.completions and n.u32(state+0x800)==1 and n.u32(state+0x7fc)==4
        native_reply[label]=dict(packet_hex=packet.hex(),completed=n.completions,rx_state=n.u32(state+0x7fc),error=n.u32(state+0x800),timer_ms=getattr(n,'timer_ms',None))
    for split in range(1,7):
        n=ResetReply(image);n.call(0xe7464);packet=bytes.fromhex('040e0401030c00');n.feed(packet[:split]);n.feed(packet[split:])
        assert n.completions==1 and not n.u32(original.HEAP+0x3000+0x800)
    timercheck=ResetReply(image);token=original.HEAP+0x8000;timercheck.call(0x125770,token,20)
    assert struct.unpack('<H',timercheck.uc.mem_read(token+2,2))[0]==20
    native_reply['reset_deadline']=dict(units=20,unit_ms=100,deadline_ms=2000,
        scope='Original reset function selects20 and original timer arithmetic uses100ms units; time and timer provider remain modeled')
    handoff_proof=None
    if a.handoff:
        handoff=a.handoff.resolve()
        if not handoff.is_relative_to(ROOT/'xnu-S2I9100/out'):p.error('Handoff evidence must stay in XNU out')
        manifest=json.loads((handoff/'manifest.json').read_text());emitted=handoff/'native-handoff.json';raw=emitted.read_bytes()
        if manifest.get('result')!='PASS' or hashlib.sha256(raw).hexdigest()!=manifest.get('native_handoff_sha256'):
            raise RuntimeError('Emitted H4/native worker proof is incomplete or changed')
        data=json.loads(raw)
        if data.get('result')!='PASS' or data.get('model_fixture') is not True or data.get('hardware_tested') is not False:
            raise RuntimeError('Handoff proof lost its model attribution')
        packet=bytes.fromhex(data['reply_hex'])
        if data['request_hex']!='01030c00' or not 0<data['elapsed_ns']<1500000000:
            raise RuntimeError('Actual handoff exceeds the bounded original-reset response window')
        n=ResetReply(image);n.call(0xe7464);n.feed(packet)
        assert n.completions==1 and n.u32(original.HEAP+0x3000+0x800)==0
        handoff_proof=dict(path=str(handoff.relative_to(ROOT)),manifest_sha256=hashlib.sha256((handoff/'manifest.json').read_bytes()).hexdigest(),
            emitted_sha256=hashlib.sha256(raw).hexdigest(),reply_hex=data['reply_hex'],original_reset_completed=True,
            actual_driver_elapsed_ns=data['elapsed_ns'],scope='Actual controller register/native-worker model output consumed by original H4 decoder; no physical radio or full-daemon claim')
    report=dict(result='PASS',hardware_tested=False,device_contacted=False,cpu='Cortex-A9',
        source_sha256=original.IMAGE_SHA,source_uuid=original.UUID,results=result,native_reply=native_reply,handoff=handoff_proof,
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependencies={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in
            [('uart_verifier',original.__file__),('macho_analyzer',original.CATALOG.__file__)]},
        scope='Original H4 reset/dispatch/framing/POSIX writer instructions executed; explicit FD/register state and libc/timer/diagnostic/socket facades. No command sent to a device.')
    out.mkdir(parents=True);(out/'native-reset.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS original H4 reset sends 01030c00 through the actual native POSIX write call on both write-success and failure paths; no hardware')


if __name__=='__main__':main()
