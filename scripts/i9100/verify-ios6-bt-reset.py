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


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
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
    report=dict(result='PASS',hardware_tested=False,device_contacted=False,cpu='Cortex-A9',
        source_sha256=original.IMAGE_SHA,source_uuid=original.UUID,results=result,
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependencies={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in
            [('uart_verifier',original.__file__),('macho_analyzer',original.CATALOG.__file__)]},
        scope='Original H4 reset/dispatch/framing/POSIX writer instructions executed; explicit FD/register state and libc/timer/diagnostic/socket facades. No command sent to a device.')
    out.mkdir(parents=True);(out/'native-reset.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS original H4 reset sends 01030c00 through the actual native POSIX write call on both write-success and failure paths; no hardware')


if __name__=='__main__':main()
