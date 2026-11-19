#!/usr/bin/env python3
"""Execute original BTServer UART/transport entry points with explicit OS facades."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import sys

if os.environ.get('I9100_CPU_CAPPED') != '1':
    os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice', '-c2', '-n7',
                         sys.executable, '-B', __file__, *sys.argv[1:]], dict(os.environ, I9100_CPU_CAPPED='1'))
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'assets/py-native-hid'))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_CPSR, UC_ARM_REG_FPEXC)

SPEC = importlib.util.spec_from_file_location('btserver_native_catalog', Path(__file__).with_name('research-ios6-btserver.py'))
CATALOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CATALOG)
IMAGE = ROOT / 'research/ios6-btserver-20261119/BTServer.bin'
IMAGE_SHA = '21c2b6734d6d638a508fbc3d2fa88d05a072f9e5b1066447290d4674f397b17c'
UUID = 'af0150d5085e326598edff072a23d146'
STACK, HEAP, STOP = 0x20000000, 0x21000000, 0x22000000
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]


class Native:
    def __init__(self, image, *, device_speed=115200, preference_speed=None, override=None,
                 fail=None, mode=0, transport=1):
        self.image = image
        self.device_speed, self.preference_speed, self.override = device_speed, preference_speed, override
        self.fail, self.mode, self.transport = fail, mode, transport
        self.calls, self.executed, self.attributes, self.address = [], set(), None, None
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        self.uc.cpr_write(15, 0, 1, 0, 2, 0, False, 0xf00000)
        self.uc.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
        for segment in image.segments:
            if not segment['vm'] or not segment['size']:
                continue
            start = segment['vm'] & ~4095
            size = (segment['vm'] + segment['size'] + 4095 & ~4095) - start
            self.uc.mem_map(start, size)
            self.uc.mem_write(segment['vm'], image.raw[segment['offset']:segment['offset']+segment['file_bytes']])
        self.uc.mem_map(STACK, 0x40000)
        self.uc.mem_map(HEAP, 0x10000)
        self.uc.mem_map(STOP, 4096)
        self.uc.mem_write(HEAP, struct.pack('<I', 0x19384756))
        self.uc.mem_write(HEAP+4, struct.pack('<I', 5))
        for address, name in image.pointers.items():
            if name == '___stack_chk_guard':
                self.uc.mem_write(address, struct.pack('<I', HEAP))
            elif name in ('_kCFAllocatorDefault','___stderrp','___stdoutp'):
                self.uc.mem_write(address, struct.pack('<I', HEAP+8))
        if override is not None:
            self.uc.mem_write(HEAP+0x100, override.encode()+b'\0')
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.invalid)

    def invalid(self, uc, access, address, size, value, user):
        self.invalid_access = dict(unmapped=hex(address), bytes=size, pc=hex(uc.reg_read(UC_ARM_REG_PC)))
        return False

    def u32(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def string(self, address):
        result = bytearray()
        for offset in range(1024):
            value = bytes(self.uc.mem_read(address+offset, 1))[0]
            if not value:
                return result.decode()
            result.append(value)
        raise AssertionError('Unbounded native string')

    def returned(self, value=0):
        self.uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
        link = self.uc.reg_read(UC_ARM_REG_LR)
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
        self.uc.reg_write(UC_ARM_REG_CPSR, (cpsr & ~32) | (32 if link & 1 else 0))
        self.uc.reg_write(UC_ARM_REG_PC, link)

    def code(self, uc, address, size, user):
        self.executed.add(address)
        if address == STOP:
            uc.emu_stop()
            return
        r = [uc.reg_read(reg) for reg in REGS]
        # Original configuration selection still executes; only CF objects are modeled.
        if address == 0xe0f50:
            self.calls.append(dict(name='CFPreferences facade', key=self.image.string(r[0])))
            self.returned(HEAP+0x400 if self.preference_speed is not None else 0)
            return
        if address == 0x128df4:
            assert r[0] == HEAP+0x400 and self.preference_speed is not None
            self.returned(self.preference_speed)
            return
        if address in (0xe5404, 0xe52fc, 0xdaee0, 0xe3504, 0xe7394, 0xe7c1c, 0xdae90, 0xcefe0):
            self.calls.append(dict(name='native helper facade', address=hex(address), r0=r[0], r1=r[1]))
            self.returned(1 if address == 0xe52fc else 0)
            return
        if address == 0xcf184:
            assert r[0] in (0x804, 0x808)
            self.returned(HEAP+0x3000)
            return
        if address == 0x124f18:
            self.calls.append(dict(name='log', text=self.string(r[0])))
            self.returned()
            return
        name = self.image.stubs.get(address)
        if name is None:
            return
        self.calls.append(dict(name=name, args=r))
        if name == '___error':
            self.returned(HEAP+4)
        elif name == '_strerror':
            uc.mem_write(HEAP+0x500, b'modeled failure\0')
            self.returned(HEAP+0x500)
        elif name == '_strncpy':
            assert 0 < r[2] <= 256
            text = self.string(r[1]).encode()[:r[2]]
            uc.mem_write(r[0], text+bytes(r[2]-len(text)))
            self.returned(r[0])
        elif name == '_strlcpy':
            assert r[2] == 96
            text = self.string(r[1]).encode()
            assert len(text) < r[2]
            uc.mem_write(r[0], text+b'\0')
            self.returned(len(text))
        elif name == '_strtok':
            assert self.string(r[1]) == ','
            if r[0]:
                self.token_next = r[0]
            start = getattr(self, 'token_next', 0)
            if not start:
                self.returned()
            else:
                text = self.string(start)
                delimiter = text.find(',')
                if delimiter >= 0:
                    uc.mem_write(start+delimiter, b'\0')
                    self.token_next = start+delimiter+1
                else:
                    self.token_next = 0
                self.returned(start)
        elif name == '_strtoul':
            assert r[1] == r[2] == 0
            self.returned(int(self.string(r[0]), 0))
        elif name == '_socket':
            assert r[:3] == [32, 1, 2]
            self.returned(-1 if self.fail == 'socket' else 11)
        elif name == '_ioctl':
            assert r[0] == 11 and r[1] == 0xc0644e03
            assert self.string(r[2]+4) == 'com.apple.uart.bluetooth'
            uc.mem_write(r[2], struct.pack('<I', 43))
            self.returned(-1 if self.fail == 'ioctl' else 0)
        elif name == '_connect':
            assert r[0] == 11 and r[2] == 32
            self.address = bytes(uc.mem_read(r[1], 32))
            assert self.address == struct.pack('<BBHII5I', 32, 32, 2, 43, 0, 0, 0, 0, 0, 0)
            self.returned(-1 if self.fail == 'connect' else 0)
        elif name == '_getsockopt':
            assert r[:3] == [11, 2, 0x402c7413]
            count = self.u32(uc.reg_read(UC_ARM_REG_SP))
            assert self.u32(count) == 44
            uc.mem_write(r[3], struct.pack('<4I20s2I', 0, 0, 0x8b00, 0, bytes(20), 115200, 115200))
            self.returned()
        elif name == '_cfmakeraw':
            # Explicit libc facade, not a claim that libc/electrical flow was verified.
            term = list(struct.unpack('<4I20s2I', uc.mem_read(r[0], 44)))
            term[0] &= ~0x3eb
            term[1] &= ~1
            term[2] = (term[2] & ~0x1300) | 0x300
            term[3] &= ~0x800001cb
            cc = bytearray(term[4]); cc[16], cc[17] = 1, 0; term[4] = bytes(cc)
            uc.mem_write(r[0], struct.pack('<4I20s2I', *term))
            self.returned()
        elif name == '_cfsetspeed':
            uc.mem_write(r[0]+36, struct.pack('<2I', r[1], r[1]))
            self.returned()
        elif name == '_setsockopt':
            assert r[:3] == [11, 2, 0x802c7414] and self.u32(uc.reg_read(UC_ARM_REG_SP)) == 44
            self.attributes = bytes(uc.mem_read(r[3], 44))
            self.returned()
        elif name == '_IOMasterPort':
            assert r[0] == 0
            uc.mem_write(r[1], struct.pack('<I', 1))
            self.returned()
        elif name == '_IOServiceNameMatching':
            assert self.string(r[0]) == 'bluetooth'
            self.returned(HEAP+0x600)
        elif name == '_IOServiceGetMatchingService':
            self.returned(2)
        elif name == '_IORegistryEntrySearchCFProperty':
            self.property = self.image.string(r[2])
            assert self.property in ('transport-speed', 'transport-encoding')
            assert self.string(r[1]) == 'IODeviceTree'
            self.returned(HEAP+0x700)
        elif name == '_CFDataGetBytes':
            assert r[1:3] == [0, 4]
            uc.mem_write(r[3], struct.pack('<I', self.device_speed if self.property == 'transport-speed' else self.transport))
            self.returned()
        elif name in ('_CFRelease', '_IOObjectRelease'):
            self.returned()
        elif name == '_open':
            assert self.string(r[0]) == '/dev/btwake' and r[1] == 0
            self.returned(12)
        elif name == '___stack_chk_fail':
            raise AssertionError('Original stack guard failed')
        else:
            raise AssertionError('Unexpected original import '+name)

    def call(self, address, *args):
        for reg, value in zip(REGS, list(args)+[0]*4):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_SP, STACK+0x20000)
        self.uc.reg_write(UC_ARM_REG_LR, STOP | 1)
        try:
            self.uc.emu_start(address | 1, STOP+2, count=20000)
        except Exception as exc:
            raise AssertionError(dict(error=str(exc), pc=hex(self.uc.reg_read(UC_ARM_REG_PC)),
                invalid=getattr(self,'invalid_access',None), registers=[hex(self.uc.reg_read(reg)) for reg in REGS], recent_calls=self.calls[-8:])) from exc
        assert STOP in self.executed, 'Native path did not return within budget'
        return self.uc.reg_read(UC_ARM_REG_R0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT/'uniloader-S2I9100/out') or out.exists():
        parser.error('Use a fresh loader/out evidence directory')
    image = CATALOG.MachO(IMAGE)
    assert hashlib.sha256(image.raw).hexdigest() == IMAGE_SHA and image.uuid == UUID
    assert len(image.functions) == 9455 and all(value & 1 for value in image.function_entries)
    assert image.functions[0] == 0x2198 and image.function(0x2199) == 0x2198
    record, _ = CATALOG.analyze(image, 0xdf1d8, 0xdf450)
    socket = next(call for call in record['calls'] if call['symbol'] == '_socket')
    assert [socket['arguments'][name]['value'] for name in ('r0', 'r1', 'r2')] == [32, 1, 2]
    assert any(ref['value'] == 'com.apple.uart.bluetooth' for ref in record['refs'])
    results = {}
    for label, options in (
        ('device-speed-115200', {}), ('default-speed', dict(device_speed=0)),
        ('preference-speed', dict(preference_speed=921600)),
        ('explicit-speed', dict(device_speed=2400000, override='com.apple.uart.bluetooth,115200')),
        ('parity-mode-1', dict(mode=1)), ('parity-mode-2', dict(mode=2)),
        ('socket-failure', dict(fail='socket')), ('ioctl-failure', dict(fail='ioctl')),
        ('connect-failure', dict(fail='connect'))):
        native = Native(image, **options)
        result = native.call(0xdf1d8, native.mode, HEAP+0x100 if native.override is not None else 0)
        if native.fail:
            assert result and native.attributes is None
        else:
            assert result == 0 and len(native.attributes) == 44
            values = struct.unpack('<4I20s2I', native.attributes)
            speed = 115200 if native.override else native.preference_speed if native.preference_speed is not None else native.device_speed or 2400000
            assert values[-2:] == (speed, speed)
            assert values[2] == (0x9b00 if native.mode in (1, 2) else 0x38b00)
            assert values[0] == (0x10 if native.mode in (1, 2) else 4)
        results[label] = dict(return_value=result, calls=native.calls,
            termios_hex=native.attributes.hex() if native.attributes else None,
            sockaddr_hex=native.address.hex() if native.address else None)
    h4 = Native(image)
    assert h4.call(0xe6e4c) == 0x6d
    assert not any(item['name'] == '_open' for item in h4.calls)
    h4bc = Native(image)
    assert h4bc.call(0xe7548) == 0x6d
    assert any(item['name'] == '_open' for item in h4bc.calls)
    results['h4-wake-policy'] = h4.calls
    results['h4bc-wake-policy'] = h4bc.calls
    launch = plistlib.loads((ROOT/'research/ios6-btserver-20261119/com.apple.BTServer.plist').read_bytes())
    assert launch['UserName'] == 'mobile' and launch['ProgramArguments'] == ['/usr/sbin/BTServer']
    proof = dict(result='PASS', hardware_tested=False, device_contacted=False, cpu='Cortex-A9',
        original_image_sha256=IMAGE_SHA, original_image_uuid=UUID, analyzer_sha256=hashlib.sha256(Path(CATALOG.__file__).read_bytes()).hexdigest(),
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), function_starts=9455,
        scope='Original UART configuration and H4/H4BC initialization instructions; CF/libc/socket/allocator/thread/electrical providers are explicit facades. Not a complete daemon or radio acceptance.',
        code_sha256={hex(lo):hashlib.sha256(image.raw[image.offset(lo,hi-lo):image.offset(lo,hi-lo)+hi-lo]).hexdigest()
            for lo,hi in ((0xdf1d8,0xdf450),(0xe11b4,0xe11d8),(0xe0fcc,0xe1068),(0xe6e4c,0xe6eb0),(0xe7548,0xe75b4))},
        original_launchd=launch, results=results)
    out.mkdir(parents=True)
    (out/'native-btserver.json').write_text(json.dumps(proof, indent=2)+'\n')
    print('PASS original Thumb entries, UART socket/CTLIOCGINFO/44B termios/default and explicit baud/parity/failure paths, H4 versus H4BC wake dependency; OS facades, no hardware')


if __name__ == '__main__':
    main()
