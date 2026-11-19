#!/usr/bin/env python3
"""Read original iOS6 motion matching strings and HID factory instructions."""
import argparse
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import re
import struct
import sys

if os.environ.get('I9100_CPU_CAPPED') != '1':
    os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice', '-c2', '-n7',
                         sys.executable, '-B', __file__, *sys.argv[1:]], dict(os.environ, I9100_CPU_CAPPED='1'))

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'assets/py-native-hid'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--disasm', nargs=2, action='append', default=[], metavar=('HEX_ADDRESS', 'HEX_BYTES'))
    p.add_argument('--symbol-pattern', help='Limit symbol disassembly to this expression')
    a = p.parse_args()
    output = a.output.resolve()
    if not output.is_relative_to(ROOT / 'research'):
        p.error('Write research inside this project')
    output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('motion_cache', Path(__file__).with_name('symbolize-ios6-stacks.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    source = ROOT / 'assets/ios6-extract/dyld_cache6_armv7'
    report = dict(source=str(source.relative_to(ROOT)), hardware_tested=False, images=[])
    lines = []
    with source.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        cache = module.Cache(data)
        for base, name in cache.images:
            if not any(part in name for part in ('/CoreMotion.', '/IOKit.', '/GraphicsServices.', '/CoreLocation.')):
                continue
            at = cache.offset(base); pos = at + 28; count = cache.unpack('<I', at+16)[0]
            item = dict(path=name, base=f'{base:08x}', strings=[], sections=[])
            for _ in range(count):
                cmd, size = cache.unpack('<2I', pos)
                if cmd == 0x1b:
                    item['uuid'] = data[pos+8:pos+24].hex()
                if cmd == 1:
                    n = cache.unpack('<I', pos+48)[0]
                    for i in range(n):
                        s = pos+56+i*68; label = bytes(data[s:s+16]).rstrip(b'\0').decode()
                        address, length = cache.unpack('<2I', s+32)
                        if label == '__cstring':
                            raw = bytes(data[cache.offset(address, length):cache.offset(address, length)+length])
                            item['sections'].append(dict(name=label, address=f'{address:08x}', bytes=length,
                                                         sha256=hashlib.sha256(raw).hexdigest()))
                            cursor = 0
                            for text in raw.split(b'\0'):
                                value = text.decode('utf-8', 'replace')
                                if re.search(r'accel|gyro|compass|magnet|IOHID|HIDServiceSupport|PrimaryUsage|DeviceUsage|SampleInterval|ReportInterval|Sensor', value, re.I):
                                    item['strings'].append(dict(address=f'{address+cursor:08x}', value=value))
                                cursor += len(text)+1
                pos += size
            _, symbols, _ = cache.image_symbols(base)
            interesting = [(v, s) for v, s in symbols if (re.search(a.symbol_pattern, s) if a.symbol_pattern else s.startswith(('_IOHIDEventCreateAccelerometer',
                '_IOHIDEventCreateGyro', '_IOHIDEventCreateCompass', '_IOHIDEventGetFloatValue',
                '_IOHIDEventGetIntegerValue', '_IOHIDEventCreateData', '_IOHIDEventCreateWithData',
                '_IOHIDServiceConformsTo', '_IOHIDServiceClientConformsTo')) or
                re.search(r'CLIoHidManager|CLSensorInterfaceIoHid', s))]
            item['symbols'] = [dict(address=f'{v:08x}', name=s) for v, s in interesting]
            for address, symbol in interesting:
                extent = 0x600 if 'Get' in symbol else 0x300
                blob = bytes(data[cache.offset(address, extent):cache.offset(address, extent)+extent])
                lines.append(f'\n{symbol} {address:08x} SHA256 {hashlib.sha256(blob).hexdigest()}')
                for insn in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(blob, address):
                    lines.append(f'{insn.address:08x} {insn.mnemonic:9} {insn.op_str}')
            report['images'].append(item)
        report['extra_code'] = []
        for va, length in a.disasm:
            address, extent = int(va, 16), int(length, 16)
            if not 2 <= extent <= 0x4000:
                p.error('Disassembly must remain bounded to 16 KiB per address')
            blob = bytes(data[cache.offset(address, extent):cache.offset(address, extent)+extent])
            report['extra_code'].append(dict(address=f'{address:08x}', bytes=extent,
                                            sha256=hashlib.sha256(blob).hexdigest()))
            lines.append(f'\nEXTRA {address:08x} SHA256 {hashlib.sha256(blob).hexdigest()}')
            lines.extend(f'{i.address:08x} {i.mnemonic:9} {i.op_str}'
                         for i in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(blob, address))
    (output/'catalog.json').write_text(json.dumps(report, indent=2)+'\n')
    (output/'hid-factories.txt').write_text('\n'.join(lines)+'\n')
    print('EVIDENCE', output)
    for image in report['images']:
        print(image['path'], image.get('uuid'), 'matching strings', len(image['strings']))
        for symbol in image['symbols']:print(symbol['name'], symbol['address'])


if __name__ == '__main__':
    main()
