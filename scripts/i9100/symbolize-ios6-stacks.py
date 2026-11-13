#!/usr/bin/env python3
"""Name live stack frames using their captured slide and the original iOS6 cache.

Read-only: no device session, no emulator, no target memory modification.
Nearest symbols marked <redacted> identify an image, not a recovered function.
"""
import os
import sys

if os.environ.get('I9100_CPU_CAPPED') != '1':
    os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice',
                         '-c2', '-n7', sys.executable, '-B', __file__, *sys.argv[1:]],
               dict(os.environ, I9100_CPU_CAPPED='1'))

import argparse
import bisect
import json
import mmap
from pathlib import Path
import struct

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO.parent


class Cache:
    def __init__(self, data):
        self.data = data
        if len(data) < 32 or not data[:16].startswith(b'dyld_v1'):
            raise ValueError('Expected an original dyld shared cache')
        mo, mc, io, ic = self.unpack('<4I', 16)
        if not 1 <= mc <= 16 or not 1 <= ic <= 4096:
            raise ValueError('Unbounded cache tables')
        self.maps = [self.unpack('<QQQII', mo + n * 32) for n in range(mc)]
        self.images = []
        self.symbols = {}
        for n in range(ic):
            va, _, _, name, _ = self.unpack('<QQQII', io + n * 32)
            self.images.append((va, self.string(name, len(data))))
        self.images.sort()
        self.bases = [entry[0] for entry in self.images]

    def unpack(self, fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(self.data):
            raise ValueError('Cache field outside file')
        return struct.unpack_from(fmt, self.data, offset)

    def string(self, offset, end):
        if not 0 <= offset < end <= len(self.data):
            raise ValueError('Cache string outside file')
        zero = self.data.find(b'\0', offset, end)
        if zero < 0:
            raise ValueError('Unterminated cache string')
        return self.data[offset:zero].decode('utf-8', 'replace')

    def offset(self, address, size=1):
        for va, length, offset, _, _ in self.maps:
            if va <= address and address + size <= va + length:
                result = offset + address - va
                if result + size <= len(self.data):
                    return result
        raise ValueError(f'Address outside original cache: {address:08x}')

    def image_symbols(self, base):
        at = self.offset(base, 28)
        magic, cpu, _, _, count, length, _ = self.unpack('<7I', at)
        if magic != 0xfeedface or cpu != 12 or count > 256:
            raise ValueError('Expected an ARM32 image')
        position, end = at + 28, at + 28 + length
        if end > len(self.data):
            raise ValueError('Image load commands outside cache')
        symbols, text = [], []
        for _ in range(count):
            command, size = self.unpack('<2I', position)
            if size < 8 or position + size > end:
                raise ValueError('Invalid image load command')
            if command == 1 and size >= 56:
                va, extent = self.unpack('<2I', position + 24)
                if self.data[position + 8:position + 24].rstrip(b'\0') == b'__TEXT':
                    text.append((va, va + extent))
            if command == 2 and size >= 24:
                so, number, st, strings = self.unpack('<4I', position + 8)
                if number > 1000000 or so + number * 12 > len(self.data) or st + strings > len(self.data):
                    raise ValueError('Symbol table outside cache')
                for n in range(number):
                    name, kind, _, _, value = self.unpack('<IBBHI', so + n * 12)
                    if value and kind & 0xe == 0xe and not kind & 0xe0 and name < strings:
                        symbols.append((value & ~1, self.string(st + name, st + strings)))
            position += size
        symbols.sort()
        return text, symbols, [entry[0] for entry in symbols]

    def describe(self, address):
        n = bisect.bisect_right(self.bases, address) - 1
        if n < 0:
            raise ValueError('Frame precedes cache images')
        base, name = self.images[n]
        if base not in self.symbols:
            self.symbols[base] = self.image_symbols(base)
        text, symbols, addresses = self.symbols[base]
        if not any(start <= address < end for start, end in text):
            raise ValueError(f'Frame outside image text: {address:08x}')
        n = bisect.bisect_right(addresses, address) - 1
        suffix = f'{symbols[n][1]}+0x{address-symbols[n][0]:x}' if n >= 0 else 'no local symbol'
        return f'{address:08x} {name}:{suffix}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stacks', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.stacks.resolve(), args.output.resolve()
    if not source.is_relative_to(REPO / 'out') or not output.is_relative_to(ROOT / 'research'):
        parser.error('Read loader out stacks and write research only')
    evidence = json.loads(source.read_text())
    lines = [f'Source: {source}', f'BUILD: {evidence["tag"]}',
             'Original-cache nearest symbols; <redacted> does not name a private function.']
    with (ROOT / 'assets/ios6-extract/dyld_cache6_armv7').open('rb') as file:
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            cache = Cache(data)
            for process in evidence['processes']:
                slide = int(process['dyld_info']['cache_slide'], 16)
                lines.append(f'PROCESS {process["process"]} PID={process["pid"]} slide={slide:x}')
                for thread in process['threads']:
                    lines.append(f'THREAD {thread["thread"]:08x}')
                    for frame in thread.get('frames', []):
                        live = int(frame['lr'], 16) & ~1
                        if live < 0x30000000:
                            lines.append(f'{live:08x} main executable (live address)')
                        else:
                            lines.append(cache.describe(live - slide))
    with output.open('x', encoding='utf-8') as file:
        file.write('\n'.join(lines) + '\n')
    print('\n'.join(lines), flush=True)


if __name__ == '__main__':
    main()
