#!/usr/bin/env python3
"""Retain bounded own-process user memory on one verified serial handle.

The PID and task must match before and after collection. Page tables and byte
reads are sequential evidence, not an atomic process snapshot. No writes,
reboot, input, flash, serial retry or forced process termination is performed.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import struct

import importlib.util

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    boot = module('user_memory_boot', 'capture-boot-snapshot.py')
    f, m, o = boot.f, boot.m, boot.o
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--process', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--range', action='append', required=True,
                        help='label:hex-user-VA:hex-length, at most 32 ranges')
    args = parser.parse_args()
    f.validate_command('threads ' + args.process)
    ranges = []
    for item in args.range:
        match = re.fullmatch(r'([A-Za-z0-9_-]{1,48}):([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,4})', item)
        if not match:
            parser.error('Invalid labeled user range')
        label, address, size = match[1], int(match[2], 16), int(match[3], 16)
        if not 4096 <= address < 0x40000000 or not 0 < size <= 32768 or address + size > 0x40000000:
            parser.error('User range must fit below 1GiB and be at most 32KiB')
        ranges.append((label, address, size))
    if not 0 < args.pid or len(ranges) > 32 or len({r[0] for r in ranges}) != len(ranges):
        parser.error('Positive PID and up to 32 distinct labels required')
    out = o.confined(args.output, f.REPO / 'out')
    kernel_file = o.confined(args.kernel, f.REPO / 'out')
    o.require(not out.exists(), 'Fresh evidence directory required')
    symbols = m.Symbols(kernel_file)
    profile = json.loads((o.OUT / 'inventory-20261106-211114-download-profile.json').read_text())
    with o.host_lock():
        device = o.cdc(o.Host().inventory())
        o.require(device and device['service'].lower() == 'usbser' and
                  o.normalize_location(device['location']) == profile['location'],
                  'Approved kernel CDC absent')
        out.mkdir(parents=True)
        with (out / 'events.jsonl').open('x', encoding='utf-8') as events:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'RANGE_SAVED', 'STOP', 'CLOSED', 'DONE'):
                    print(json.dumps(row), flush=True)

            try:
                with boot.open_session(device, symbols.tag, out, record, 300) as session:
                    answer, _ = session.command('panic-status')
                    o.require(answer == 'OK panic=0 seconds=00000000', 'Active panic; preserve panic log first')
                    _, before = session.command('threads ' + args.process)
                    (out / 'threads-before.txt').write_bytes(before)
                    found = re.search(rb'proc\s+(\d+)\s+', before)
                    threads = re.findall(rb'\bthr=(0x[0-9a-f]+)', before)
                    o.require(found and int(found[1]) == args.pid and threads, 'Expected process identity absent')
                    kernel = m.Kernel(session, symbols)
                    task = kernel.u32(int(threads[0], 16) + 0x3a0)
                    map_va = kernel.u32(task + 0x18)
                    user = kernel.user_pmap(kernel.u32(map_va + 0x2c))
                    result = dict(tag=symbols.tag, process=args.process, pid=args.pid, task=hex(task),
                                  snapshot='sequential user reads; not atomic', ranges=[], identity_stable=False)
                    for label, address, size in ranges:
                        row = dict(label=label, address=hex(address), size=size)
                        try:
                            data = user.read(address, size)
                            (out / (label + '.bin')).write_bytes(data)
                            import hashlib
                            row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                            record('RANGE_SAVED', **row)
                        except m.MappingError as error:
                            row['mapping_error'] = str(error)
                        result['ranges'].append(row)
                        (out / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                    _, after = session.command('threads ' + args.process)
                    (out / 'threads-after.txt').write_bytes(after)
                    found_after = re.search(rb'proc\s+(\d+)\s+', after)
                    after_threads = re.findall(rb'\bthr=(0x[0-9a-f]+)', after)
                    result['identity_stable'] = bool(found_after and int(found_after[1]) == args.pid and
                        after_threads and kernel.u32(int(after_threads[0], 16) + 0x3a0) == task)
                    (out / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                    o.require(result['identity_stable'], 'Process changed during capture; saved original bytes, no retry')
                record('DONE', ranges=len(ranges))
            except BaseException as error:
                record('STOP', error=str(error), retry=False)
                raise


if __name__ == '__main__':
    main()
