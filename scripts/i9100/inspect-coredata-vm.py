#!/usr/bin/env python3
"""Observe the real CoreData VM result with one verified CDC handle."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import struct
import time

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


f = module('coredata_forensic', 'forensic-session.py')
m = module('coredata_memory', 'live-memory.py')
o = module('coredata_odin', 'odin-loop.py')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--seconds', type=int, default=180, choices=range(1, 601))
    a = p.parse_args()
    symbols = m.Symbols(a.kernel)
    out = o.confined(a.output, f.REPO / 'out')
    o.require(not out.exists(), 'Fresh output directory required')
    profile = json.loads((f.REPO / 'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device = o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location']) == profile['location'],
                  'No approved live CDC')
        out.mkdir(parents=True)
        transport = None
        with (out / 'events.jsonl').open('x') as events, (out / 'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'SAMPLE', 'STOP', 'DONE', 'CLOSED'):
                    print(json.dumps(row), flush=True)
            try:
                transport = f.WinTransport(device['port'], record)
                s = f.Session(transport, symbols.tag, record, capture, timeout=20)
                s.handshake()
                kernel = m.Kernel(s, symbols)
                deadline = time.monotonic() + a.seconds
                count = 0
                while True:
                    answer, _ = s.command('panic-status')
                    if answer != 'OK panic=0 seconds=00000000':
                        _, data = s.command('panic-log')
                        (out / 'panic-log.bin').write_bytes(data)
                        raise RuntimeError('Panic observed; retain log and stop this opener')
                    vm = kernel.read(symbols['_i9100_vm_remap_diag'], (1 + 128 * 20) * 4)
                    errors = kernel.read(symbols['_i9100_vm_error_diag'], (1 + 64 * 6) * 4)
                    faults = kernel.read(symbols['_i9100_user_fault_detail_diag'], (1 + 32 * 29) * 4)
                    exit_data = kernel.read(symbols['_i9100_process_exit'], 36)
                    for label, data in [('remap', vm), ('vm-errors', errors), ('faults', faults), ('sb-exit', exit_data)]:
                        (out / f'{count:02}-{label}.bin').write_bytes(data)
                    words = struct.unpack('<2561I', vm)
                    o.require(words[0] <= 128, 'Invalid remap count')
                    fields = ['sequence','pid','api','target_map','source_map','before','after','size',
                              'mask','flags','source_address','copy','inheritance','result','cur','max']
                    rows = []
                    for n in range(words[0]):
                        row = dict(zip(fields, words[1+n*20:1+n*20+16]))
                        pos = (1+n*20+16)*4
                        row['name'] = vm[pos:pos+16].split(b'\0')[0].decode('ascii', 'replace')
                        if row['sequence']:
                            rows.append(row)
                    words = struct.unpack('<385I', errors)
                    o.require(words[0] <= 64, 'Invalid VM error count')
                    error_fields = ['pid','id','retcode','size','bits','options']
                    error_rows = [dict(zip(error_fields, words[1+n*6:1+(n+1)*6])) for n in range(words[0])]
                    result = dict(tag=symbols.tag, remaps=rows, vm_errors=error_rows,
                                  fault_count=struct.unpack_from('<I', faults)[0],
                                  sb_exit=list(struct.unpack('<9I', exit_data)))
                    (out / f'{count:02}-decoded.json').write_text(json.dumps(result, indent=2)+'\n')
                    record('SAMPLE', number=count, **result)
                    count += 1
                    evidence = bool(error_rows or any(row['result'] for row in rows))
                    if evidence or time.monotonic() >= deadline:
                        record('DONE', samples=count, reason='VM-error-retained' if evidence else 'window-ended')
                        break
                    time.sleep(min(30, max(0, deadline-time.monotonic())))
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()
                record('CLOSED')


if __name__ == '__main__':
    main()
