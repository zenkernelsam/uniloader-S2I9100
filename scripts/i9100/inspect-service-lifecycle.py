#!/usr/bin/env python3
"""Sample one service and retained user faults on one verified CDC handle.

All observations are sequential and may straddle a process restart. A missing
name is not evidence that launchd never started the job. No target writes,
reboots, serial retries or forced termination.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def fault_rows(raw):
    if len(raw) != (1 + 32 * 29) * 4:
        raise ValueError('Unexpected retained fault table length')
    sequence = struct.unpack_from('<I', raw)[0]
    fields = 'sequence pid thread task type pc lr sp far fsr psr result'.split()
    fields += ['r' + str(n) for n in range(13)]
    rows = []
    for n in range(32):
        at = (1 + n * 29) * 4
        values = struct.unpack_from('<25I', raw, at)
        if not values[0] or ((sequence - values[0]) & 0xffffffff) >= 32:
            continue
        row = dict(zip(fields, values))
        row['name'] = raw[at + 100:at + 116].split(b'\0')[0].decode('ascii', 'replace')
        rows.append(row)
    return dict(sequence=sequence, rows=sorted(rows, key=lambda r: r['sequence']))


def main():
    boot = module('service_boot', 'capture-boot-snapshot.py')
    stacks = module('service_stacks', 'inspect-stacks.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--process', required=True)
    parser.add_argument('--samples', type=int, choices=range(1, 13), default=6)
    parser.add_argument('--interval', type=int, choices=range(1, 31), default=10)
    a = parser.parse_args()
    boot.f.validate_command('threads ' + a.process)
    kernel_path = boot.o.confined(a.kernel, boot.f.REPO / 'out')
    out = boot.o.confined(a.output, boot.f.REPO / 'out')
    boot.o.require(not out.exists(), 'Fresh output directory required')
    symbols = boot.m.Symbols(kernel_path)
    profile = json.loads((boot.o.OUT / 'inventory-20261106-211114-download-profile.json').read_text())
    with boot.o.host_lock():
        device = boot.o.cdc(boot.o.Host().inventory())
        boot.o.require(device and device['service'].lower() == 'usbser' and
                       boot.o.normalize_location(device['location']) == profile['location'],
                       'Approved live kernel CDC absent')
        out.mkdir(parents=True)
        with (out / 'events.jsonl').open('x', encoding='utf-8') as events:
            def record(phase, **fields):
                from datetime import datetime, timezone
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'SAMPLE', 'STOP', 'CLOSED', 'DONE'):
                    print(json.dumps(row), flush=True)
            try:
                results = dict(tag=symbols.tag, process=a.process, samples=[],
                               snapshot='sequential raw observations; absent sample does not mean never started')
                with boot.open_session(device, symbols.tag, out, record, budget_seconds=600) as session:
                    kernel = boot.m.Kernel(session, symbols)
                    for n in range(a.samples):
                        sample = out / f'{n:02}'
                        sample.mkdir()
                        answer, _ = session.command('panic-status')
                        if answer != 'OK panic=0 seconds=00000000':
                            _, raw = session.command('panic-log')
                            (sample / 'panic-log.bin').write_bytes(raw)
                            raise RuntimeError('Panic retained; stop this session')
                        raw = kernel.read(symbols['_i9100_user_fault_detail_diag'], (1 + 32 * 29) * 4)
                        (sample / 'user-fault-detail.bin').write_bytes(raw)
                        faults = fault_rows(raw)
                        retained = {}
                        for name, words in (('_i9100_commcenter_fault_payload', 144),
                                            ('_i9100_commcenter_fault_stack', 52)):
                            if name in symbols.values:
                                data = kernel.read(symbols[name], words * 4)
                                (sample / (name.lstrip('_') + '.bin')).write_bytes(data)
                                values = list(struct.unpack('<' + 'I' * words, data))
                                entry = dict(words=values[:16])
                                if name.endswith('_payload') and values[0]:
                                    if values[10] > 512 or values[12] not in (0, 1) or values[13] != 1:
                                        raise ValueError('Unknown Classic assertion payload schema')
                                    entry['expression'] = data[64:64 + values[10]].split(b'\0')[0].decode('utf-8', 'replace')
                                    entry['copy_error'] = values[11]
                                    entry['terminated'] = bool(values[12])
                                if name.endswith('_stack') and values[0]:
                                    if values[8] > 14:
                                        raise ValueError('Unknown Classic fault stack length')
                                    entry['frames'] = [dict(zip(('fp', 'previous', 'lr'), values[10+n*3:13+n*3]))
                                                       for n in range(values[8])]
                                retained[name] = entry
                        proc = stacks.capture_process(session, kernel, a.process, sample, boot.m, True, 1)
                        (sample / 'stacks.json').write_text(json.dumps(dict(tag=symbols.tag, processes=[proc]), indent=2) + '\n')
                        _, after = session.command('threads ' + a.process)
                        (sample / 'threads-after.txt').write_bytes(after)
                        identity = re.search(rb'proc\s+(\d+)\s+', after)
                        row = dict(number=n, process=proc, faults=faults, retained=retained,
                                   pid_after=int(identity[1]) if identity else None)
                        row['same_pid_after'] = proc.get('pid') is not None and proc['pid'] == row['pid_after']
                        results['samples'].append(row)
                        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                        record('SAMPLE', number=n, pid=proc.get('pid'), faults=faults['sequence'])
                        if n + 1 < a.samples:
                            session.sleep(a.interval)
                    answer, _ = session.command('panic-status')
                    if answer != 'OK panic=0 seconds=00000000':
                        _, raw = session.command('panic-log')
                        (out / 'panic-log-final.bin').write_bytes(raw)
                        raise RuntimeError('Panic started during sampling; evidence retained')
                record('DONE', samples=len(results['samples']))
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise


if __name__ == '__main__':
    main()
