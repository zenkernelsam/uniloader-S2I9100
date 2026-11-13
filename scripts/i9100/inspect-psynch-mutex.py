#!/usr/bin/env python3
"""Retain service thread IDs and actual contended mutex bytes, read-only."""
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


def main():
    boot = module('mutex_boot', 'capture-boot-snapshot.py')
    stacks = module('mutex_stacks', 'inspect-stacks.py')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--process', required=True)
    a = p.parse_args()
    boot.f.validate_command('threads ' + a.process)
    out = boot.o.confined(a.output, boot.f.REPO / 'out')
    boot.o.require(not out.exists(), 'Fresh output required')
    symbols = boot.m.Symbols(boot.o.confined(a.kernel, boot.f.REPO / 'out'))
    profile = json.loads((boot.o.OUT / 'inventory-20261106-211114-download-profile.json').read_text())
    with boot.o.host_lock():
        device = boot.o.cdc(boot.o.Host().inventory())
        boot.o.require(device and device['service'].lower() == 'usbser' and
                       boot.o.normalize_location(device['location']) == profile['location'],
                       'Approved CDC absent')
        out.mkdir(parents=True)
        with (out / 'events.jsonl').open('x', encoding='utf-8') as events:
            def record(phase, **fields):
                from datetime import datetime, timezone
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'STOP', 'CLOSED', 'DONE'):
                    print(json.dumps(row), flush=True)
            try:
                with boot.open_session(device, symbols.tag, out, record, budget_seconds=300) as session:
                    answer, _ = session.command('panic-status')
                    boot.o.require(answer == 'OK panic=0 seconds=00000000', 'Panic active')
                    kernel = boot.m.Kernel(session, symbols)
                    proc = stacks.capture_process(session, kernel, a.process, out, boot.m, True, 16)
                    result = dict(tag=symbols.tag, process=proc,
                                  snapshot='sequential live bytes; raw owner matching is not a lock-consistency proof')
                    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    if proc.get('threads'):
                        # Match the actual _thread_tid accessor before using its member offsets.
                        accessor = kernel.read(symbols['_thread_tid'] & ~1, 18)
                        boot.o.require(bytes.fromhex('d0f8c804') in accessor and
                                       bytes.fromhex('d1f8cc14') in accessor,
                                       'Unexpected thread_id accessor; no guessed member reads')
                        tls_accessor = kernel.read(symbols['_thread_get_cthread_self'] & ~1, 14)
                        boot.o.require(bytes.fromhex('d0e9e601') in tls_accessor,
                                       'Unexpected cthread accessor; no guessed TLS member reads')
                        user = kernel.user_pmap(int(proc['pmap'], 16))
                        if '_i9100_audio_property_lock_diag' in symbols.values:
                            repair=struct.unpack('<12I',kernel.read(symbols['_i9100_audio_property_lock_diag'],48))
                            result['audio_repair']=list(repair)
                            if repair[0]==2 and repair[1]==proc['pid'] and repair[2]==int(proc['task'],16):
                                for label,address,length in [('site',repair[4],24),('trampoline',repair[5],68)]:
                                    raw=user.read(address,length)
                                    (out/('audio-repair-'+label+'.bin')).write_bytes(raw)
                                    result['audio_repair_'+label]=raw.hex()
                        dyld = proc.get('dyld_info', {})
                        count = dyld.get('image_count', 0)
                        if 0 < count <= 512:
                            image_data = user.read(int(dyld['image_array'], 16), count * 12)
                            (out / 'dyld-images.bin').write_bytes(image_data)
                            images = [struct.unpack_from('<3I', image_data, n * 12) for n in range(count)]
                            candidates = [int(t['registers']['pc'], 16) & ~1 for t in proc['threads'] if 'registers' in t]
                            candidates += [int(f['lr'], 16) & ~1 for t in proc['threads'] for f in t.get('frames', [])]
                            selected = set()
                            for address in candidates:
                                if 4096 <= address < 0x30000000:
                                    bases = [base for base, path, date in images if base <= address]
                                    if bases:
                                        selected.add(max(bases))
                            result['images'] = []
                            for base, path, date in images:
                                if base not in selected or not 4096 <= path <= 0x3ffffe00:
                                    continue
                                raw = user.read(path, min(512, 4096 - (path & 4095)))
                                (out / f'image-{base:08x}-path.bin').write_bytes(raw)
                                result['images'].append(dict(base=hex(base), path=raw.split(b'\0')[0].decode('utf-8', 'replace'),
                                                             terminated=b'\0' in raw))
                        for thread in proc['threads']:
                            data = kernel.read(thread['thread'] + 0x4c8, 8)
                            thread['kernel_thread_id'] = struct.unpack('<Q', data)[0]
                            tls = struct.unpack('<Q', kernel.read(thread['thread'] + 0x398, 8))[0]
                            thread['cthread_self'] = hex(tls)
                            if 4096 <= tls <= 0x3fffffc0:
                                data_tls = user.read(tls, 64)
                                (out / f'thread-{thread["thread"]:08x}-tls.bin').write_bytes(data_tls)
                                thread['tls_words'] = list(struct.unpack('<16I', data_tls))
                            (out / f'thread-{thread["thread"]:08x}-id.bin').write_bytes(data)
                            registers = thread.get('registers', {})
                            if int(registers.get('r12', '0'), 16) != 301:
                                continue
                            address = int(registers['r0'], 16)
                            if not 4096 <= address <= 0x3fffffc0:
                                continue
                            data = user.read(address, 64)
                            (out / f'mutex-{address:08x}.bin').write_bytes(data)
                            thread['mutex'] = dict(address=hex(address), words=list(struct.unpack('<16I', data)),
                                                   raw_owner=struct.unpack_from('<Q', data, 32)[0])
                            prefix = user.read(address - 16, 16)
                            thread['mutex']['prefix'] = list(struct.unpack('<4I', prefix))
                            (out / f'mutex-{address:08x}-prefix.bin').write_bytes(prefix)
                            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    _, after = session.command('threads ' + a.process)
                    (out / 'threads-after.txt').write_bytes(after)
                    identity = re.search(rb'proc\s+(\d+)\s+', after)
                    result['pid_after'] = int(identity[1]) if identity else None
                    result['same_pid_after'] = proc.get('pid') is not None and proc['pid'] == result['pid_after']
                    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    answer, _ = session.command('panic-status')
                    boot.o.require(answer == 'OK panic=0 seconds=00000000', 'Panic during read')
                record('DONE')
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise


if __name__ == '__main__':
    main()
