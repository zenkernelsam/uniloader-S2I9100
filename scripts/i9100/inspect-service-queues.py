#!/usr/bin/env python3
"""Read current service receive queues with one BUILD-verified CDC handle.

Port offsets match the existing inspect-display-rpc.py ARM snapshot. Save
bounded message prefixes only for queues that are actually nonempty; a raw
IRQ snapshot is an observation, not a locked or atomic service-state proof.
"""
import argparse
from datetime import datetime, timezone
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
    f = module('queues_forensic', 'forensic-session.py')
    m = module('queues_memory', 'live-memory.py')
    o = module('queues_odin', 'odin-loop.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--process', action='append', required=True)
    a = parser.parse_args()
    for name in a.process:
        f.validate_command('ports ' + name)
    out = o.confined(a.output, f.REPO / 'out')
    o.require(not out.exists(), 'Fresh evidence directory required')
    symbols = m.Symbols(a.kernel)
    profile = json.loads((f.REPO / 'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device = o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location']) == profile['location'],
                  'Expected the approved healthy i9100 CDC device')
        out.mkdir(parents=True)
        transport = None
        with (out / 'events.jsonl').open('x') as events, (out / 'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'STOP', 'DONE', 'CLOSED'):
                    print(json.dumps(row), flush=True)
            try:
                transport = f.WinTransport(device['port'], record)
                session = f.Session(transport, symbols.tag, record, capture, timeout=20)
                session.handshake()
                answer, _ = session.command('panic-status')
                o.require(answer == 'OK panic=0 seconds=00000000', 'Panic active; preserve it with panic recovery')
                kernel = m.Kernel(session, symbols)
                results = dict(tag=symbols.tag, snapshot='raw-irq', processes=[])
                for name in a.process:
                    _, raw_ports = session.command('ports ' + name)
                    (out / (name + '-ports.txt')).write_bytes(raw_ports)
                    text = raw_ports.decode('ascii')
                    identity = re.search(r'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)', text)
                    process = dict(name=name, queues=[])
                    if identity:
                        process.update(pid=int(identity[1]), task=identity[2])
                    for pn, obj in re.findall(r'pn=([0-9a-f]+) rt=recv obj=(0x[0-9a-f]+)', text)[:256]:
                        address = int(obj, 16)
                        raw = kernel.read(address, 0x8c)
                        (out / f'{name}-port-{pn}.bin').write_bytes(raw)
                        w = struct.unpack('<35I', raw)
                        q = dict(name=pn, object=obj, bits=hex(w[0]), references=w[1],
                                 count=w[17], limit=w[18], sequence=w[19],
                                 receiver_name=hex(w[20]), receiver_space=hex(w[22]),
                                 send_rights=w[25], send_once_rights=w[26], pset_count=w[31],
                                 context=[hex(w[33]), hex(w[34])], messages=[])
                        if w[17] > 65535 or w[18] > 65535:
                            q['error'] = 'Queue geometry changed or is unavailable'
                        else:
                            node = w[16]
                            seen = set()
                            while node and node not in seen and len(seen) < min(w[17], 8):
                                seen.add(node)
                                kh = struct.unpack('<6I', kernel.read(node, 24))
                                h = kernel.read(kh[5], 24)
                                bits, size, remote, local, reserved, msgid = struct.unpack('<5Ii', h)
                                if not 24 <= size <= kh[3]:
                                    q['error'] = 'Message changed or has inconsistent bounds'
                                    break
                                prefix = kernel.read(kh[5], min(size, 512))
                                (out / f'{name}-message-{pn}-{len(q["messages"])}.bin').write_bytes(prefix)
                                q['messages'].append(dict(kmsg=hex(node), header=hex(kh[5]),
                                    size=size, bits=hex(bits), remote=hex(remote), local=hex(local),
                                    id=msgid, reserved=hex(reserved), prefix_bytes=len(prefix)))
                                node = kh[0]
                        process['queues'].append(q)
                    _, after = session.command('ports ' + name)
                    (out / (name + '-ports-after.txt')).write_bytes(after)
                    current = re.search(r'proc\s+(\d+)\s+', after.decode('ascii'))
                    process['same_pid_after'] = bool(identity and current and int(current[1]) == process['pid'])
                    results['processes'].append(process)
                    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                    print(name, 'pid=' + str(process.get('pid')), 'pending=' +
                          str([(q['name'], q['count'], [v['id'] for v in q['messages']])
                               for q in process['queues'] if q['count']]), flush=True)
                record('DONE', processes=len(results['processes']))
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()
                record('CLOSED')


if __name__ == '__main__':
    main()
