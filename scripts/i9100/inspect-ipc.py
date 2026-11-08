#!/usr/bin/env python3
"""Snapshot a blocked Mach send queue without writing kernel/user memory.

The IPC member offsets below are from the matching ARM trap.o DWARF.
Queue headers and payload prefixes are retained with physical-read evidence.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import struct


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    here = Path(__file__).resolve().parent
    f = module('forensic', here / 'forensic-session.py')
    m = module('memory', here / 'live-memory.py')
    odin = module('odin', here / 'odin-loop.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--process', default='backboardd')
    args = parser.parse_args()
    symbols = m.Symbols(args.kernel)
    output = args.output.resolve()
    if not output.is_relative_to(f.REPO / 'out') or output.exists():
        parser.error('Fresh output directory in repository out required')
    with odin.host_lock():
        device = odin.cdc(odin.Host().inventory())
        if device is None:
            raise RuntimeError('No healthy i9100 CDC device')
        profile = json.loads((f.REPO / 'out/automation/inventory-20261108-recovery-download.json').read_text())
        if odin.normalize_location(device['location']) != profile['location']:
            raise RuntimeError('USB topology differs from approved device')
        output.mkdir(parents=True)
        transport = None
        with (output / 'events.jsonl').open('x') as events, (output / 'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n'); events.flush()
                if phase in ('OPEN_BEGIN','OPEN_OK','DTR_OK','STOP','DONE'):
                    print(json.dumps(row), flush=True)
            try:
                transport = f.WinTransport(device['port'], record)
                session = f.Session(transport, symbols.tag, record, capture, timeout=20)
                session.handshake()
                _, threads = session.command('threads ' + args.process)
                (output / 'threads.txt').write_bytes(threads)
                kernel = m.Kernel(session, symbols)
                # Read and snapshot evidence for every physical read.
                raw_read = kernel.read_phys
                count = 0
                def evidenced_read(addr, size):
                    nonlocal count
                    data = raw_read(addr, size)
                    (output / f'memory-{count:03}-{addr:08x}-{size:x}.bin').write_bytes(data)
                    count += 1
                    return data
                kernel.read_phys = evidenced_read
                kernel.pmap.read_phys = evidenced_read
                result = dict(kernel_tag=symbols.tag, kernel_file=str(symbols.path),
                              phys_base=hex(kernel.phys_base), virt_base=hex(kernel.virt_base),
                              queues=[], ipc_offsets=dict(port_messages=0x30,port_receiver=0x58,
                              port_kobject=0x5c,space_task=0x34,kmsg_header=0x14))
                for line in threads.decode().splitlines():
                    fields = dict(re.findall(r'\b([a-z0-9]+)=(0x[0-9a-f]+|[0-9a-f]+)', line))
                    if fields.get('wev') != f'{symbols["_ipc_mqueue_full"]:x}':
                        continue
                    wq = int(fields['wq'], 16)
                    port = wq - 0x30
                    raw = kernel.read(port, 0x8c)
                    (output / f'port-{port:08x}.bin').write_bytes(raw)
                    words = struct.unpack('<35I', raw)
                    space = words[0x58 // 4]
                    q = dict(thread=line.strip(),port=hex(port),bits=hex(words[0]),
                             references=words[1],queue_count=words[0x44//4],
                             queue_limit=words[0x48//4],receiver_name=hex(words[0x50//4]),
                             fullwaiters=words[0x54//4],receiver_space=hex(space),
                             receiver_task=hex(kernel.u32(space+0x34)),
                             kobject=hex(words[0x5c//4]),pset_count=words[0x7c//4],messages=[])
                    head = words[0x40//4]
                    node = head
                    seen = set()
                    while node and node not in seen and len(seen) < min(q['queue_count'],16):
                        seen.add(node)
                        kh = kernel.read(node, 0x18)
                        nxt, prev, prealloc, size, sender, header = struct.unpack('<6I', kh)
                        h = kernel.read(header, 24)
                        bits, msgsize, remote, local, reserved, msgid = struct.unpack('<5Ii', h)
                        prefix = kernel.read(header, min(max(msgsize,24),512))
                        (output / f'message-{port:08x}-{len(q["messages"]):02}.bin').write_bytes(prefix)
                        strings = [s.decode('ascii') for s in re.findall(rb'[ -~]{4,}',prefix)]
                        q['messages'].append(dict(kmsg=hex(node),next=hex(nxt),header=hex(header),
                                                  allocation=size,bits=hex(bits),size=msgsize,id=msgid,
                                                  remote=hex(remote),local=hex(local),reserved=hex(reserved),strings=strings))
                        node = nxt
                    result['queues'].append(q)
                (output/'ipc.json').write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps(result,indent=2),flush=True)
                record('DONE', queues=len(result['queues']))
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()


if __name__=='__main__':
    main()
