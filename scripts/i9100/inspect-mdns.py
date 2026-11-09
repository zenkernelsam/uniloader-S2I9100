#!/usr/bin/env python3
"""Read bounded MDNS startup evidence with one verified serial handle."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import struct


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


TABLES = {
    'spawn': ('_i9100_mdns_spawn_diag', 8, 4,
              ['caller', 'stage', 'error', 'result']),
    'syscalls': ('_i9100_mdns_syscall_diag', 64, 16,
                 ['pid', 'role', 'syscall', 'nargs'] + ['arg'+str(n) for n in range(7)] +
                 ['error', 'result', 'pc', 'lr', 'stage']),
    'exit_user': ('_i9100_mdns_exit_user_diag', 8, 52,
                  ['pid', 'status', 'pc', 'lr', 'sp', 'fp', 'frames', 'walk_error'] +
                  ['lr'+str(n) for n in range(8)] + ['error_pointer', 'copy_error', 'role', 'stage']),
    'lifecycle': ('_i9100_mdns_lifecycle_diag', 8, 9,
                  ['pid', 'role', 'wait_status', 'task', 'own_context', 'exception', 'code', 'subcode', 'stage']),
    'sandbox': ('_i9100_mdns_sandbox_diag', 8, 5,
                ['pid', 'operation', 'original_error', 'providers', 'stage']),
    'tcc': ('_i9100_tcc_development_diag', 16, 7,
            ['pid', 'operation', 'original_error', 'result', 'providers', 'unconfined', 'stage']),
}


def decode_table(data, cap, stride, fields):
    words = struct.unpack('<'+str(1+cap*stride)+'I', data)
    if words[0] > cap:
        raise ValueError('Counter exceeds the matching kernel layout')
    rows = []
    for n in range(words[0]):
        values = words[1+n*stride:1+(n+1)*stride]
        row = dict(zip(fields, values))
        if stride == 52:
            row['error_text'] = data[(1+n*stride+20)*4:(1+n*stride+52)*4].split(b'\0')[0].decode('utf-8', 'replace')
        rows.append(row)
    return dict(count=words[0], rows=rows)


def main():
    here = Path(__file__).resolve().parent
    f = module('forensic', here/'forensic-session.py')
    m = module('memory', here/'live-memory.py')
    odin = module('odin', here/'odin-loop.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    symbols = m.Symbols(a.kernel)
    for symbol, _, _, _ in TABLES.values():
        symbols[symbol]
    symbols['_i9100_mdns_stderr_diag']
    out = a.output.resolve()
    if out.exists() or not out.is_relative_to(f.REPO/'out'):
        parser.error('Fresh directory inside loader out required')
    with odin.host_lock():
        device = odin.cdc(odin.Host().inventory())
        profile = json.loads((f.REPO/'out/automation/inventory-20261108-recovery-download.json').read_text(encoding='utf-8'))
        if device is None or odin.normalize_location(device['location']) != profile['location']:
            raise RuntimeError('Approved live device absent')
        out.mkdir(parents=True)
        transport = None
        with (out/'events.jsonl').open('x') as events, (out/'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row)+'\n'); events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'STOP', 'DONE', 'CLOSED'):
                    print(json.dumps(row), flush=True)
            try:
                transport = f.WinTransport(device['port'], record)
                session = f.Session(transport, symbols.tag, record, capture, timeout=20)
                session.handshake()
                kernel = m.Kernel(session, symbols)
                result = dict(tag=symbols.tag, device=device, tables={})
                for name, (symbol, cap, stride, fields) in TABLES.items():
                    data = kernel.read(symbols[symbol], (1+cap*stride)*4)
                    (out/(name+'.bin')).write_bytes(data)
                    result['tables'][name] = decode_table(data, cap, stride, fields)
                    table = result['tables'][name]
                    preview = table if table['count'] <= 8 else dict(count=table['count'],
                        first=table['rows'][:3], last=table['rows'][-3:])
                    print(name, json.dumps(preview), flush=True)
                data = kernel.read(symbols['_i9100_mdns_stderr_diag'], (6+128)*4)
                (out/'stderr.bin').write_bytes(data)
                sequence, pid, task, role, used, error = struct.unpack_from('<6I', data)
                if used > 511:
                    raise ValueError('Invalid stderr length')
                result['stderr'] = dict(sequence=sequence, pid=pid, task=hex(task), role=role,
                    used=used, copy_error=error, text=data[24:24+used].decode('utf-8', 'replace'))
                print('stderr', json.dumps(result['stderr']), flush=True)
                for process in ('mDNSResponder', 'mDNSResponderHel', 'launchd', 'configd', 'SpringBoard'):
                    _, data = session.command('threads '+process)
                    (out/(process+'-threads.txt')).write_bytes(data)
                (out/'results.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
                record('DONE')
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()


if __name__ == '__main__':
    main()
