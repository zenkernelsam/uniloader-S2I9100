#!/usr/bin/env python3
"""One verified fresh CDC enumeration -> one handle -> immediate Download reboot.

Waits only through read-only PnP observations. No serial retries, forced process
termination, driver replacement or partition writes. Already-present Download
is validated against the approved profile and returned without opening COM.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import time


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    here = Path(__file__).resolve().parent
    f = module('forensic', here / 'forensic-session.py')
    odin = module('odin', here / 'odin-loop.py')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--expect', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--wait', type=int, choices=range(1, 1801), default=300)
    args = p.parse_args()
    f.Receiver(args.expect)
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to(f.REPO / 'out'):
        p.error('Fresh directory within this repository out required')
    profile = json.loads((f.REPO / 'out/automation/inventory-20261108-recovery-download.json').read_text())
    odin.validate_profile(profile)
    with odin.host_lock():
        out.mkdir(parents=True)
        transport = None
        with (out / 'events.jsonl').open('x') as events, (out / 'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                print(json.dumps(row), flush=True)
            record('BEGIN', pid=os.getpid(), expected_tag=args.expect, wait_seconds=args.wait)
            try:
                deadline = time.monotonic() + args.wait
                absent, previous = False, None
                host = odin.Host()
                while time.monotonic() < deadline:
                    devices = host.inventory()
                    if odin.samsung(devices):
                        observed = odin.download(devices, profile)
                        record('DONE_DOWNLOAD_PRESENT', profile=observed)
                        return
                    device = odin.cdc(devices)
                    if device is None:
                        absent = True
                    state = 'ABSENT' if device is None else 'FRESH_CDC' if absent else 'WAIT_FOR_DISCONNECT'
                    if state != previous:
                        record(state, device=device)
                        previous = state
                    if device is not None and absent:
                        if odin.normalize_location(device['location']) != profile['location']:
                            raise RuntimeError('Fresh CDC is on a different USB port')
                        transport = f.WinTransport(device['port'], record)
                        session = f.Session(transport, args.expect, record, capture, timeout=15,
                                            allow_reboot_download=True)
                        session.handshake()
                        session.command('reboot-download')
                        record('DONE_REBOOT_ACK', device=device)
                        return
                    time.sleep(1)
                record('WAIT_EXPIRED', serial_attempts=0)
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()
                record('CLOSED')


if __name__ == '__main__':
    main()
