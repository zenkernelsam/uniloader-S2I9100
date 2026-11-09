#!/usr/bin/env python3
"""Save a verified panic snapshot and observe the automatic Download route.

No flash, driver changes, forced process exit, command resends, or opener
retries. --trigger explicitly requests one qualification-only panic; its
acknowledged healthy handle is closed before the new panic USB session opens.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FIELDS = ('magic', 'version', 'used', 'dropped', 'history_bytes', 'category',
          'callsite', 'pc', 'lr', 'far', 'fsr', 'cpsr', 'reset_seconds',
          'elapsed_seconds', 'ticks_low', 'ticks_high')


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


f = module('panic_forensic', 'forensic-session.py')
odin = module('panic_odin', 'odin-loop.py')


def decode_snapshot(payload):
    if not 64 <= len(payload) <= 64 + 28672:
        raise ValueError('Panic snapshot length is outside the bounded format')
    header = dict(zip(FIELDS, struct.unpack_from('<16I', payload)))
    if header['magic'] != 0x39504c47 or header['version'] != 1:
        raise ValueError('Unknown panic snapshot format')
    if len(payload) != 64 + header['used'] or header['history_bytes'] > min(8192, header['used']):
        raise ValueError('Panic snapshot body/history length mismatch')
    if header['reset_seconds'] not in (0, 180) or header['elapsed_seconds'] > header['reset_seconds']:
        raise ValueError('Invalid panic snapshot countdown')
    header['ticks'] = header['ticks_low'] | (header['ticks_high'] << 32)
    return header, payload[64:]


def countdown(answer):
    match = re.fullmatch(r'OK panic=([01]) seconds=([0-9a-f]{8})', answer)
    if not match:
        raise ValueError('Missing exact panic-status reply')
    active, seconds = int(match[1]), int(match[2], 16)
    if seconds > 180 or (not active and seconds):
        raise ValueError('Invalid panic-status countdown')
    return active, seconds


def healthy_cdc(devices, profile):
    matches = [d for d in devices if d['instance'].upper() == odin.CDC]
    odin.require(len(matches) <= 1, 'Ambiguous i9100 CDC device')
    if not matches or matches[0]['status'] != 'OK':
        return None
    device = odin.cdc(devices)
    odin.require(device['service'].lower() == 'usbser' and
                 odin.normalize_location(device['location']) == profile['location'],
                 'CDC identity/driver/topology changed')
    return device


@contextmanager
def serial_session(directory, device, tag, record, trigger=False):
    directory.mkdir()
    transport = None
    with (directory / 'received.bin').open('xb') as capture:
        try:
            transport = f.WinTransport(device['port'], record)
            session = f.Session(transport, tag, record, capture, timeout=25,
                                allow_panic_test=trigger)
            session.handshake()
            yield session
        except BaseException:
            if 'session' in locals() and session.receiver.payload:
                (directory / 'incomplete-data.partial').write_bytes(session.receiver.payload)
            raise
        finally:
            if transport is not None:
                transport.close()
            capture.flush()
            os.fsync(capture.fileno())
            record('SERIAL_CLOSED', directory=str(directory))


def collect(session, output, record):
    answer, _ = session.command('panic-status')
    active, remaining = countdown(answer)
    odin.require(active == 1 and remaining > 0, 'Expected a retained, timed panic')
    _, payload = session.command('panic-log')
    observed = time.monotonic()
    # Preserve even a malformed/truncated kernel record before interpreting it.
    (output / 'panic-log.bin').write_bytes(payload)
    header, text = decode_snapshot(payload)
    (output / 'panic-log.txt').write_text(text.decode('utf-8', 'replace'), encoding='utf-8')
    digest = hashlib.sha256(payload).hexdigest()
    odin.save(output / 'panic-log.json', dict(**header, sha256=digest,
              text_sha256=hashlib.sha256(text).hexdigest(), build=session.receiver.expected_tag))
    record('PANIC_LOG_SAVED', bytes=len(payload), sha256=digest, **header)
    odin.require(header['reset_seconds'] == 180 and header['dropped'] == 0,
                 'Panic snapshot is truncated or automatic recovery is disabled')
    odin.require(b'I9100 PANIC_WAIT seconds=180 route=DOWNLOAD' in text,
                 'Panic formatting has not completed; snapshot is preserved, stop')
    # Sample once more on the same handle, proving the hardware counter moves
    # while the kernel scheduler and interrupts are stopped.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        chunk = session.transport.read()
        if chunk:
            session.capture.write(chunk)
            session.capture.flush()
            session.receiver.feed(chunk)
    second, _ = session.command('panic-status')
    active2, remaining2 = countdown(second)
    odin.require(active2 == 1 and 0 < remaining2 < remaining,
                 'Panic countdown did not advance')
    record('PANIC_COUNTDOWN_ADVANCED', first_seconds=remaining, second_seconds=remaining2)
    return header, observed, digest


def run(plan, output, trigger, record):
    profile = plan.data['profile']
    odin.require(profile is not None, 'An approved Download profile is required')
    image = (plan.parent / 'zImage').read_bytes()
    odin.require(b'i9100panicrecovery=1' in image, 'This plan does not enable panic recovery')
    if trigger:
        odin.require(b'i9100panictest=1' in image, 'This plan does not enable the qualification command')
    host = odin.Host()
    device = healthy_cdc(host.inventory(), profile)
    odin.require(device is not None, 'Expected a healthy CDC device, not cached COM metadata')
    origin = None
    with serial_session(output / 'initial', device, plan.data['control_tag'], record, trigger) as session:
        answer, _ = session.command('panic-status')
        active, _ = countdown(answer)
        if trigger:
            odin.require(active == 0, 'Kernel has already panicked; use a new collect-only run')
            _, threads = session.command('threads SpringBoard')
            (output / 'threads-before-panic.txt').write_bytes(threads)
            springboard_seen = bool(threads)
            if not threads:
                # Recovery also has to work during early userspace startup.
                # An empty, successful query is not a failed command retry.
                _, threads = session.command('threads')
                (output / 'threads-all-before-panic.txt').write_bytes(threads)
            odin.require(b'snapshot=raw-irq' in threads, 'Missing real interrupt-safe thread snapshot')
            record('THREAD_SNAPSHOT_VERIFIED', bytes=len(threads), springboard_seen=springboard_seen)
            session.command('root-status')
            origin = time.monotonic()
            session.command('panic-test')
            record('CONTROLLED_PANIC_ACK')
        else:
            odin.require(active == 1, 'Kernel is running normally; no panic was triggered')
            header, observed, digest = collect(session, output, record)
    if trigger:
        # The panic handler discards the old conversation and resets DWC2.
        # PnP waiting opens nothing; only one new, verified panic opener follows.
        time.sleep(2)
        deadline = origin + 45
        while True:
            devices = host.inventory()
            odin.require(not odin.samsung(devices), 'Download arrived before panic log collection')
            device = healthy_cdc(devices, profile)
            if device is not None:
                break
            odin.require(time.monotonic() < deadline, 'Panic CDC enumeration timed out; no opener retry')
            time.sleep(1)
        with serial_session(output / 'panic', device, plan.data['control_tag'], record) as session:
            header, observed, digest = collect(session, output, record)
        text = (output / 'panic-log.txt').read_text(encoding='utf-8')
        odin.require('I9100 controlled panic:' in text and header['category'] == 0xf101,
                     'Saved log does not match the controlled panic')
    estimated_start = origin if trigger else observed - header['elapsed_seconds']
    deadline = estimated_start + 240
    report_at = 0
    while True:
        devices = host.inventory()
        now = time.monotonic()
        if odin.samsung(devices):
            actual = odin.download(devices, profile)
            duration = now - estimated_start
            odin.save(output / 'observed-download.json', actual)
            record('DOWNLOAD_OBSERVED', seconds_since_panic=round(duration, 3), profile=actual)
            odin.require(175 <= duration <= 210, 'Download timing is outside the three-minute window')
            result = dict(controlled_trigger=trigger, build=plan.data['control_tag'],
                          plan_sha256=odin.sha(plan.path), panic_log_sha256=digest,
                          panic_header=header, seconds_since_panic=round(duration, 3),
                          download=actual, flash_writes=0,
                          meaning='Complete retained history/panic snapshot, advancing countdown, '
                                  'and automatic Download identity observed on hardware')
            odin.save(output / 'result.json', result)
            record('DONE_PANIC_RECOVERY', **result)
            return
        odin.require(now < deadline, 'Timed panic did not reach Download; no flash or retry')
        if now >= report_at:
            record('WAIT_AUTOMATIC_DOWNLOAD', elapsed_seconds=round(now-estimated_start, 1))
            report_at = now + 30
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--approve-plan', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trigger', action='store_true', help='One explicit controlled-panic qualification')
    args = parser.parse_args()
    plan = odin.Plan(args.plan, args.approve_plan)
    output = odin.confined(args.output, REPO / 'out')
    odin.require(not output.exists(), 'Use a new evidence directory; completed runs are never overwritten')
    with odin.host_lock(), odin.immutable_snapshots(plan):
        output.mkdir(parents=True)
        with (output / 'events.jsonl').open('x', encoding='utf-8') as events:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row, ensure_ascii=False) + '\n')
                events.flush()
                print(json.dumps(row, ensure_ascii=False), flush=True)
            record('BEGIN', pid=os.getpid(), trigger=args.trigger, plan=str(plan.path))
            try:
                run(plan, output, args.trigger, record)
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False, flash_writes=0)
                raise
            finally:
                record('CLOSED')


if __name__ == '__main__':
    main()
