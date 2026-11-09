#!/usr/bin/env python3
"""One CDC handle, one attempt per command, exact bounded DATA framing.

Uses rawcom's mutex, DTR handshake and GetTickCount64 sequence source. Output
stays in this repository's out directory. Importing this module opens no device.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import time

REPO = Path(__file__).resolve().parents[2]
MAX_DATA = 32768


class ProtocolError(RuntimeError):
    pass


def validate_command(verb, allow_reboot_download=False):
    if verb == 'reboot-download' and allow_reboot_download:
        return None
    if verb in ('ping', 'status', 'root-status'):
        return None
    if re.fullmatch(r'(threads|ports)( [A-Za-z0-9_.-]{1,32})?', verb):
        return None
    match = re.fullmatch(r'read-memory ([0-9a-fA-F]{8}) ([0-9a-fA-F]{1,8})', verb)
    if match:
        addr, size = (int(x, 16) for x in match.groups())
        if 0x40000000 <= addr < 0x80000000 and 0 < size <= MAX_DATA and addr + size <= 0x80000000:
            return addr, size
    raise ValueError('Only ping/status/root-status, threads/ports, or bounded DRAM reads are accepted')


class Receiver:
    """Framing policy; payload bytes never pass through the text-line parser."""
    def __init__(self, expected_tag, allow_reboot_download=False):
        if not re.fullmatch(r'[0-9a-f]{16}', expected_tag):
            raise ValueError('Expected a 16-hex kernel build tag')
        self.expected_tag = expected_tag
        self.allow_reboot_download = bool(allow_reboot_download)
        self.ready = self.tag_seen = False
        self.line = bytearray()
        self.drop = False
        self.seq = None
        self.verb = None
        self.reply = None
        self.payload = bytearray()
        self.remaining = 0
        self.complete = False

    def start(self, seq, verb):
        validate_command(verb, self.allow_reboot_download)
        if not 0 < seq <= 0xffffffff:
            raise ValueError('Invalid sequence')
        self.seq, self.verb = seq, verb
        self.reply = None
        self.payload.clear()
        self.remaining = 0
        self.complete = False
        return f'I9CTL1 {seq:08x} {verb}\n'.encode('ascii')

    def _line(self, raw):
        if raw == b'I9CTL1 READY control=0':
            raise ProtocolError('Kernel maintenance is disabled')
        if raw == b'I9CTL1 READY control=1':
            self.ready = True
            return
        if raw.startswith(b'I9CTL1 BUILD '):
            tag = raw[13:].decode('ascii', 'strict')
            if tag != self.expected_tag:
                raise ProtocolError(f'Wrong build tag: {tag}')
            self.tag_seen = True
            return
        if self.seq is None or self.complete:
            return
        prefix = f'I9CTL1 {self.seq:08x} '.encode('ascii')
        if not raw.startswith(prefix):
            return
        answer = raw[len(prefix):].decode('ascii', 'strict')
        if answer.startswith('ERR '):
            raise ProtocolError(answer)
        self.reply = answer
        data = re.fullmatch(r'OK DATA ([0-9a-f]{8}) ([0-9a-f]{8})', answer)
        if data:
            addr, size = (int(x, 16) for x in data.groups())
            if size > MAX_DATA:
                raise ProtocolError('DATA length exceeds staging buffer')
            requested = validate_command(self.verb, self.allow_reboot_download)
            if requested is not None and (addr, size) != requested:
                raise ProtocolError('DATA address/length does not match request')
            if self.verb in ('ping', 'status', 'root-status', 'reboot-download'):
                raise ProtocolError('Unexpected DATA for scalar query')
            self.remaining = size
            self.complete = size == 0
        elif self.verb in ('ping', 'status') and answer == 'OK control=1':
            self.complete = True
        elif self.verb == 'root-status' and answer in ('OK root=BOOTING', 'OK root=WAIT_ROOT', 'OK root=NO_ROOT', 'OK root=MEDIA_FOUND'):
            self.complete = True
        elif self.verb == 'reboot-download' and answer == 'OK reboot-download':
            self.complete = True
        else:
            raise ProtocolError(f'Unexpected reply: {answer}')

    def feed(self, chunk):
        pos = 0
        while pos < len(chunk):
            if self.remaining:
                take = min(self.remaining, len(chunk) - pos)
                self.payload.extend(chunk[pos:pos + take])
                self.remaining -= take
                pos += take
                if not self.remaining:
                    self.complete = True
                continue
            char = chunk[pos]
            pos += 1
            if char == 10:
                raw = bytes(self.line).rstrip(b'\r')
                self.line.clear()
                drop, self.drop = self.drop, False
                if not drop:
                    self._line(raw)
            elif len(self.line) == 255 or (char != 13 and not 32 <= char < 127):
                self.drop = True
            elif not self.drop:
                self.line.append(char)


class Session:
    def __init__(self, transport, expected_tag, record, capture, timeout=15, clock=time.monotonic, sleep=time.sleep,
                 allow_reboot_download=False):
        self.transport = transport
        self.receiver = Receiver(expected_tag, allow_reboot_download)
        self.record, self.capture, self.timeout = record, capture, timeout
        self.clock, self.sleep = clock, sleep
        self.seq = 0
        self.reboot_requested = False

    def _wait(self, predicate, label):
        deadline = self.clock() + self.timeout
        while not predicate():
            if self.clock() >= deadline:
                raise TimeoutError(f'{label} timed out; no retry')
            chunk = self.transport.read()
            if chunk:
                self.capture.write(chunk)
                self.capture.flush()
                self.receiver.feed(chunk)

    def handshake(self):
        self._wait(lambda: self.receiver.ready and self.receiver.tag_seen, 'READY/BUILD')
        self.record('IDENTITY_OK', tag=self.receiver.expected_tag)
        self.command('ping')

    def command(self, verb):
        if self.reboot_requested:
            raise ProtocolError('Download reboot is terminal for this handle; no further command')
        if verb == 'reboot-download' and not (self.receiver.ready and self.receiver.tag_seen):
            raise ProtocolError('Download reboot needs the verified READY/BUILD handshake')
        validate_command(verb, self.receiver.allow_reboot_download)
        # A host ReadFile completion can precede the kernel's next 10ms poll
        # that clears uctl_flight. Allow that completion before another write.
        self.sleep(0.075)
        self.seq = max(self.seq + 1, self.transport.ticks() & 0xffffffff)
        if not 0 < self.seq < 0xffffffff:
            raise ProtocolError('Sequence source wrapped; stop this session')
        wire = self.receiver.start(self.seq, verb)
        if verb == 'reboot-download':
            self.reboot_requested = True
        self.record('SEND', sequence=self.seq, command=verb, bytes=len(wire))
        self.transport.write(wire)
        self._wait(lambda: self.receiver.complete, verb)
        payload = bytes(self.receiver.payload)
        self.record('REPLY', sequence=self.seq, command=verb, reply=self.receiver.reply,
                    bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        return self.receiver.reply, payload


class WinTransport:
    def __init__(self, port, record):
        if os.name != 'nt' or not re.fullmatch(r'COM[0-9]+', port):
            raise ValueError('Windows COM port required')
        import ctypes
        from ctypes import wintypes as W
        self.c, self.W = ctypes, W
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        k = self.k
        k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, ctypes.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
        k.CreateFileW.restype = W.HANDLE
        k.CreateMutexW.argtypes = [ctypes.c_void_p, W.BOOL, W.LPCWSTR]
        k.CreateMutexW.restype = W.HANDLE
        k.CloseHandle.argtypes = [W.HANDLE]
        k.SetCommTimeouts.argtypes = [W.HANDLE, ctypes.c_void_p]
        k.EscapeCommFunction.argtypes = [W.HANDLE, W.DWORD]
        k.GetTickCount64.restype = ctypes.c_ulonglong
        k.ReadFile.argtypes = [W.HANDLE, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD), ctypes.c_void_p]
        k.WriteFile.argtypes = k.ReadFile.argtypes
        self.lock = k.CreateMutexW(None, True, 'Local\\I9100OneShotRawReader')
        self.h = None
        if not self.lock or ctypes.get_last_error() == 183:
            if self.lock:
                k.CloseHandle(self.lock)
            self.lock = None
            raise RuntimeError('Another rawcom/forensic opener exists')
        try:
            record('OPEN_BEGIN', port=port)
            self.h = k.CreateFileW('\\\\.\\' + port, 0xc0000000, 0, None, 3, 0, None)
            if self.h == ctypes.c_void_p(-1).value:
                self.h = None
                raise ctypes.WinError(ctypes.get_last_error())
            record('OPEN_OK', port=port)
            class Timeouts(ctypes.Structure):
                _fields_ = [('interval', W.DWORD), ('multiplier', W.DWORD), ('constant', W.DWORD),
                            ('write_multiplier', W.DWORD), ('write_constant', W.DWORD)]
            t = Timeouts(0, 0, 250, 0, 1000)
            if not k.SetCommTimeouts(self.h, ctypes.byref(t)):
                raise ctypes.WinError(ctypes.get_last_error())
            record('DTR_BEGIN')
            if not k.EscapeCommFunction(self.h, 5):
                raise ctypes.WinError(ctypes.get_last_error())
            record('DTR_OK')
        except BaseException:
            self.close()
            raise

    def ticks(self):
        return self.k.GetTickCount64()

    def read(self):
        buf = self.c.create_string_buffer(4096)
        count = self.W.DWORD()
        if not self.k.ReadFile(self.h, buf, len(buf), self.c.byref(count), None):
            raise self.c.WinError(self.c.get_last_error())
        return buf.raw[:count.value]

    def write(self, data):
        buf = self.c.create_string_buffer(data)
        count = self.W.DWORD()
        if not self.k.WriteFile(self.h, buf, len(data), self.c.byref(count), None) or count.value != len(data):
            raise RuntimeError(f'WriteFile failed/partial ({count.value}/{len(data)}), error {self.c.get_last_error()}; no retry')

    def close(self):
        if self.h is not None:
            self.k.CloseHandle(self.h)
            self.h = None
        if self.lock is not None:
            self.k.CloseHandle(self.lock)
            self.lock = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, choices=range(5, 61), default=20)
    parser.add_argument('--command', action='append', required=True)
    parser.add_argument('--reboot-download', action='store_true',
                        help='After the queries, send one download reboot on the same validated handle')
    args = parser.parse_args()
    for verb in args.command:
        validate_command(verb)
    if args.reboot_download:
        args.command.append('reboot-download')
    Receiver(args.expect)
    output = args.output.resolve()
    if not output.is_relative_to(REPO / 'out') or output.exists():
        parser.error('Use a new output directory within this repository out')
    spec = importlib.util.spec_from_file_location('odin', Path(__file__).with_name('odin-loop.py'))
    odin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(odin)
    with odin.host_lock():
        device = odin.cdc(odin.Host().inventory())
        if device is None:
            raise RuntimeError('Expected a healthy i9100 CDC device')
        profile_path = REPO / 'out/automation/inventory-20261108-recovery-download.json'
        profile = json.loads(profile_path.read_text())
        if odin.normalize_location(device['location']) != profile['location']:
            raise RuntimeError('Device moved away from the approved USB port')
        output.mkdir(parents=True)
        transport = None
        with (output / 'events.jsonl').open('x', encoding='utf-8') as events, (output / 'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                print(json.dumps(row), flush=True)
            record('BEGIN', pid=os.getpid(), device=device, expected_tag=args.expect)
            try:
                transport = WinTransport(device['port'], record)
                session = Session(transport, args.expect, record, capture, args.timeout,
                                  allow_reboot_download=args.reboot_download)
                session.handshake()
                for number, verb in enumerate(args.command, 1):
                    answer, payload = session.command(verb)
                    label = re.sub('[^a-zA-Z0-9_.-]+', '-', verb)
                    (output / f'{number:02}-{label}.data').write_bytes(payload)
                    (output / f'{number:02}-{label}.json').write_text(json.dumps(dict(command=verb,reply=answer,bytes=len(payload)), indent=2)+'\n')
                record('DONE')
            except BaseException as exc:
                if 'session' in locals() and session.receiver.payload:
                    (output / 'incomplete-data.partial').write_bytes(session.receiver.payload)
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()
                record('CLOSED')


if __name__ == '__main__':
    main()
