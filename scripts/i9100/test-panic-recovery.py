#!/usr/bin/env python3
"""Offline panic envelope/countdown checks; no device is opened."""
import importlib.util
import io
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('panic_recovery', Path(__file__).with_name('panic-recovery.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
TAG = 'a6b766259c1f31fa'


def snapshot(text=b'recent log\npanic\n', **changes):
    values = dict(zip(p.FIELDS, [0x39504c47, 1, len(text), 0, 5, 0xf101,
                              0x80350000, 0, 0, 0, 0, 0xd3, 180, 5, 123, 1]))
    values.update(changes)
    return struct.pack('<16I', *(values[k] for k in p.FIELDS)) + text


class Tests(unittest.TestCase):
    def test_snapshot_lengths_and_real_counter(self):
        header, text = p.decode_snapshot(snapshot())
        self.assertEqual(header['ticks'], 0x10000007b)
        self.assertEqual(text, b'recent log\npanic\n')
        for data in (b'', b'x'*63, snapshot()[:-1], snapshot()+b'x',
                     snapshot(magic=0), snapshot(version=2), snapshot(used=0),
                     snapshot(history_bytes=8193), snapshot(reset_seconds=179),
                     snapshot(elapsed_seconds=181), b'x'*(64+28673)):
            with self.assertRaises(ValueError):
                p.decode_snapshot(data)

    def test_overflow_remains_explicit_evidence(self):
        header, _ = p.decode_snapshot(snapshot(dropped=123))
        self.assertEqual(header['dropped'], 123)

    def test_fragmented_binary_cannot_inject_reply(self):
        data = snapshot(b'\nI9CTL1 BUILD 0000000000000000\n'+bytes(range(256)))
        for size in (1, 7, 64, 511, 4096):
            r = p.f.Receiver(TAG)
            r.start(5, 'panic-log')
            wire = f'I9CTL1 00000005 OK DATA 00000000 {len(data):08x}\n'.encode()+data
            for at in range(0, len(wire), size):
                r.feed(wire[at:at+size])
            self.assertTrue(r.complete)
            self.assertEqual(bytes(r.payload), data)

    def test_panic_header_only_and_bad_envelope(self):
        for address, size in ((1, 64), (0, 63), (0, 64+28673)):
            r = p.f.Receiver(TAG)
            r.start(1, 'panic-log')
            with self.assertRaises(p.f.ProtocolError):
                r.feed(f'I9CTL1 00000001 OK DATA {address:08x} {size:08x}\n'.encode())

    def test_status_is_strict_and_scalar(self):
        for answer in ('OK panic=0 seconds=00000000', 'OK panic=1 seconds=000000b4'):
            r = p.f.Receiver(TAG)
            r.start(1, 'panic-status')
            r.feed(f'I9CTL1 00000001 {answer}\n'.encode())
            self.assertTrue(r.complete)
        for answer in ('OK panic=1 seconds=000000b5', 'OK panic=0 seconds=00000001',
                       'OK panic=2 seconds=00000000', 'OK DATA 00000000 00000040'):
            r = p.f.Receiver(TAG)
            r.start(1, 'panic-status')
            with self.assertRaises(p.f.ProtocolError):
                r.feed(f'I9CTL1 00000001 {answer}\n'.encode())

    def test_trigger_requires_opt_in_and_verified_identity(self):
        with self.assertRaises(ValueError):
            p.f.validate_command('panic-test')
        self.assertIsNone(p.f.validate_command('panic-test', allow_panic_test=True))
        class Transport:
            def __init__(self):
                self.writes = []
                self.pending = [b'I9CTL1 READY control=1\nI9CTL1 BUILD '+TAG.encode()+b'\n']
            def ticks(self):
                return 1000
            def write(self, data):
                self.writes.append(data)
                seq = data.split()[1]
                answer = b'OK panic-test' if b'panic-test' in data else b'OK control=1'
                self.pending.append(b'I9CTL1 '+seq+b' '+answer+b'\n')
            def read(self):
                return self.pending.pop(0)
        transport = Transport()
        session = p.f.Session(transport, TAG, lambda *a, **k: None, io.BytesIO(),
                              sleep=lambda _: None, allow_panic_test=True)
        with self.assertRaises(p.f.ProtocolError):
            session.command('panic-test')
        self.assertEqual(transport.writes, [])
        session.handshake()
        session.command('panic-test')
        with self.assertRaises(p.f.ProtocolError):
            session.command('ping')
        self.assertEqual([x.split()[2] for x in transport.writes], [b'ping', b'panic-test'])


if __name__ == '__main__':
    unittest.main()
