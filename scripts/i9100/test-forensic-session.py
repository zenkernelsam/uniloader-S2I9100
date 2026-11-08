#!/usr/bin/env python3
"""Offline framing/one-attempt regression; no imports open devices."""
import importlib.util
import io
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('forensic',Path(__file__).with_name('forensic-session.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
TAG='a6b766259c1f31fa'


class Tests(unittest.TestCase):
    def test_identity_fragmentation(self):
        data=b'log\r\n\nI9CTL1 READY control=1\nI9CTL1 BUILD '+TAG.encode()+b'\n'
        for n in (1,2,7,13,4096):
            r=f.Receiver(TAG)
            for i in range(0,len(data),n):r.feed(data[i:i+n])
            self.assertTrue(r.ready and r.tag_seen)

    def test_wrong_identity_rejects(self):
        r=f.Receiver(TAG)
        with self.assertRaises(f.ProtocolError):r.feed(b'I9CTL1 BUILD 0000000000000000\n')
        with self.assertRaises(f.ProtocolError):r.feed(b'I9CTL1 READY control=0\n')

    def test_exact_binary_payload_and_tail(self):
        payload=bytes(range(256))*128
        for n in (1,3,511,4096):
            r=f.Receiver(TAG);r.start(3,'read-memory 43e00000 8000')
            data=b'noise\nI9CTL1 00000002 ERR stale\nI9CTL1 00000003 OK DATA 43e00000 00008000\n'+payload+b'console tail\n'
            for i in range(0,len(data),n):r.feed(data[i:i+n])
            self.assertTrue(r.complete);self.assertEqual(bytes(r.payload),payload)

    def test_payload_text_cannot_inject_identity(self):
        payload=b'\nI9CTL1 BUILD 0000000000000000\nI9CTL1 00000005 ERR sequence\n'
        r=f.Receiver(TAG);r.start(5,'threads')
        r.feed(f'I9CTL1 00000005 OK DATA 00000000 {len(payload):08x}\n'.encode()+payload)
        self.assertTrue(r.complete);self.assertEqual(bytes(r.payload),payload)

    def test_data_bounds_and_request_match(self):
        for header in ('43e00000 00008001','43e00001 00000004','43e00000 00000008'):
            r=f.Receiver(TAG);r.start(9,'read-memory 43e00000 4')
            with self.assertRaises(f.ProtocolError):r.feed(f'I9CTL1 00000009 OK DATA {header}\n'.encode())

    def test_truncated_data_stays_incomplete(self):
        r=f.Receiver(TAG);r.start(1,'ports backboardd')
        r.feed(b'I9CTL1 00000001 OK DATA 00000000 00000008\nabc')
        self.assertFalse(r.complete);self.assertEqual(r.remaining,5)

    def test_overlong_log_resynchronizes(self):
        r=f.Receiver(TAG);r.start(1,'root-status')
        r.feed(b'x'*5000+b'\nI9CTL1 00000001 OK root=MEDIA_FOUND\n')
        self.assertTrue(r.complete);self.assertLessEqual(len(r.line),255)

    def test_no_write_or_reboot_verbs(self):
        for verb in ('reboot','reboot-download','write-memory 43e00000 4','read-memory 3fffffff 4','read-memory 7fffffff 2','read-memory 43e00000 8001','threads\nreboot'):
            with self.assertRaises(ValueError):f.validate_command(verb)

    def test_error_is_terminal(self):
        for error in ('sequence','busy','disabled'):
            r=f.Receiver(TAG);r.start(1,'threads')
            with self.assertRaises(f.ProtocolError):r.feed(f'I9CTL1 00000001 ERR {error}\n'.encode())

    def test_one_attempt_and_tick_sequence(self):
        class T:
            def __init__(self):self.writes=[];self.pending=[]
            def ticks(self):return 240000000
            def write(self,data):
                self.writes.append(data);seq=data.split()[1]
                self.pending.append(b'I9CTL1 '+seq+b' OK control=1\n')
            def read(self):return self.pending.pop(0)
        t=T();s=f.Session(t,TAG,lambda *a,**k:None,io.BytesIO(),sleep=lambda _:None)
        s.command('ping');s.command('status')
        self.assertEqual(len(t.writes),2)
        self.assertEqual(t.writes[0].split()[1],b'0e4e1c00')
        self.assertEqual(int(t.writes[1].split()[1],16),240000001)

    def test_timeout_never_resends(self):
        class T:
            writes=[]
            def ticks(self):return 1000
            def write(self,data):self.writes.append(data)
            def read(self):return b''
        now=iter([0,1,2,3,4]);t=T()
        s=f.Session(t,TAG,lambda *a,**k:None,io.BytesIO(),timeout=2,clock=lambda:next(now),sleep=lambda _:None)
        with self.assertRaises(TimeoutError):s.command('threads')
        self.assertEqual(len(t.writes),1)


if __name__=='__main__':unittest.main()
