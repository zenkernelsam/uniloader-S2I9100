#!/usr/bin/env python3
"""Fetch `i9ctl <verb>` DATA payloads over one persistent COM session.
Usage: i9fetch.py COM12 out1.bin "threads backboardd" [out2.bin "threads SpringBoard" ...]"""
import sys, time, ctypes
from ctypes import wintypes as W

PORT = sys.argv[1]
pairs = [(sys.argv[i], sys.argv[i + 1]) for i in range(2, len(sys.argv) - 1, 2)]

k32 = ctypes.windll.kernel32

class COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [("ReadIntervalTimeout", W.DWORD),
                ("ReadTotalTimeoutMultiplier", W.DWORD),
                ("ReadTotalTimeoutConstant", W.DWORD),
                ("WriteTotalTimeoutMultiplier", W.DWORD),
                ("WriteTotalTimeoutConstant", W.DWORD)]

h = k32.CreateFileW("\\\\.\\" + PORT, 0xC0000000, 0, None, 3, 0, None)
if h == ctypes.c_void_p(-1).value:
    sys.exit('open fail')
k32.EscapeCommFunction(h, 5)
k32.EscapeCommFunction(h, 3)
t = COMMTIMEOUTS(0, 0, 200, 0, 1000)
k32.SetCommTimeouts(h, ctypes.byref(t))

seq = int(time.time()) & 0x7fffffff
chunk = ctypes.create_string_buffer(8192)

def cmd(verb, deadline_s=90):
    global seq
    seq += 1
    mark = ("\nI9CTL1 %08x " % seq).encode()
    line = ("I9CTL1 %08x %s\n" % (seq, verb)).encode()
    k32.WriteFile(h, line, len(line), ctypes.byref(W.DWORD()), None)
    buf = b""; payload = b""; dlen = None; reply = b""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        n = W.DWORD()
        if not k32.ReadFile(h, chunk, 8192, ctypes.byref(n), None):
            break
        if not n.value:
            continue
        buf += chunk.raw[:n.value]
        if dlen is None:
            i = buf.rfind(mark)
            if i < 0:
                buf = buf[-8192:]
                continue
            eol = buf.find(b"\n", i + len(mark))
            if eol < 0:
                continue
            reply = buf[i + len(mark):eol]
            if reply.startswith(b"OK DATA "):
                try:
                    dlen = int(reply[17:25], 16)
                except ValueError:
                    return reply, b""
                buf = buf[eol + 1:]
            elif reply.startswith(b"ERR busy"):
                buf = buf[eol + 1:]
                continue
            else:
                return reply, b""
        else:
            take = min(len(buf), dlen - len(payload))
            payload += buf[:take]
            buf = buf[take:]
            if len(payload) >= dlen:
                return reply, payload
    return reply or b"TIMEOUT", payload

for out, verb in pairs:
    r, d = cmd(verb)
    sys.stderr.write('%s -> %r %dB\n' % (verb, r, len(d)))
    if d:
        open(out, 'wb').write(d)
