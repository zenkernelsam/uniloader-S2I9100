#!/usr/bin/env python3
"""I9CTL1 client over raw CreateFile (no DCB reconfigure - like rawcom).

Usage: i9ctl.py COM12 <verb...> [--data-out FILE] [--timeout N]
"""
import sys, re, time, ctypes
from ctypes import wintypes as W

k32 = ctypes.windll.kernel32
GENERIC_RW = 0xC0000000
OPEN_EXISTING = 3
INVALID = ctypes.c_void_p(-1).value

class COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [("ReadIntervalTimeout", W.DWORD),
                ("ReadTotalTimeoutMultiplier", W.DWORD),
                ("ReadTotalTimeoutConstant", W.DWORD),
                ("WriteTotalTimeoutMultiplier", W.DWORD),
                ("WriteTotalTimeoutConstant", W.DWORD)]

def main():
    args = sys.argv[1:]
    port = args[0]
    data_out, timeout = None, 30
    if "--data-out" in args:
        i = args.index("--data-out"); data_out = args[i+1]; del args[i:i+2]
    if "--timeout" in args:
        i = args.index("--timeout"); timeout = int(args[i+1]); del args[i:i+2]
    verb = " ".join(args[1:])
    seq = int(time.time()) & 0x7fffffff
    h = k32.CreateFileW("\\\\.\\" + port, GENERIC_RW, 0, None, OPEN_EXISTING, 0, None)
    if h == INVALID:
        sys.stderr.write("OPEN_ERROR %d\n" % ctypes.GetLastError()); return
    k32.EscapeCommFunction(h, 5)  # SETDTR: keep the device from canceling
    k32.EscapeCommFunction(h, 3)  # SETRTS
    t = COMMTIMEOUTS(0, 0, 250, 0, 1000)
    k32.SetCommTimeouts(h, ctypes.byref(t))
    buf = b""; payload = b""
    got_header = False; data_len = None
    chunk = ctypes.create_string_buffer(4096)
    last_send = 0.0
    mark = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not got_header and time.time() - last_send > 3.0:
            last_send = time.time()
            seq += 1
            line = ("I9CTL1 %08x %s\n" % (seq, verb)).encode()
            wn = W.DWORD()
            k32.WriteFile(h, line, len(line), ctypes.byref(wn), None)
            mark = ("\nI9CTL1 %08x " % seq).encode()
        n = W.DWORD()
        if not k32.ReadFile(h, chunk, 4096, ctypes.byref(n), None):
            sys.stderr.write("READ_ERROR %d\n" % ctypes.GetLastError()); break
        if not n.value:
            continue
        buf += chunk.raw[:n.value]
        if not got_header:
            if not mark:
                continue
            i = buf.rfind(mark)
            if i < 0:
                if len(buf) > 65536:
                    buf = buf[-4096:]
                continue
            eol = buf.find(b"\n", i + len(mark))
            if eol < 0:
                continue
            reply = buf[i + len(mark):eol]
            sys.stderr.write("REPLY %s\n" % reply.decode(errors="replace"))
            got_header = True
            m = re.match(rb"OK DATA ([0-9a-f]{8}) ([0-9a-f]{8})", reply)
            if m:
                data_len = int(m.group(2), 16)
                buf = buf[eol + 1:]
                deadline = time.time() + timeout  # payload gets a fresh budget
            elif reply.startswith(b"ERR busy"):
                got_header = False  # a resend raced an in-flight DATA stream
                buf = buf[eol + 1:]
                continue
            else:
                break
        else:
            take = min(len(buf), data_len - len(payload))
            payload += buf[:take]
            buf = buf[take:]
            if len(payload) >= data_len:
                break
    if data_out is not None:
        open(data_out, "wb").write(payload)
        sys.stderr.write("WROTE %d bytes -> %s\n" % (len(payload), data_out))
    elif buf:
        sys.stdout.write(buf.decode(errors="replace"))
    k32.CloseHandle(h)

if __name__ == "__main__":
    main()
