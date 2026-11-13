import ctypes, time, sys, struct, re
from ctypes import wintypes as W
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
h = k32.CreateFileW("\\\\.\\COM12", 0xC0000000, 0, None, 3, 0, None)
if h in (0, -1, W.HANDLE(-1).value):
    print("OPEN_ERROR"); sys.exit(1)
ct = bytes([0,0,0,0, 0,0,0,0, 250,0,0,0, 0,0,0,0, 232,3,0,0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))
seq = int(time.time()) & 0x7fffffff
pa = int(sys.argv[1], 16)
want = int(sys.argv[2], 0) if len(sys.argv) > 2 else 64
out = b""
while len(out) < want:
    n = min(want - len(out), 0x400)
    got = None
    for attempt in range(8):
        seq += 1
        mark = ("\nI9CTL1 %08x " % seq).encode()
        line = ("I9CTL1 %08x read-memory %x %x\n" % (seq, pa + len(out), n)).encode()
        nn = W.DWORD()
        k32.WriteFile(h, line, len(line), ctypes.byref(nn), None)
        buf = b""; payload = b""; header = False; need = None
        t0 = time.time()
        while time.time() - t0 < 6:
            nn = W.DWORD(); ch = ctypes.create_string_buffer(8192)
            if not k32.ReadFile(h, ch, 8192, ctypes.byref(nn), None):
                break
            if nn.value:
                buf += ch.raw[:nn.value]
            if not header:
                i = buf.rfind(mark)
                if i >= 0:
                    eol = buf.find(b"\n", i + len(mark))
                    if eol >= 0:
                        reply = buf[i + len(mark):eol]
                        m = re.match(rb"OK DATA ([0-9a-f]{8}) ([0-9a-f]{8})", reply)
                        if m:
                            header = True; need = int(m.group(2), 16); buf = buf[eol + 1:]
                        elif reply.startswith(b"ERR"):
                            header = True; need = -1; buf = buf[eol + 1:]
            else:
                take = min(len(buf), need - len(payload))
                payload += buf[:take]
                buf = buf[take:]
                if len(payload) >= need:
                    break
        if need == -1:
            print("ERR at %x" % (pa + len(out))); got = None; break
        if header and need is not None and len(payload) >= need:
            got = payload[:n]; break
        time.sleep(0.25)
    if got is None:
        print("FAIL at %x" % (pa + len(out))); break
    out += got
sys.stdout.write(out.hex() + "\n")
if len(sys.argv) > 3:
    open(sys.argv[3], "wb").write(out)
k32.CloseHandle(h)
