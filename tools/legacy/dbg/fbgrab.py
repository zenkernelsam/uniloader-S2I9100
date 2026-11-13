import ctypes, time, sys, re
from ctypes import wintypes as W

k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]

port = sys.argv[1] if len(sys.argv) > 1 else "COM12"
base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x43E00000
total = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x177000
out = sys.argv[4] if len(sys.argv) > 4 else "fb.bin"
CHUNK = 0x8000

h = k32.CreateFileW("\\\\.\\" + port, 0xC0000000, 0, None, 3, 0, None)
if h in (0, 0xFFFFFFFFFFFFFFFF, -1, W.HANDLE(-1).value):
    print("OPEN_ERROR", ctypes.GetLastError()); sys.exit(1)
ct = bytes([0,0,0,0, 0,0,0,0, 250,0,0,0, 0,0,0,0, 232,3,0,0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))

seq = int(time.time()) & 0x7fffffff
data = bytearray()
pos = 0
while pos < total:
    want = min(CHUNK, total - pos)
    addr = base + pos
    got = None
    for attempt in range(10):
        seq += 1
        mark = ("\nI9CTL1 %08x " % seq).encode()
        line = ("I9CTL1 %08x read-memory %x %x\n" % (seq, addr, want)).encode()
        n = W.DWORD()
        k32.WriteFile(h, line, len(line), ctypes.byref(n), None)
        buf = b""
        payload = b""
        header = False
        need = None
        t0 = time.time()
        while time.time() - t0 < 8:
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
                            header = True
                            need = int(m.group(2), 16)
                            buf = buf[eol + 1:]
                        elif reply.startswith(b"ERR"):
                            break
            else:
                take = min(len(buf), need - len(payload))
                payload += buf[:take]
                buf = buf[take:]
                if len(payload) >= need:
                    break
        if header and len(payload) >= (need or want):
            got = payload[:want]
            break
        time.sleep(0.4)
    if got is None:
        print("FAIL at +%x" % pos)
        break
    data += got
    pos += want
    if pos % (CHUNK * 6) == 0:
        print("...%x/%x" % (pos, total), flush=True)

open(out, "wb").write(bytes(data))
print("WROTE %d -> %s" % (len(data), out))
k32.CloseHandle(h)
