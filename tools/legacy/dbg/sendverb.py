import ctypes, time, sys, re
from ctypes import wintypes as W
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
h = k32.CreateFileW("\\\\.\\COM12", 0xC0000000, 0, None, 3, 0, None)
if h in (0, -1, W.HANDLE(-1).value):
    print("OPEN_ERROR"); sys.exit(1)
ct = bytes([0,0,0,0, 0,0,0,0, 250,0,0,0, 0,0,0,0, 232,3,0,0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))
verb = " ".join(sys.argv[1:])
seq = int(time.time()) & 0x7fffffff
for attempt in range(15):
    seq += 1
    mark = ("I9CTL1 %08x" % seq).encode()
    line = mark + b" " + verb.encode() + b"\n"
    n = W.DWORD()
    k32.WriteFile(h, line, len(line), ctypes.byref(n), None)
    buf = b""; t0 = time.time()
    while time.time() - t0 < 4:
        nn = W.DWORD(); ch = ctypes.create_string_buffer(8192)
        if not k32.ReadFile(h, ch, 8192, ctypes.byref(nn), None):
            break
        if nn.value:
            buf += ch.raw[:nn.value]
        if mark in buf:
            break
    hits = [l for l in buf.split(b"\n") if mark in l]
    if hits:
        print("try", attempt, hits[-1][:80]); break
    print("try", attempt, "no reply")
    time.sleep(0.4)
k32.CloseHandle(h)
