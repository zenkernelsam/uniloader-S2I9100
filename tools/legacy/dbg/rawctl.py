import ctypes, time, sys
from ctypes import wintypes as W
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
h = k32.CreateFileW("\\\\.\\COM12", 0xC0000000, 0, None, 3, 0, None)
print('h=', h, 'err=', ctypes.GetLastError())
if h in (0, 0xFFFFFFFFFFFFFFFF, -1, W.HANDLE(-1).value):
    sys.exit(1)
ct = bytes([0, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 244, 1, 0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))
seq = int(time.time()) & 0x7fffffff
for attempt in range(8):
    seq += 1
    line = ("I9CTL1 %08x read-memory 0x43E00000 64\n" % seq).encode()
    n = W.DWORD()
    k32.WriteFile(h, line, len(line), ctypes.byref(n), None)
    buf = b""; t0 = time.time()
    while time.time() - t0 < 4:
        nn = W.DWORD(); ch = ctypes.create_string_buffer(1024)
        if not k32.ReadFile(h, ch, 1024, ctypes.byref(nn), None):
            break
        if nn.value:
            buf += ch.raw[:nn.value]
        if ("I9CTL1 %08x" % seq).encode() in buf:
            break
    hits = [l for l in buf.split(b"\n") if b"I9CTL1" in l]
    print('try', attempt, 'seq %08x' % seq, 'lines:', [l[:60] for l in hits[-3:]])
    if any(b'OK DATA' in l for l in hits):
        break
k32.CloseHandle(h)
