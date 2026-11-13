import ctypes, time, sys
from ctypes import wintypes as W
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
h = k32.CreateFileW("\\\\.\\COM12", 0xC0000000, 0, None, 3, 0, None)
print('h=', h, 'err=', ctypes.GetLastError())
if h in (0, 0xFFFFFFFFFFFFFFFF, -1, W.HANDLE(-1).value):
    sys.exit(1)
ct = bytes([0,0,0,0, 0,0,0,0, 250,0,0,0, 0,0,0,0, 232,3,0,0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))
buf = b""
t0 = time.time()
secs = int(sys.argv[2]) if len(sys.argv) > 2 else 20
while time.time() - t0 < secs:
    n = W.DWORD(); ch = ctypes.create_string_buffer(8192)
    if not k32.ReadFile(h, ch, 8192, ctypes.byref(n), None):
        print("read err", ctypes.GetLastError()); break
    if n.value:
        buf += ch.raw[:n.value]
k32.CloseHandle(h)
open(sys.argv[1], "wb").write(buf)
print("CAPTURED", len(buf))
