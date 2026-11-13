import ctypes, time, sys
from ctypes import wintypes as W
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
port = sys.argv[1] if len(sys.argv) > 1 else "COM12"
name = "\\\\.\\" + port
h = k32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
print('h=', h, 'err=', ctypes.GetLastError())
if h not in (0, 0xFFFFFFFFFFFFFFFF, -1, W.HANDLE(-1).value):
    n = W.DWORD(); buf = ctypes.create_string_buffer(512)
    t0 = time.time()
    while time.time() - t0 < 8:
        ok = k32.ReadFile(h, buf, 512, ctypes.byref(n), None)
        if not ok:
            print('read err', ctypes.GetLastError()); break
        if n.value:
            print('RX', n.value, buf.raw[:n.value][:100]); break
        time.sleep(0.05)
    k32.CloseHandle(h)
