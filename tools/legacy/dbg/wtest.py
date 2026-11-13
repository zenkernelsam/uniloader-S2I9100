import ctypes, time, sys
from ctypes import wintypes as W
k = ctypes.windll.kernel32
for port in (sys.argv[1:] or ['COM12', 'COM17']):
    h = k.CreateFileW('\\\\.\\' + port, 0xC0000000, 0, None, 3, 0, None)
    print(port, 'h=', h if h != ctypes.c_void_p(-1).value else 'FAIL')
    if h == ctypes.c_void_p(-1).value:
        continue
    k.EscapeCommFunction(h, 5)
    k.EscapeCommFunction(h, 3)
    n = W.DWORD()
    line = b'I9CTL1 70000001 ping\n'
    ok = k.WriteFile(h, line, len(line), ctypes.byref(n), None)
    print('  write ok=', ok, 'bytes=', n.value)
    time.sleep(2)
    k.CloseHandle(h)
