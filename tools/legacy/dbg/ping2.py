import ctypes, time, sys
from ctypes import wintypes as W
k = ctypes.windll.kernel32
for port in (sys.argv[1:] or ['COM12', 'COM17']):
    h = k.CreateFileW('\\\\.\\' + port, 0xC0000000, 0, None, 3, 0, None)
    if h == ctypes.c_void_p(-1).value:
        print(port, 'open-fail')
        continue
    k.EscapeCommFunction(h, 5); k.EscapeCommFunction(h, 3)
    seq = int(time.time()) & 0x7fffffff
    line = ('I9CTL1 %08x ping\n' % seq).encode()
    n = W.DWORD()
    k.WriteFile(h, line, len(line), ctypes.byref(n), None)
    buf = ctypes.create_string_buffer(8192); data = b''; t0 = time.time()
    while time.time() - t0 < 30:
        k.ReadFile(h, buf, 8192, ctypes.byref(n), None)
        if n.value:
            data += buf.raw[:n.value]
            if b'OK' in data or b'ERR' in data:
                break
    print(port, 'recv', len(data), data[:200])
    k.CloseHandle(h)
