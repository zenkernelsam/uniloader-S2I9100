import ctypes, time, sys
from ctypes import wintypes as W
k = ctypes.windll.kernel32
port = sys.argv[1] if len(sys.argv) > 1 else 'COM12'
h = k.CreateFileW('\\\\.\\' + port, 0xC0000000, 0, None, 3, 0, None)
if h == ctypes.c_void_p(-1).value:
    print('open FAIL gle=', k.GetLastError())
    sys.exit(1)
print('open ok h=', h)
k.EscapeCommFunction(h, 5)
k.EscapeCommFunction(h, 3)
# dump any pending RX for 2s
n = W.DWORD()
buf = ctypes.create_string_buffer(65536)
t0 = time.time()
pre = b''
while time.time() - t0 < 2:
    k.ReadFile(h, buf, 65536, ctypes.byref(n), None)
    if n.value:
        pre += buf.raw[:n.value]
print('pre-rx', len(pre))
for i in range(3):
    line = ('I9CTL1 %08x ping\n' % (0x71000000 + i)).encode()
    ok = k.WriteFile(h, line, len(line), ctypes.byref(n), None)
    print('write', i, 'ok=', ok, 'n=', n.value, 'gle=', k.GetLastError())
    time.sleep(0.5)
# listen 8s for replies / CDC stats
t0 = time.time()
data = b''
while time.time() - t0 < 8:
    k.ReadFile(h, buf, 65536, ctypes.byref(n), None)
    if n.value:
        data += buf.raw[:n.value]
k.CloseHandle(h)
import re
cdc = re.findall(rb'I9100 CDC m=[^\r\n]*', data)
print('post-rx', len(data))
for c in cdc[-4:]:
    print(' ', c.decode(errors='replace'))
okl = re.findall(rb'I9CTL1 [0-9a-f]{8} [^\r\n]*', data)
for c in okl[:10]:
    print('REPLY:', c.decode(errors='replace'))
