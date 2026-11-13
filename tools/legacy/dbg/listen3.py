import ctypes, time, sys
from ctypes import wintypes as W
k = ctypes.windll.kernel32
p = sys.argv[1] if len(sys.argv) > 1 else 'COM12'
h = k.CreateFileW('\\\\.\\' + p, 0xC0000000, 0, None, 3, 0, None)
if h == ctypes.c_void_p(-1).value:
    sys.exit('open fail gle=%d' % k.GetLastError())
# assert DTR
dcb = ctypes.create_string_buffer(28)
W.DWORD(28)
ctypes.memset(dcb, 0, 28)
class DCB(ctypes.Structure):
    _fields_ = [('DCBlength', W.DWORD), ('BaudRate', W.DWORD), ('flags', W.DWORD),
                ('wReserved', W.WORD), ('XonLim', W.WORD), ('XoffLim', W.WORD),
                ('ByteSize', W.BYTE), ('Parity', W.BYTE), ('StopBits', W.BYTE),
                ('XonChar', ctypes.c_char), ('XoffChar', ctypes.c_char),
                ('ErrorChar', ctypes.c_char), ('EofChar', ctypes.c_char),
                ('EvtChar', ctypes.c_char), ('wReserved1', W.WORD)]
d = DCB(); d.DCBlength = 28
k.GetCommState(h, ctypes.byref(d)); d.flags |= 1  # fDtrControl=DTR
k.SetCommState(h, ctypes.byref(d))
k.EscapeCommFunction(h, 5)  # SETDTR
deadline = time.time() + 180
buf = ctypes.create_string_buffer(4096); n = W.DWORD(0); total = 0
last = time.time()
while time.time() < deadline:
    if k.ReadFile(h, buf, 4096, ctypes.byref(n), None) and n.value:
        total += n.value
        sys.stdout.write(buf.raw[:n.value].decode('utf-8','replace')); sys.stdout.flush()
        last = time.time()
    else:
        time.sleep(0.05)
print('\n=== total %d bytes, last at +%ds' % (total, int(last - (deadline-180))))
k.CloseHandle(h)
