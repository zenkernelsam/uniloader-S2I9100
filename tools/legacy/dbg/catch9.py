import ctypes, time, sys, subprocess
from ctypes import wintypes as W
k = ctypes.windll.kernel32

VERBS = [v for v in sys.argv[2:]] or ['ping', 'root-status']
PORT = sys.argv[1] if len(sys.argv) > 1 else 'COM12'
OUTP = 'out/forensic/catch-' + time.strftime('%H%M%S')
console = open(OUTP + '-console.bin', 'wb')

def com_exists():
    r = subprocess.run(['powershell','-NoProfile','-Command',
        "Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -match 'COM\\d+'} | Select-Object -ExpandProperty Name"],
        capture_output=True, timeout=20)
    return PORT.encode() in r.stdout

print('waiting for', PORT, flush=True)
while not com_exists():
    time.sleep(0.5)
print('port present, opening NOW', flush=True)

h = k.CreateFileW('\\\\.\\' + PORT, 0xC0000000, 0, None, 3, 0, None)
if h == ctypes.c_void_p(-1).value:
    sys.exit('open fail gle=%d' % k.GetLastError())
k.EscapeCommFunction(h, 5)  # SETDTR

buf = ctypes.create_string_buffer(65536); n = W.DWORD(0)
seq = 0x73000000
deadline = time.time() + 600
sent = 0
next_send = time.time() + 0.3
t0 = time.time()
while time.time() < deadline:
    if sent < len(VERBS) and time.time() >= next_send:
        line = ('I9CTL1 %08x %s\n' % (seq, VERBS[sent])).encode()
        ok = k.WriteFile(h, line, len(line), ctypes.byref(n), None)
        gle = k.GetLastError()
        print('write %r ok=%d n=%d gle=%d' % (line[:48], ok, n.value, gle), flush=True)
        if ok and n.value:
            sent += 1; seq += 1
        next_send = time.time() + 3
    n = W.DWORD(0)
    if k.ReadFile(h, buf, 65536, ctypes.byref(n), None) and n.value:
        chunk = buf.raw[:n.value]
        console.write(chunk); console.flush()
        sys.stdout.buffer.write(chunk); sys.stdout.buffer.flush()
    else:
        gle = k.GetLastError()
        if gle in (22, 1167, 121):
            print('port lost gle=%d at +%.1fs - reopening...' % (gle, time.time()-t0), flush=True)
            k.CloseHandle(h)
            while not com_exists():
                time.sleep(0.5)
            h = k.CreateFileW('\\\\.\\' + PORT, 0xC0000000, 0, None, 3, 0, None)
            if h == ctypes.c_void_p(-1).value:
                time.sleep(0.3); continue
            k.EscapeCommFunction(h, 5)
            print('reopened at +%.1fs' % (time.time()-t0), flush=True)
            next_send = time.time()
        else:
            time.sleep(0.02)
print('done at +%.1fs' % (time.time()-t0))
