import ctypes, time, sys, struct, re
from ctypes import wintypes as W

k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]

h = k32.CreateFileW("\\\\.\\COM12", 0xC0000000, 0, None, 3, 0, None)
if h in (0, -1, W.HANDLE(-1).value):
    print("OPEN_ERROR"); sys.exit(1)
ct = bytes([0,0,0,0, 0,0,0,0, 250,0,0,0, 0,0,0,0, 232,3,0,0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))
seq = int(time.time()) & 0x7fffffff

def rdmem(pa, want):
    global seq
    for attempt in range(8):
        seq += 1
        mark = ("\nI9CTL1 %08x " % seq).encode()
        line = ("I9CTL1 %08x read-memory %x %x\n" % (seq, pa, want)).encode()
        n = W.DWORD()
        k32.WriteFile(h, line, len(line), ctypes.byref(n), None)
        buf = b""; payload = b""; header = False; need = None
        t0 = time.time()
        while time.time() - t0 < 6:
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
                            return None
            else:
                take = min(len(buf), need - len(payload))
                payload += buf[:take]
                buf = buf[take:]
                if len(payload) >= need:
                    break
        if header and len(payload) >= (need or want):
            return payload[:want]
        time.sleep(0.25)
    return None

def u32pa(pa):
    d = rdmem(pa, 4)
    return struct.unpack("<I", d)[0] if d else None

kp = u32pa(0x8043af10 - 0x40000000)
pm = rdmem(kp - 0x40000000, 32)
tte_pa = struct.unpack("<8I", pm)[3]
print("tte pa=%x" % tte_pa)

def v2p(va):
    if 0x80000000 <= va < 0xC0000000:
        return va - 0x40000000
    l1i = va >> 20
    e = u32pa(tte_pa + l1i * 4)
    if not e:
        return None
    if (e & 3) == 2:
        return (e & 0xFFF00000) | (va & 0xFFFFF)
    l2pa = e & 0xFFFFFC00
    pte = u32pa(l2pa + ((va >> 12) & 0xFF) * 4)
    if not pte:
        return None
    return (pte & 0xFFFFF000) | (va & 0xFFF)

def rdva(va, n):
    out = b""
    off = 0
    while off < n:
        pa = v2p(va + off)
        if pa is None:
            return None
        chunk = min(n - off, 0x1000 - (pa & 0xFFF))
        d = rdmem(pa, chunk)
        if not d:
            return None
        out += d
        off += chunk
    return out

target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xC1E33880
size = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x8000
out = rdva(target, size)
if out:
    fn = sys.argv[3] if len(sys.argv) > 3 else "/tmp/kring.bin"
    open(fn, "wb").write(out)
    print("wrote %d -> %s" % (len(out), fn))
k32.CloseHandle(h)
