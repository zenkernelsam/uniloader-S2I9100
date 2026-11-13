import ctypes, time, sys, struct, re
from ctypes import wintypes as W

k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = W.HANDLE
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]

h = k32.CreateFileW("\\\\.\\COM12", 0xC0000000, 0, None, 3, 0, None)
if h in (0, 0xFFFFFFFFFFFFFFFF, -1, W.HANDLE(-1).value):
    print("OPEN_ERROR", ctypes.GetLastError()); sys.exit(1)
ct = bytes([0,0,0,0, 0,0,0,0, 250,0,0,0, 0,0,0,0, 232,3,0,0])
k32.SetCommTimeouts(h, ctypes.create_string_buffer(ct, 20))
seq = int(time.time()) & 0x7fffffff

def rdmem(pa, want):
    global seq
    for attempt in range(10):
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
        time.sleep(0.3)
    return None

def u32(pa):
    d = rdmem(pa, 4)
    return struct.unpack("<I", d)[0] if d else None

# _kernel_pmap VA 0x8043af10 -> PA; it's a pmap_t pointer
kp = u32(0x8043af10 - 0x40000000)
print("kernel_pmap -> %x" % (kp or 0))
pmap_pa = kp - 0x40000000
pm = rdmem(pmap_pa, 32)
if pm:
    fields = struct.unpack("<8I", pm)
    print("pmap fields:", [hex(x) for x in fields])
    tte_va = fields[4]
    tte_pa = fields[3]
    print("tte va=%x pa=%x" % (tte_va, tte_pa))
    va = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xC20F5238
    l1i = va >> 20
    e = u32(tte_pa + l1i * 4)
    print("L1[%x]=%x" % (l1i, e if e else 0))
    if e:
        t = e & 3
        if t == 2:
            pa = (e & 0xFFF00000) | (va & 0xFFFFF)
            print("section pa=%x" % pa)
        else:
            # treat as coarse L2 table pointer regardless of tag bits
            l2pa = e & 0xFFFFFC00
            l2i = (va >> 12) & 0xFF
            pte = u32(l2pa + l2i * 4)
            print("L2[%x]=%x (t=%d)" % (l2i, pte if pte else 0, t))
            if pte:
                pa = (pte & 0xFFFFF000) | (va & 0xFFF)
                print("page pa=%x" % pa)
k32.CloseHandle(h)
