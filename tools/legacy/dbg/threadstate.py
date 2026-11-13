#!/usr/bin/env python3
"""Decode per-thread state from `i9ctl threads` output via kernel pmap.
Usage: threadstate.py <threads-dump.txt> [COMx]
Single persistent session — no DTR toggling between reads."""
import sys, struct, time, ctypes
from ctypes import wintypes as W

PORT = sys.argv[2] if len(sys.argv) > 2 else "COM12"
KPMAP_PTR = 0x8043bf10
VA2PA = 0x80000000 - 0x40000000

k32 = ctypes.windll.kernel32
GENERIC_RW = 0xC0000000

class COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [("ReadIntervalTimeout", W.DWORD),
                ("ReadTotalTimeoutMultiplier", W.DWORD),
                ("ReadTotalTimeoutConstant", W.DWORD),
                ("WriteTotalTimeoutMultiplier", W.DWORD),
                ("WriteTotalTimeoutConstant", W.DWORD)]

h = k32.CreateFileW("\\\\.\\" + PORT, GENERIC_RW, 0, None, 3, 0, None)
if h == ctypes.c_void_p(-1).value:
    sys.exit('open fail')
k32.EscapeCommFunction(h, 5)  # SETDTR
k32.EscapeCommFunction(h, 3)  # SETRTS
t = COMMTIMEOUTS(0, 0, 200, 0, 1000)
k32.SetCommTimeouts(h, ctypes.byref(t))

seq = int(time.time()) & 0x7fffffff
chunk = ctypes.create_string_buffer(8192)

def cmd(verb, deadline_s=20):
    """Send verb, return (reply_line, payload_bytes)."""
    global seq
    seq += 1
    mark = ("\nI9CTL1 %08x " % seq).encode()
    line = ("I9CTL1 %08x %s\n" % (seq, verb)).encode()
    k32.WriteFile(h, line, len(line), ctypes.byref(W.DWORD()), None)
    buf = b""; payload = b""; dlen = None
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        n = W.DWORD()
        if not k32.ReadFile(h, chunk, 8192, ctypes.byref(n), None):
            break
        if not n.value:
            continue
        if len(buf) < 200:
            sys.stderr.write('rx %d: %r\n' % (n.value, chunk.raw[:min(n.value,60)]))
        buf += chunk.raw[:n.value]
        if dlen is None:
            i = buf.rfind(mark)
            if i < 0:
                buf = buf[-4096:]
                continue
            eol = buf.find(b"\n", i + len(mark))
            if eol < 0:
                continue
            reply = buf[i + len(mark):eol]
            if reply.startswith(b"OK DATA "):
                dlen = int(reply[17:25], 16)
                buf = buf[eol + 1:]
            elif reply.startswith(b"ERR busy"):
                buf = buf[eol + 1:]
                continue
            else:
                sys.stderr.write('reply: %r\n' % reply)
                return reply, b""
        else:
            take = min(len(buf), dlen - len(payload))
            payload += buf[:take]
            buf = buf[take:]
            if len(payload) >= dlen:
                return b"OK DATA", payload
    return b"TIMEOUT", payload

def kread(pa, ln):
    for _ in range(3):
        r, d = cmd("read-memory %08x %x" % (pa, ln), 60)
        sys.stderr.write('kread %x -> %r %dB\n' % (pa, r, len(d)))
        if len(d) >= ln:
            return d[:ln]
        if d:
            return d  # partial; caller decides
    return None

def rd32(pa):
    d = kread(pa, 4)
    return struct.unpack('<I', d)[0] if d and len(d) >= 4 else None

kpmap = rd32(KPMAP_PTR - VA2PA)
if not kpmap:
    sys.exit('no kernel_pmap')
hdr = kread(kpmap - VA2PA, 0x40) or b'\0' * 0x40
tte_va = None
for w in struct.unpack('<16I', hdr):
    if 0x80400000 < w < 0xc0000000 and (w & 0x3fff) == 0:
        tte_va = w; break
if tte_va is None:
    for w in struct.unpack('<16I', hdr):
        if 0x40000000 <= w < 0x80000000 and (w & 0x3fff) == 0:
            tte_va = w + VA2PA; break
if not tte_va:
    sys.exit('no tte')
tte_pa = tte_va - VA2PA if tte_va >= 0x80000000 else tte_va
sys.stderr.write('kpmap=%x tte=%x\n' % (kpmap, tte_va))

# L1 covering 0x80000000-0xe0000000 (indices 0x800..0xdff) in chunks of
# 0x400 to stay under the 32KiB staging cap and below flaky sizes.
l1d = b''
for i in range(6):
    d = kread(tte_pa + (0x800 + i * 0x100) * 4, 0x400)
    l1d += d or b'\0' * 0x400

L2 = {}
def l2tab(l2pa):
    if l2pa not in L2:
        L2[l2pa] = kread(l2pa, 0x400) or b''
    return L2[l2pa]

def xlate(va):
    idx = va >> 20
    off = idx * 4 - 0x2000
    l1 = struct.unpack_from('<I', l1d, off)[0] \
        if 0 <= off <= len(l1d) - 4 else 0
    if (l1 & 3) == 2:
        return (l1 & 0xfff00000) | (va & 0xfffff)
    l2pa = l1 & 0xfffffc00
    if l2pa < 0x40000000 or l2pa >= 0x80000000:
        return None
    tab = l2tab(l2pa)
    l2 = struct.unpack_from('<I', tab + b'\0' * 0x400,
                            ((va >> 12) & 0xff) * 4)[0]
    if not (0x40000000 <= (l2 & 0xfffff000) < 0x80000000):
        return None
    return (l2 & 0xfffff000) | (va & 0xfff)

BITS = [(0x01,'WAIT'),(0x02,'SUSP'),(0x04,'RUN'),(0x08,'UNINT'),
        (0x10,'TERM'),(0x20,'TERM2'),(0x80,'IDLE')]

proc = '?'
for line in open(sys.argv[1]):
    line = line.rstrip('\n')
    if line.startswith('proc '):
        proc = line[5:].strip()
        continue
    if 'thr=0x' not in line:
        continue
    thr = int(line.split('thr=')[1].split()[0], 16)
    pa = xlate(thr)
    if pa is None:
        print('%-22s thr=%x XLATE-FAIL' % (proc, thr))
        sys.stdout.flush()
        continue
    d = kread(pa, 0xa0) or b''
    d = d + b'\0' * (0xa0 - len(d))
    wq = struct.unpack_from('<I', d, 0x0c)[0]
    ev = struct.unpack_from('<Q', d, 0x10)[0]
    ks = struct.unpack_from('<I', d, 0x8c)[0]
    st = struct.unpack_from('<I', d, 0x94)[0]
    flags = '|'.join(n for b, n in BITS if st & b) or 'none'
    print('%-22s thr=%x st=%02x(%s) wq=%x ev=%x kstk=%x' %
          (proc, thr, st, flags, wq, ev, ks))
    sys.stdout.flush()
