#!/usr/bin/env python3
"""Walk _allproc via kernel pmap translation, reading through i9ctl subprocess.
Usage: proclist.py [mach_kernel] [COMx]"""
import subprocess, sys, struct, re, os, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = sys.argv[2] if len(sys.argv) > 2 else "COM12"
ALLPROC = 0x80474d98
KPMAP_PTR = 0x8043bf10
VA2PA = 0x80000000 - 0x40000000
TMP = tempfile.mktemp(suffix='.bin')

def kread(pa, ln):
    p = subprocess.run([sys.executable, os.path.join(HERE, 'i9ctl.py'), PORT,
        "read-memory %08x %x" % (pa, ln), '--timeout', '15', '--data-out', TMP],
        capture_output=True)
    try:
        return open(TMP, 'rb').read()[:ln]
    except OSError:
        return None

def rd32(pa):
    d = kread(pa, 4)
    return struct.unpack('<I', d)[0] if d and len(d) >= 4 else None

kpmap = rd32(KPMAP_PTR - VA2PA)
print("kernel_pmap=%x" % (kpmap or 0))
if not kpmap:
    sys.exit(1)
hdr = kread(kpmap - VA2PA, 0x40) or b'\0' * 0x40
print("pmap hdr:", ' '.join('%08x' % x for x in struct.unpack('<16I', hdr)))
tte_va = None
for w in struct.unpack('<16I', hdr):
    if 0x80400000 < w < 0xc0000000 and (w & 0x3fff) == 0:
        tte_va = w; break
if tte_va is None:
    for w in struct.unpack('<16I', hdr):
        if 0x40000000 <= w < 0x80000000 and (w & 0x3fff) == 0:
            tte_va = w + VA2PA; break
print("tte=%x" % (tte_va or 0))
if not tte_va:
    sys.exit(1)

def xlate(va):
    l1 = rd32((tte_va - VA2PA_OFF) if False else (tte_va - VA2PA if tte_va >= 0x80000000 else tte_va) + (va >> 20) * 4)
    if l1 is None:
        return None
    if (l1 & 3) == 2:
        return (l1 & 0xfff00000) | (va & 0xfffff)
    l2pa = l1 & 0xfffffc00
    if l2pa < 0x40000000 or l2pa >= 0x80000000:
        return None
    l2 = rd32(l2pa + ((va >> 12) & 0xff) * 4)
    if l2 is None or not (0x40000000 <= (l2 & 0xfffff000) < 0x80000000):
        return None
    return (l2 & 0xfffff000) | (va & 0xfff)

first = rd32(ALLPROC - VA2PA)
print("allproc first=%x" % (first or 0))
va, seen = first, set()
for i in range(80):
    if not va or va in seen or va < 0xc0000000:
        break
    seen.add(va)
    pa = xlate(va)
    if not pa:
        print("xlat fail va=%x" % va); break
    d = kread(pa, 0x800) or b''
    strs = [s.decode() for s in re.findall(rb'[ -~]{3,16}', d[:0x400])]
    comm = next((s for s in strs if not s.startswith(('0x', 'x')) and s.isprintable()), '?')
    nxt = struct.unpack_from('<I', d + b'\0' * 0x800, 0x60)[0]
    pid = struct.unpack_from('<I', d + b'\0' * 0x800, 0x10)[0]
    print("%-18s pid=%-5d va=%x next=%x" % (comm, pid, va, nxt))
    if nxt == first or nxt == va:
        break
    va = nxt
