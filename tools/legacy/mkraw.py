#!/usr/bin/env python3
# mkraw.py - flatten a 32-bit Mach-O kernel into the "sd-xnu.raw" layout:
#   file offset 0 = Mach-O header, then each LC_SEGMENT's bytes placed at
#   (vmaddr - min_vmaddr). Zerofill range covered by zeroed flat image.
import struct, sys

def main(src, dst):
    data = open(src, "rb").read()
    magic, cputype, subtype, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from("<7I", data, 0)
    assert magic == 0xfeedface, "not a 32-bit Mach-O"
    segs, threads_entry = [], None
    off = 28
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x1:  # LC_SEGMENT
            segname = data[off+8:off+24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4I", data, off+24)
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x5:  # LC_UNIXTHREAD
            flavor = struct.unpack_from("<I", data, off+8)[0]
            if flavor == 1:  # ARM_THREAD_STATE
                threads_entry = struct.unpack_from("<I", data, off+8+4+4+15*4)[0]
        off += cmdsize
    assert segs, "no LC_SEGMENT"
    base = min(s[1] for s in segs)
    top  = max(s[1] + s[2] for s in segs)
    flat = bytearray(top - base)
    flat[0:28+sizeofcmds] = data[0:28+sizeofcmds]
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        o = vmaddr - base
        flat[o:o+filesize] = data[fileoff:fileoff+filesize]
        print("seg %-16s vm=%08x fileoff=%06x filesz=%06x -> flat %06x..%06x"
              % (name, vmaddr, fileoff, filesize, o, o+vmsize))
    if threads_entry:
        print("entry pc = %#x (flat off %#x)" % (threads_entry, threads_entry - base))
    open(dst, "wb").write(flat)
    print("wrote %s (%d bytes), base %#x" % (dst, len(flat), base))

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
