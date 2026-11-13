"""hubcycle.py - force a USB hub port power-cycle on the hub parenting
the i9100 CDC device via IOCTL_USB_HUB_CYCLE_PORT.

usage: py hubcycle.py [substr-of-device-instance-id]
"""
import ctypes, re, sys
from ctypes import wintypes as W

cfg = ctypes.windll.cfgmgr32
k = ctypes.windll.kernel32

CR_SUCCESS = 0
CM_DRP_LOCATION_INFORMATION = 0x0D
IOCTL_USB_HUB_CYCLE_PORT = 0x220444


class GUID(ctypes.Structure):
    _fields_ = [('d1', W.DWORD), ('d2', W.WORD), ('d3', W.WORD),
                ('d4', ctypes.c_ubyte * 8)]


HUB_GUID = GUID(0xF18A0E88, 0xC30C, 0x11D0,
                (ctypes.c_ubyte * 8)(0x88, 0x15, 0x00, 0xA0,
                                     0xC9, 0x06, 0xBE, 0xD8))


def devinst_id(devinst):
    buf = ctypes.create_unicode_buffer(512)
    if cfg.CM_Get_Device_IDW(W.DWORD(devinst), buf, 512, 0) != CR_SUCCESS:
        return ''
    return buf.value


def find_devinst(substr):
    root = W.DWORD()
    if cfg.CM_Locate_DevNodeW(ctypes.byref(root), None, 0) != CR_SUCCESS:
        return []
    out = []
    stack = [root.value]
    seen = set()
    while stack:
        dn = stack.pop()
        if dn in seen:
            continue
        seen.add(dn)
        iid = devinst_id(dn)
        if substr.lower() in iid.lower():
            out.append((dn, iid))
        sib = W.DWORD()
        if cfg.CM_Get_Sibling(ctypes.byref(sib), W.DWORD(dn), 0) == CR_SUCCESS:
            stack.append(sib.value)
        ch = W.DWORD()
        if cfg.CM_Get_Child(ctypes.byref(ch), W.DWORD(dn), 0) == CR_SUCCESS:
            stack.append(ch.value)
    return out


def parent_of(devinst):
    p = W.DWORD()
    if cfg.CM_Get_Parent(ctypes.byref(p), W.DWORD(devinst), 0) == CR_SUCCESS:
        return p.value
    return None


class DEVPROPKEY(ctypes.Structure):
    _fields_ = [('fmtid', ctypes.c_ubyte * 16), ('pid', W.ULONG)]


def _fmtid(d1, d2, d3, b):
    raw = (d1.to_bytes(4, 'little') + d2.to_bytes(2, 'little') +
           d3.to_bytes(2, 'little') + bytes(b))
    return (ctypes.c_ubyte * 16)(*raw)


# DEVPKEY_Device_LocationPaths = {a45c254e-df1c-4efd-8020-67d146b850e0},37
LOCPATHS = DEVPROPKEY()
LOCPATHS.fmtid = _fmtid(0xA45C254E, 0xDF1C, 0x4EFD,
                        [0x80, 0x20, 0x67, 0xD1, 0x46, 0xB8, 0x50, 0xE0])
LOCPATHS.pid = 37


def location_paths(devinst):
    size = W.ULONG(0)
    ptype = W.ULONG(0)
    cfg.CM_Get_DevNode_PropertyW(W.DWORD(devinst), ctypes.byref(LOCPATHS),
                               ctypes.byref(ptype), None,
                               ctypes.byref(size), 0)
    if not size.value:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if cfg.CM_Get_DevNode_PropertyW(W.DWORD(devinst),
            ctypes.byref(LOCPATHS), ctypes.byref(ptype),
            buf, ctypes.byref(size), 0) != CR_SUCCESS:
        return []
    ws = ctypes.wstring_at(ctypes.addressof(buf), size.value // 2)
    return [p for p in ws.split('\x00') if p]


def location_of(devinst):
    buf = ctypes.create_unicode_buffer(512)
    size = W.ULONG(1024)
    t = W.ULONG(0)
    if cfg.CM_Get_DevNode_Registry_PropertyW(
            W.DWORD(devinst), CM_DRP_LOCATION_INFORMATION,
            ctypes.byref(t), buf, ctypes.byref(size), 0) == CR_SUCCESS:
        return buf.value
    return ''


def hub_interfaces():
    n = W.ULONG(0)
    cfg.CM_Get_Device_Interface_List_SizeW(
        ctypes.byref(n), ctypes.byref(HUB_GUID), None, 0)
    buf = ctypes.create_unicode_buffer(n.value * 4 + 8)
    if cfg.CM_Get_Device_Interface_ListW(
            ctypes.byref(HUB_GUID), None, buf, n.value, 0) != CR_SUCCESS:
        return []
    parts, cur = [], ''
    for ch in buf:
        if ch == '\x00':
            if cur:
                parts.append(cur)
                cur = ''
            else:
                break
        else:
            cur += ch
    return parts


def main():
    substr = sys.argv[1] if len(sys.argv) > 1 else 'S2I9100-OS6'
    matches = find_devinst(substr)
    print('matches:', [m[1] for m in matches])
    if not matches:
        return
    dn, iid = matches[0]
    # climb to the USB hub (skip usbser/composite children)
    cur = dn
    hub_iid = None
    for _ in range(6):
        p = parent_of(cur)
        if p is None:
            break
        pid = devinst_id(p)
        print('parent:', pid)
        # a hub node has a USB hub interface: match in the list below
        hub_iid = pid
        cur = p
        if pid.startswith('USB\\ROOT_HUB') or ('VID_' in pid and
                'PID_' in pid and p != dn):
            # heuristics: the first node with a hub interface wins later
            pass
    # choose parent hub: try each ancestor, take the one that has an iface
    ifaces = hub_interfaces()
    cur = dn
    chosen = None
    for _ in range(6):
        p = parent_of(cur)
        if p is None:
            break
        pid = devinst_id(p)
        # interface paths embed the instance id with # separators
        needle = pid.replace('\\', '#').lower()
        for itf in ifaces:
            if needle in itf.lower():
                chosen = (pid, itf)
                break
        if chosen:
            break
        cur = p
    if not chosen:
        print('no hub interface found')
        return
    print('hub:', chosen[0])
    print('path:', chosen[1])
    h = k.CreateFileW(chosen[1], 0xC0000000, 3, None, 3, 0, None)
    if h == ctypes.c_void_p(-1).value:
        print('hub open fail gle=', k.GetLastError())
        return
    # find port by probing each connection's device descriptor
    IOCTL_NCI_EX = 0x220448
    port = None
    for p in range(1, 32):
        buf = ctypes.create_string_buffer(4096)
        ctypes.cast(buf, ctypes.POINTER(W.ULONG))[0] = p
        ret = W.DWORD(0)
        ok = k.DeviceIoControl(h, IOCTL_NCI_EX, buf, 4096, buf, 4096,
                               ctypes.byref(ret), None)
        if not ok:
            continue
        # USB_NODE_CONNECTION_INFORMATION_EX: ConnectionIndex@0,
        # DeviceDescriptor@4: idVendor@desc+8, idProduct@desc+10
        vid, pid = (W.USHORT.from_address(
            ctypes.addressof(buf) + 4 + 8).value,
                    W.USHORT.from_address(
            ctypes.addressof(buf) + 4 + 10).value)
        if vid:
            print('  port %2d vid=%04x pid=%04x' % (p, vid, pid))
        if vid == 0x0525 and pid == 0xA4A7:
            port = p
    if port is None:
        print('device not found on hub ports')
        k.CloseHandle(h)
        return
    print('port:', port)
    params = ctypes.create_string_buffer(8)
    ctypes.cast(params, ctypes.POINTER(W.ULONG))[0] = port
    ret = W.DWORD(0)
    ok = k.DeviceIoControl(h, IOCTL_USB_HUB_CYCLE_PORT, params, 8,
                           params, 8, ctypes.byref(ret), None)
    st = W.ULONG.from_address(ctypes.addressof(params) + 4).value
    print('cycle ok=%s gle=%s ret=%d status=%x' %
          (ok, k.GetLastError(), ret.value, st))
    k.CloseHandle(h)


if __name__ == '__main__':
    main()
