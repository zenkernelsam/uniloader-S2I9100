import ctypes
from ctypes import wintypes as W

cfg = ctypes.windll.cfgmgr32

# GUID_DEVINTERFACE_USB_HUB = F18A0E88-C30C-11D0-8815-00A0C906BED8


class GUID(ctypes.Structure):
    _fields_ = [('d1', W.DWORD), ('d2', W.WORD), ('d3', W.WORD),
                ('d4', ctypes.c_ubyte * 8)]


hub_guid = GUID(0xF18A0E88, 0xC30C, 0x11D0,
                (ctypes.c_ubyte * 8)(0x88, 0x15, 0x00, 0xA0,
                                     0xC9, 0x06, 0xBE, 0xD8))

n = W.ULONG(0)
r = cfg.CM_Get_Device_Interface_List_SizeW(
    ctypes.byref(n), ctypes.byref(hub_guid), None, 0)
print('size rc=%d n=%d' % (r, n.value))
buf = ctypes.create_unicode_buffer(n.value * 4 + 8)
r = cfg.CM_Get_Device_Interface_ListW(
    ctypes.byref(hub_guid), None, buf, n.value, 0)
print('list rc=%d' % r)
if r == 0:
    s = buf.value
    # multi-sz
    for item in s.split('\x00') if isinstance(s, str) else []:
        pass
    # parse raw multi-string
    parts = []
    cur = ''
    for ch in buf:
        if ch == '\x00':
            if cur:
                parts.append(cur)
                cur = ''
            else:
                break
        else:
            cur += ch
    for p in parts:
        print(p)
