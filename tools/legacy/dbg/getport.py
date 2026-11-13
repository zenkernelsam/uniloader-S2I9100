import ctypes, re, sys
from ctypes import wintypes as W

setupapi = ctypes.windll.setupapi

DIGCF_ALLCLASSES = 0x4
DIGCF_PRESENT = 0x2


class DEVPROPKEY(ctypes.Structure):
    _fields_ = [('fmtid', ctypes.c_ubyte * 16), ('pid', W.ULONG)]


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [('cbSize', W.DWORD), ('ClassGuid', ctypes.c_ubyte * 16),
                ('DevInst', W.DWORD), ('Reserved', ctypes.c_void_p)]


# DEVPKEY_Device_LocationPaths = {a45c254e-df1c-4efd-8020-67d146b850e0},37
def _guid_bytes(d1, d2, d3, b):
    out = []
    for x in (d1.to_bytes(4, 'little') + d2.to_bytes(2, 'little') +
              d3.to_bytes(2, 'little') + bytes(b)):
        out.append(x)
    return out


loc_key = DEVPROPKEY()
loc_key.fmtid = (ctypes.c_ubyte * 16)(*_guid_bytes(
    0xA45C254E, 0xDF1C, 0x4EFD,
    [0x80, 0x20, 0x67, 0xD1, 0x46, 0xB8, 0x50, 0xE0]))
loc_key.pid = 37

want = (sys.argv[1] if len(sys.argv) > 1 else 'S2I9100-OS6').lower()
hdev = setupapi.SetupDiGetClassDevsW(None, None, None,
                                   DIGCF_ALLCLASSES | DIGCF_PRESENT)
i = 0
found = []
while True:
    info = SP_DEVINFO_DATA()
    info.cbSize = ctypes.sizeof(info)
    if not setupapi.SetupDiEnumDeviceInfo(hdev, i, ctypes.byref(info)):
        break
    i += 1
    need = W.DWORD(0)
    # device instance id
    buf = ctypes.create_unicode_buffer(512)
    if not setupapi.SetupDiGetDeviceInstanceIdW(
            hdev, ctypes.byref(info), buf, 512, None):
        continue
    iid = buf.value
    if want not in iid.lower():
        continue
    # location paths property (REG_MULTI_SZ)
    ptype = W.ULONG(0)
    setupapi.SetupDiGetDevicePropertyW(
        hdev, ctypes.byref(info), ctypes.byref(loc_key), ctypes.byref(ptype),
        None, 0, ctypes.byref(need), 0)
    raw = ctypes.create_string_buffer(max(need.value, 2))
    ok = setupapi.SetupDiGetDevicePropertyW(
        hdev, ctypes.byref(info), ctypes.byref(loc_key), ctypes.byref(ptype),
        raw, need, ctypes.byref(need), 0)
    paths = []
    if ok:
        ws = ctypes.wstring_at(ctypes.addressof(raw), need.value // 2)
        paths = [p for p in ws.split('\x00') if p]
    found.append((iid, paths))
for iid, paths in found:
    print(iid)
    for p in paths:
        print('   ', p)
        m = re.findall(r'USB\((\d+)\)', p)
        print('    usb segments:', m)
