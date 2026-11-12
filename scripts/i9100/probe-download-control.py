#!/usr/bin/env python3
"""Probe direct USB control replies from the approved Download phone.

One WinUSB handle, bounded host transfer timeout, standard read requests
only. No bulk/Odin packets, resets, partition writes or automatic retries.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import struct
import winreg

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class Setup(c.Structure):
    _pack_ = 1
    _fields_ = [('kind', c.c_ubyte), ('request', c.c_ubyte), ('value', w.WORD), ('index', w.WORD), ('length', w.WORD)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if os.name != 'nt': p.error('WinUSB runs on Windows')
    o = module('probe_odin', 'odin-loop.py'); h = module('probe_hub', 'cycle-download-port.py')
    out = o.confined(a.output, o.REPO / 'out'); o.require(not out.exists(), 'Fresh evidence directory required')
    profile = json.loads((o.OUT / 'inventory-20261106-211114-download-profile.json').read_text())
    with o.host_lock():
        actual = o.download(o.Host().inventory(), profile)
        key = 'SYSTEM\\CurrentControlSet\\Enum\\' + actual['instance'] + '\\Device Parameters'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as registry:
            guids, _ = winreg.QueryValueEx(registry, 'DeviceInterfaceGUIDs')
        o.require(isinstance(guids, list) and len(guids) == 1, 'Ambiguous WinUSB interface registration')
        path = h.interface_path(guids[0], actual['instance'])
        out.mkdir(parents=True)
        result = dict(time=datetime.now(timezone.utc).isoformat(), device=actual,
                      interface=path, flash_writes=0, resets=0, replies=[])
        k = c.WinDLL('kernel32', use_last_error=True); u = c.WinDLL('winusb', use_last_error=True)
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        k.CreateFileW.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]; k.CloseHandle.restype = w.BOOL
        u.WinUsb_Initialize.argtypes = [w.HANDLE, c.POINTER(c.c_void_p)]; u.WinUsb_Initialize.restype = w.BOOL
        u.WinUsb_Free.argtypes = [c.c_void_p]; u.WinUsb_Free.restype = w.BOOL
        u.WinUsb_SetPipePolicy.argtypes = [c.c_void_p, c.c_ubyte, w.ULONG, w.ULONG, c.c_void_p]
        u.WinUsb_SetPipePolicy.restype = w.BOOL
        u.WinUsb_ControlTransfer.argtypes = [c.c_void_p, Setup, c.c_void_p, w.ULONG, c.POINTER(w.ULONG), c.c_void_p]
        u.WinUsb_ControlTransfer.restype = w.BOOL
        file = k.CreateFileW(path, 0xc0000000, 3, None, 3, 0x40000000, None)
        usb = c.c_void_p()
        try:
            if file == c.c_void_p(-1).value: raise c.WinError(c.get_last_error())
            if not u.WinUsb_Initialize(file, c.byref(usb)): raise c.WinError(c.get_last_error())
            timeout = w.ULONG(3000)
            if not u.WinUsb_SetPipePolicy(usb, 0, 3, c.sizeof(timeout), c.byref(timeout)):
                raise c.WinError(c.get_last_error())
            for label, setup in [('device-descriptor', Setup(0x80, 6, 0x100, 0, 18)),
                                 ('device-status', Setup(0x80, 0, 0, 0, 2)),
                                 ('bulk-in-status', Setup(0x82, 0, 0, 0x81, 2)),
                                 ('bulk-out-status', Setup(0x82, 0, 0, 0x02, 2))]:
                data = c.create_string_buffer(setup.length); count = w.ULONG()
                ok = u.WinUsb_ControlTransfer(usb, setup, data, len(data), c.byref(count), None)
                row = dict(request=label, ok=bool(ok), error=0 if ok else c.get_last_error(), bytes=count.value)
                result['replies'].append(row)
                if not ok: raise c.WinError(row['error'])
                o.require(count.value == setup.length, 'Incomplete direct USB control reply')
                raw = data.raw[:count.value]; row['hex'] = raw.hex(); (out / (label + '.bin')).write_bytes(raw)
                if label == 'device-descriptor':
                    o.require(raw[:2] == b'\x12\x01' and struct.unpack_from('<HH', raw, 8) == (0x04e8, 0x685d),
                              'Direct USB descriptor does not match the approved phone')
            result['meaning'] = 'Direct standard USB control replies only; Odin upload protocol and CPU boot not verified'
        except BaseException as exc:
            result.update(error=str(exc), retry=False); raise
        finally:
            if usb.value: u.WinUsb_Free(usb)
            if file != c.c_void_p(-1).value: k.CloseHandle(file)
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__': main()
