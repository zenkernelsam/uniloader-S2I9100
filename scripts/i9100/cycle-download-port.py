#!/usr/bin/env python3
"""Query or explicitly cycle only the approved S2 Download USB port.

Windows hub IOCTLs only. No serial opener, Odin packets, partition writes,
driver installation, whole-hub reset, or automatic retry. A port reset is
not proof of CPU recovery or a fresh working Odin protocol session.
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
import uuid

HERE = Path(__file__).resolve().parent
HUB = r'USB\ROOT_HUB30\4&189B8544&0&0'
LOCATION = 'PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)'
PORT = 2


class Guid(c.Structure):
    _fields_ = [('d1', w.DWORD), ('d2', w.WORD), ('d3', w.WORD), ('d4', c.c_ubyte * 8)]


class Interface(c.Structure):
    _fields_ = [('size', w.DWORD), ('guid', Guid), ('flags', w.DWORD), ('reserved', c.c_void_p)]


class Device(c.Structure):
    _fields_ = [('size', w.DWORD), ('guid', Guid), ('instance', w.DWORD), ('reserved', c.c_void_p)]


def connection(raw):
    # USB_NODE_CONNECTION_INFORMATION_EX is packed to one byte: its
    # USHORT address starts at25 and ConnectionStatus at31, not26/32.
    if len(raw) < 35 or struct.unpack_from('<I', raw)[0] != PORT:
        raise ValueError('Wrong or incomplete port connection response')
    if raw[4:6] != b'\x12\x01':
        raise ValueError('Invalid device descriptor')
    vid, pid = struct.unpack_from('<HH', raw, 12)
    status = struct.unpack_from('<I', raw, 31)[0]
    if (vid, pid, status, raw[24]) != (0x04e8, 0x685d, 1, 0):
        raise ValueError('Port is not the connected approved Download phone')
    return dict(vid=f'{vid:04x}', pid=f'{pid:04x}', status=status,
                speed=raw[23], configuration=raw[22], is_hub=raw[24],
                address=struct.unpack_from('<H', raw, 25)[0], bytes=len(raw))


def interface_path(guid_text, expected_instance):
    api = c.WinDLL('setupapi', use_last_error=True)
    api.SetupDiGetClassDevsW.argtypes = [c.POINTER(Guid), w.LPCWSTR, w.HWND, w.DWORD]
    api.SetupDiGetClassDevsW.restype = w.HANDLE
    api.SetupDiEnumDeviceInterfaces.argtypes = [w.HANDLE, c.c_void_p, c.POINTER(Guid), w.DWORD, c.POINTER(Interface)]
    api.SetupDiEnumDeviceInterfaces.restype = w.BOOL
    api.SetupDiGetDeviceInterfaceDetailW.argtypes = [w.HANDLE, c.POINTER(Interface), c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.POINTER(Device)]
    api.SetupDiGetDeviceInterfaceDetailW.restype = w.BOOL
    api.SetupDiGetDeviceInstanceIdW.argtypes = [w.HANDLE, c.POINTER(Device), w.LPWSTR, w.DWORD, c.POINTER(w.DWORD)]
    api.SetupDiGetDeviceInstanceIdW.restype = w.BOOL
    api.SetupDiDestroyDeviceInfoList.argtypes = [w.HANDLE]
    api.SetupDiDestroyDeviceInfoList.restype = w.BOOL
    guid = Guid.from_buffer_copy(uuid.UUID(guid_text).bytes_le)
    devices = api.SetupDiGetClassDevsW(c.byref(guid), None, None, 0x12)
    if devices == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        for index in range(32):
            interface = Interface(); interface.size = c.sizeof(interface)
            if not api.SetupDiEnumDeviceInterfaces(devices, None, c.byref(guid), index, c.byref(interface)):
                if c.get_last_error() == 259:
                    break
                raise c.WinError(c.get_last_error())
            required = w.DWORD()
            api.SetupDiGetDeviceInterfaceDetailW(devices, c.byref(interface), None, 0, c.byref(required), None)
            if not 8 <= required.value <= 65536:
                raise ValueError('Unbounded interface detail')
            detail = c.create_string_buffer(required.value)
            struct.pack_into('<I', detail, 0, 8 if c.sizeof(c.c_void_p) == 8 else 6)
            device = Device(); device.size = c.sizeof(device)
            if not api.SetupDiGetDeviceInterfaceDetailW(devices, c.byref(interface), detail, len(detail), None, c.byref(device)):
                raise c.WinError(c.get_last_error())
            instance = c.create_unicode_buffer(512)
            if not api.SetupDiGetDeviceInstanceIdW(devices, c.byref(device), instance, len(instance), None):
                raise c.WinError(c.get_last_error())
            if instance.value.upper() == expected_instance.upper():
                return detail.raw[4:].decode('utf-16-le').split('\0', 1)[0]
        raise ValueError('Approved device interface absent')
    finally:
        api.SetupDiDestroyDeviceInfoList(devices)


def hub_path():
    return interface_path('f18a0e88-c30c-11d0-8815-00a0c906bed8', HUB)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cycle', action='store_true', help='One explicit port cycle after identity checks; default query only')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Hub access runs on Windows')
    spec = importlib.util.spec_from_file_location('cycle_odin', HERE / 'odin-loop.py')
    odin = importlib.util.module_from_spec(spec); spec.loader.exec_module(odin)
    out = odin.confined(args.output, odin.REPO / 'out')
    odin.require(not out.exists(), 'Fresh evidence directory required')
    profile = json.loads((odin.OUT / 'inventory-20261106-211114-download-profile.json').read_text())
    odin.require(profile['location'] == LOCATION, 'Profile is not the audited USB(2) location')
    with odin.host_lock():
        inventory = odin.Host().inventory()
        actual = odin.download(inventory, profile)
        path = hub_path()
        out.mkdir(parents=True)
        result = dict(time=datetime.now(timezone.utc).isoformat(), download=actual,
                      hub=HUB, interface=path, port=PORT, cycle_attempted=False,
                      flash_writes=0, serial_attempts=0)
        k = c.WinDLL('kernel32', use_last_error=True)
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        k.CreateFileW.restype = w.HANDLE
        k.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        k.DeviceIoControl.restype = w.BOOL
        k.CloseHandle.argtypes = [w.HANDLE]; k.CloseHandle.restype = w.BOOL
        handle = k.CreateFileW(path, 0x40000000, 3, None, 3, 0, None)
        try:
            if handle == c.c_void_p(-1).value:
                raise c.WinError(c.get_last_error())
            data = c.create_string_buffer(1024); struct.pack_into('<I', data, 0, PORT)
            count = w.DWORD()
            if not k.DeviceIoControl(handle, 0x220448, data, len(data), data, len(data), c.byref(count), None):
                raise c.WinError(c.get_last_error())
            result['connection_hex'] = data.raw[:count.value].hex()
            result['connection'] = connection(data.raw[:count.value])
            if args.cycle:
                # Microsoft documents hub cycling on Windows8+ as requiring
                # an Administrator caller. Error31 alone is not a dead CPU.
                shell = c.WinDLL('shell32', use_last_error=True)
                shell.IsUserAnAdmin.restype = w.BOOL
                result['administrator'] = bool(shell.IsUserAnAdmin())
                if not result['administrator']:
                    raise PermissionError('Windows hub cycling requires an Administrator caller; no cycle attempted')
                cycle = c.create_string_buffer(struct.pack('<II', PORT, 0), 8)
                result['cycle_attempted'] = True
                ok = k.DeviceIoControl(handle, 0x220444, cycle, 8, cycle, 8, c.byref(count), None)
                result.update(cycle_ok=bool(ok), cycle_error=0 if ok else c.get_last_error(),
                              cycle_status=struct.unpack_from('<I', cycle.raw, 4)[0])
                if not ok:
                    raise c.WinError(result['cycle_error'])
                if result['cycle_status']:
                    raise RuntimeError('Port cycle returned nonzero USB status')
            result['meaning'] = 'Hub query/cycle result only; CPU and Odin protocol not verified'
        except BaseException as exc:
            result.update(error=str(exc), retry=False)
            raise
        finally:
            if handle != c.c_void_p(-1).value:
                k.CloseHandle(handle)
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
