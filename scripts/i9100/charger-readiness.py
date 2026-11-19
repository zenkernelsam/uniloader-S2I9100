"""Read-only readiness for the exact S2 charger COM interface.

PnP can publish a COM name before its DOS link exists. QueryDosDevice checks
that link without creating a serial handle, issuing DTR or querying serial
WMI. No opener retry is implemented here or in callers.
"""
import os,re,time

CHARGER=r'USB\VID_0525&PID_A4A7\S2I9100-CHG'

def native_target(port):
    if os.name!='nt' or not re.fullmatch(r'COM[0-9]+',port or ''):
        raise ValueError('Windows COM port required for native readiness')
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.QueryDosDeviceW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32]
    kernel.QueryDosDeviceW.restype=ctypes.c_uint32
    buffer=ctypes.create_unicode_buffer(32768)
    ctypes.set_last_error(0)
    count=kernel.QueryDosDeviceW(port,buffer,len(buffer))
    if not count:
        error=ctypes.get_last_error()
        if error==2:return None
        raise ctypes.WinError(error)
    value=buffer.value
    if not value.upper().startswith('\\DEVICE\\USBSER'):
        raise ValueError('Charger COM link is not a native USB serial interface')
    return value

def wait_charger(host,profile,seconds,record,target=None,clock=time.monotonic,sleep=time.sleep):
    if not 0<=seconds<=1800:raise ValueError('Bounded charger readiness wait required')
    target=target or native_target;deadline=clock()+seconds;previous=None
    while True:
        devices=host.inventory()
        candidates=[device for device in devices if device.get('instance','').upper()==CHARGER]
        if len(candidates)>1:raise ValueError('Distinct charger identity ambiguous; no opener')
        device=candidates[0] if candidates else None;current=None
        if device:
            if device.get('service','').lower()!='usbser' or device.get('location','').upper().split('#USBMI(')[0]!=profile['location'].upper():
                raise ValueError('Charger driver/topology differs; no opener')
            if device.get('status')=='OK' and re.fullmatch(r'COM[0-9]+',device.get('port','')):
                native=target(device['port'])
                if native:current=(device['instance'].upper(),device['port'],native)
        if current and (previous==current or seconds==0):
            record('CHARGER_INTERFACE_READY',port=device['port'],native=current[2],
                stable_observations=1 if seconds==0 else 2,serial_openers=0)
            return device
        if clock()>=deadline:raise TimeoutError('Charger PnP/DOS interface not ready; no opener attempted')
        previous=current;sleep(min(1,max(0,deadline-clock())))
