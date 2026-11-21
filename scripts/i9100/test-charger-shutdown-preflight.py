#!/usr/bin/env python3
"""Exercise the real single-owner pre-halt path with explicit memory stand-ins.

No COM/USB/flash is accessed. Actual kernel symbols are parsed, production
ui-session/preflight code runs, and every refused read/clock/state is retained.
"""
from contextlib import nullcontext
from datetime import datetime,timezone
import argparse,importlib.util,json,struct
from pathlib import Path
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
ui=module('preflight_ui','ui-session.py')
p=module('preflight_actual','charger-shutdown-preflight.py')
repo=HERE.parents[1];out=repo/'out'/('charge-prehalt-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
kernel_file=repo/'out/automation/control-20261121-charge-rtc-live/mach_kernel'
symbols=ui.b.m.Symbols(kernel_file)
assert {'_i9100_lpm_poweroff_ready','_i9100_rtc_read_diag','_i9100_charge_epoch_live'}<=symbols.values.keys()
profile=json.loads((ui.b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
device=dict(instance=ui.b.o.CDC,service='usbser',location=profile['location'],port='COM12',status='OK')
ui.b.o.host_lock=lambda:nullcontext()
class Host:
    def inventory(self):return [device]
ui.b.o.Host=Host
original_module=ui.b.module
ui.b.module=lambda name,file:p if file=='charger-shutdown-preflight.py' else original_module(name,file)
class Clock:
    def __init__(self):self.now=1.0
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=seconds
clock=Clock();ui.time=p.time=clock
ui.process_lease=lambda pid:(1234,1000)
def epoch(sequence,sampled,rtc,full=False):
    words=[0]*32;words[:4]=[0x45433949,2,128,3]
    words[4:9]=[14,1,1,1,1];words[9]=int(full)
    words[14:21]=[int(not full),int(not full),99 if full else 44,4180 if full else 3808,280,0xfffffffc if full else 0,0]
    elapsed=0 if full else 400000000000+sampled-100000000000
    for index,value in ((21,sampled),(23,elapsed),(25,0 if full else 1000000000),(27,rtc)):
        words[index:index+2]=[value&0xffffffff,value>>32]
    words[29]=0;words[30]=sequence
    raw=struct.pack('<32I',*words);words[-1]=p.epoch.checksum(raw);return struct.pack('<32I',*words)
rtc_seconds=p.rtc_time(0x02130129,0x202611,3)
def changed(raw,slot,value):
    words=list(struct.unpack('<32I',raw));words[slot]=value
    words[-1]=p.epoch.checksum(struct.pack('<32I',*words));return struct.pack('<32I',*words)
cases=[]
for scenario in ('healthy-bcd','healthy-binary','healthy-binary12','healthy-native-binary12','healthy-noon-binary12','full','old-invalid-rtc','invalid-rtc','moving-rtc',
                 'frozen-epoch','frozen-rtc','timeout','unknown-clock-format','changed-cycle',
                 'lost-charger','read-error','slow-read','invalid-raw-calendar','unready-worker'):
    directory=out/scenario;clock.now=1.0;commands=[];openers=[];reads=[]
    before=epoch(10,100000000000,rtc_seconds,scenario=='full')
    after=epoch(12,102200000000,rtc_seconds+2,scenario=='full')
    rtc_words=[1,2,15,0x303,0x02130129,0x202611,0x02130129,0x202611,1,rtc_seconds&0xffffffff,rtc_seconds>>32,0]
    if scenario=='healthy-binary':
        rtc_words[3]=0x202;rtc_words[4]=rtc_words[6]=0x020d011d;rtc_words[5]=rtc_words[7]=0x141a0b
    if scenario=='healthy-binary12':
        rtc_words[3]=0;rtc_words[4]=rtc_words[6]=0x0241011d;rtc_words[5]=rtc_words[7]=0x141a0b
    if scenario=='healthy-native-binary12':
        native_seconds=35034
        before=epoch(10,100000000000,native_seconds)
        after=epoch(12,102200000000,native_seconds+2)
        rtc_words=[1,2,15,0,0x01092b36,0x010001,0x01092b36,0x010001,1,native_seconds,0,0]
    if scenario=='healthy-noon-binary12':
        noon_seconds=43780
        before=epoch(10,100000000000,noon_seconds)
        after=epoch(12,102200000000,noon_seconds+2)
        rtc_words=[1,2,15,0,0x014c0928,0x010001,0x014c0928,0x010001,1,noon_seconds,0,0]
    if scenario=='old-invalid-rtc':
        before=(repo/'out/forensic/final-poweroff-20261121-0018/task-0000/charge-epoch-live.bin').read_bytes()
    if scenario=='invalid-rtc':rtc_words[8]=7
    if scenario=='frozen-epoch':after=before
    if scenario=='frozen-rtc':after=epoch(12,102200000000,rtc_seconds)
    if scenario=='timeout':before=changed(before,10,1)
    if scenario=='unknown-clock-format':rtc_words[3]=0x101
    if scenario=='changed-cycle':after=epoch(12,102200000000,rtc_seconds+2,True)
    if scenario=='lost-charger':after=changed(after,7,0)
    if scenario=='invalid-raw-calendar':rtc_words[5]=0x312613
    rtc_raw=struct.pack('<12I',*rtc_words)
    class Transport:
        def __init__(self,port,record):
            assert port=='COM12';self.closed=False;openers.append(self)
        def read(self):raise OSError('Modeled normal disconnect after the authorized halt')
        def close(self):self.closed=True
    class Session:
        def __init__(self,*args,seconds,**kwargs):
            self.deadline=clock.now+seconds;self.receiver=SimpleNamespace(payload=b'')
        def handshake(self):commands.append('ping')
        def command(self,verb):
            assert verb=='poweroff-charge';commands.append(verb);return 'OK poweroff-charge',b''
    class Kernel:
        def __init__(self,session,symbols):self.symbols=symbols
        def u32(self,address):assert address==symbols.values['_i9100_lpm_poweroff_ready'];return int(scenario!='unready-worker')
        def read(self,address,size):
            reads.append((address,size));clock.now+=6 if scenario=='slow-read' else .01
            if scenario=='read-error':raise TimeoutError('Modeled uncertain read: no resend')
            if address==symbols.values['_i9100_charge_epoch_live']:
                return before if sum(a==address for a,n in reads)==1 else after
            assert address==symbols.values['_i9100_rtc_read_diag']
            if size==48:return rtc_raw
            assert size==8;return struct.pack('<2I',1,4 if scenario=='moving-rtc' else 2)
    ui.b.f.WinTransport=Transport;ui.OwnerSession=Session;ui.b.m.Kernel=Kernel
    args=SimpleNamespace(kernel=kernel_file,output=directory,seconds=240,
        allow_poweroff_charge=True,allow_reboot_download=False,require_charge_epoch=True,
        poweroff_on_ready=True,charge_on_ready=False,on_ready=[])
    expected=scenario in ('healthy-bcd','healthy-binary','healthy-binary12','healthy-native-binary12','healthy-noon-binary12','full')
    failed=False
    try:ui.serve(args)
    except (ValueError,TimeoutError):failed=True
    assert failed!=expected and len(openers)==1 and openers[0].closed
    assert commands.count('poweroff-charge')==int(expected)
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    assert events[-1]['phase']=='CLOSED'
    if expected:
        assert p.verify_retained(directory/'task-0001/poweroff-preflight',symbols.tag)['qualified']
        assert sum(row['phase']=='POWEROFF_PREFLIGHT_OK' for row in events)==1
    else:
        assert any(row['phase']=='STOP' for row in events)
        assert not any(row['phase']=='POWEROFF_PREFLIGHT_OK' for row in events)
    cases.append(dict(scenario=scenario,halt_commands=commands.count('poweroff-charge'),
                      raw_reads=len(reads),one_opener_closed=True,hardware=False))
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,cases=cases,
    actual_path='Production ui-session.serve invokes production preflight before halt',
    limitation='COM transport and live memory are stand-ins. No physical charge or shutdown tested.'),indent=2)+'\n')
print('PASS production owner: valid RTC precedes halt, 13 bad/frozen/uncertain cases issue no halt, one normal close')
print('EVIDENCE',out)
