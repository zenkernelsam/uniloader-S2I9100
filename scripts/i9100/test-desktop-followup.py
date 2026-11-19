#!/usr/bin/env python3
"""Run the actual gesture script and desktop gate with a modeled native session.

Kernel symbols and desktop/lock pixels are real retained inputs; USB, live
memory and clock are facades. No phone access. Keep successful and failed
evidence under out without deleting any input or temporary artifact.
"""
import argparse,importlib.util,io,json,struct,sys
from contextlib import nullcontext,redirect_stdout
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
here=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,here/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
inject=load('followup_input','inject-touch.py');f=load('followup_wire','forensic-session.py')
memory=load('followup_symbols','live-memory.py');gate=load('followup_gate','ui-frame-gate.py')
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True)
p.add_argument('--desktop',type=Path,required=True);p.add_argument('--locked',type=Path,required=True);a=p.parse_args()
repo=here.parents[1];out=repo/'out'/('desktop-followup-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
kernel_path=a.kernel.resolve();assert kernel_path.is_relative_to(repo/'out');symbols=memory.Symbols(kernel_path)
reference=gate.load_reference(a.desktop,repo);locked=gate.load_reference(a.locked,repo)
profile=json.loads((repo/'out/automation/inventory-20261109-panic-download.json').read_text())
summary=[];native_module=inject.module
for scenario in ('desktop','stayed-locked','asleep','changing-frame','partial-followup','no-touch-reader','bad-reference'):
    directory=out/scenario;clock=[0.0];transports=[];commands=[];reads=[];hid=[0,0,0]
    state=[1,1,0,0,0,0,0,0,0,0,0,0,1,0,1,1];current_pixels=[locked['raw']]
    class Transport:
        def __init__(self,port,record):assert port=='COM12';self.closed=False;transports.append(self)
        def close(self):self.closed=True
    class Session:
        def __init__(self,t,tag,record,capture,**kwargs):self.t=t;self.ready=False;assert tag==symbols.tag
        def handshake(self):self.ready=True
        def command(self,verb):
            assert self.ready;f.validate_command(verb,allow_input_test=True);commands.append(verb);clock[0]+=.2
            values=verb.split();home=values[0]=='hid-home';points=[0,0,0,0] if home else [int(x,16) for x in values[1:5]]
            ms=int(values[-1],16);state[1]=4;state[2]+=1;state[3:8]=[*points,ms];state[8]=2 if home else 23 if points[0]!=points[2] else 6
            state[13]=int(home);hid[0]+=state[8];hid[1]+=0 if home else state[8];hid[2]+=state[8]
            if home and scenario=='no-touch-reader':state[12]=0
            if not home and points[0]!=points[2] and scenario!='stayed-locked':current_pixels[0]=reference['raw']
            if len(commands)==3 and scenario=='partial-followup':raise RuntimeError('Modeled WriteFile partial; no retry')
            return 'OK input-queued',b''
    class Kernel:
        def __init__(self,session,sym):assert sym.tag==symbols.tag
        def read(self,address,size):
            clock[0]+=.05;reads.append((address,size))
            if address==symbols['_i9100_input_test']:assert size==64;return struct.pack('<16I',*state)
            if address==symbols['_i9100_hid_execution_diag']:
                words=[0]*32;words[0]=words[1]=2;words[10]=words[24]=words[26]=1;words[16:19]=hid
                return struct.pack('<32I',*words)[:size]
            if address==symbols['_PE_state']+4:return struct.pack('<5I',0xc0007000,1920,480,800,32)
            if address==symbols['_i9100_graphics_seq']:return struct.pack('<Q',int(clock[0]*100) if scenario=='changing-frame' else 640)
            if address==symbols['_i9100_display_power_diag']:
                return struct.pack('<12I',1,5,int(scenario!='asleep'),0,0,0,int(scenario=='asleep'),0,0,0,0,0)
            raise AssertionError((address,size))
        def u32(self,address):clock[0]+=.05;return 0x43e00000 if address==symbols['_i9100_fb_physical'] else 0
        def read_phys(self,address,size):
            clock[0]+=.3;assert size==16*1920;offset=address-0x43e00000
            return current_pixels[0][offset:offset+size]
    class Host:
        def inventory(self):return [dict(port='COM12',location=profile['location'],service='usbser')]
    fake_odin=SimpleNamespace(confined=lambda path,root:Path(path).resolve(),require=lambda ok,message:None if ok else (_ for _ in ()).throw(RuntimeError(message)),
        normalize_location=lambda value:value,host_lock=lambda:nullcontext(),Host=Host,cdc=lambda values:values[0])
    observed=SimpleNamespace(ObservationSymbols=lambda sym,names:sym,
        capture_ui_observations=lambda *args:dict(hardware=False,hid_counts=dict(callback=hid[0],digitizer=hid[1],gs=hid[2])))
    def module(name,file):
        if file=='forensic-session.py':return SimpleNamespace(REPO=repo,validate_command=f.validate_command,WinTransport=Transport,Session=Session)
        if file=='live-memory.py':return SimpleNamespace(Symbols=memory.Symbols,Kernel=Kernel)
        if file=='odin-loop.py':return fake_odin
        if file=='inspect-mdns.py':return observed
        if file=='ui-frame-gate.py':
            return SimpleNamespace(load_reference=gate.load_reference,
                wait_desktop=lambda k,s,r,o,record:gate.wait_desktop(k,s,r,o,record,lambda:clock[0],lambda t:clock.__setitem__(0,clock[0]+t)))
        return native_module(name,file)
    inject.module=module;old_sleep=inject.time.sleep;old_clock=inject.time.monotonic
    inject.time.sleep=lambda t:clock.__setitem__(0,clock[0]+t);inject.time.monotonic=lambda:clock[0]
    reference_path=a.desktop
    if scenario=='bad-reference':
        reference_path=out/'bad-reference.json';bad=json.loads(a.desktop.read_text());bad['coherent']=False;reference_path.write_text(json.dumps(bad)+'\n')
    sys.argv=['inject-touch.py','--kernel',str(kernel_path),'--output',str(directory),'--wake-first','--swipe','90','726','380','726',
        '--ms','650','--follow-tap','299','471','--follow-ms','150','--wait-desktop',str(reference_path),'--trace']
    failed=False;text=io.StringIO()
    try:
        with redirect_stdout(text):inject.main()
    except (RuntimeError,TimeoutError,ValueError):failed=True
    finally:inject.time.sleep=old_sleep;inject.time.monotonic=old_clock
    (out/(scenario+'-stdout.txt')).write_text(text.getvalue())
    assert failed==(scenario!='desktop')
    assert len(commands)==(0 if scenario=='bad-reference' else 1 if scenario=='no-touch-reader' else 3 if scenario in ('desktop','partial-followup') else 2)
    assert all(t.closed for t in transports)
    if scenario=='desktop':
        result=json.loads((directory/'result.json').read_text());assert result['steps'][1]['desktop_qualification']['ready']
        assert not result['ui_delivery_verified'] and len(result['steps'])==3
    elif directory.exists():
        events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
        assert events[-1]['phase']=='STOP' and events[-1]['retry'] is False
    summary.append(dict(scenario=scenario,failed=failed,commands=commands,opener_count=len(transports),seconds=clock[0]))
inject.module=native_module
(out/'result.json').write_text(json.dumps(dict(result='PASS',cases=summary,hardware=False,
    scope='Actual input orchestration and real reference pixels; USB/live memory/clock facade'),indent=2)+'\n')
print('PASS actual wake/swipe/visible desktop/follow-up ordering, stale locked/asleep/transition rejection and no resend after partial write')
print('EVIDENCE',out)
