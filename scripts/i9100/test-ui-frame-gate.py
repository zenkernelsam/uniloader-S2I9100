#!/usr/bin/env python3
"""Verify desktop qualification against real retained home and lockscreen frames.

No device opener/input. Reference pixels and hash are real; physical reads,
sequence and timing are modeled. Retain all sample/error evidence under out.
"""
import argparse,importlib.util,json,struct
from pathlib import Path
from datetime import datetime
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('frame_gate',here/'ui-frame-gate.py')
g=importlib.util.module_from_spec(s);s.loader.exec_module(g)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--desktop',type=Path,required=True);p.add_argument('--locked',type=Path,required=True)
a=p.parse_args();repo=here.parents[1];reference=g.load_reference(a.desktop,repo);locked=g.load_reference(a.locked,repo)
out=repo/'out'/('ui-frame-gate-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir();cases=[]
symbols={'_PE_state':0x1000,'_i9100_fb_physical':0x2000,'_i9100_graphics_seq':0x3000,'_i9100_panel_console_enabled':0x4000,'_i9100_display_power_diag':0x5000}
class Symbols:
    def __init__(self,data):self.values=data
    def __getitem__(self,key):return self.values[key]
for scenario in ('desktop','locked','transition','console','truncated','wrong-geometry','asleep','power-transition','symbols-object'):
    timer=[0.0];reads=[]
    class Kernel:
        def u32(self,at):timer[0]+=.05;return 0x43e00000 if at==0x2000 else int(scenario=='console')
        def read(self,at,n):
            timer[0]+=.1
            if at==0x1004:return struct.pack('<5I',0xc0007000,1920,360 if scenario=='wrong-geometry' else 480,800,32)
            if at==0x5000 and n==48:
                return struct.pack('<12I',1,int(timer[0]*100) if scenario=='power-transition' else 5,
                    0 if scenario=='asleep' else 1,0,0,0,1 if scenario=='asleep' else 0,0,0,0,0,0)
            assert at==0x3000 and n==8
            return struct.pack('<Q',100+int(timer[0]*100) if scenario=='transition' else 100)
        def read_phys(self,at,n):
            reads.append((at,n));timer[0]+=.5
            assert n==16*1920 and at>=0x43e00000
            offset=at-0x43e00000;data=(locked if scenario=='locked' else reference)['raw'][offset:offset+n]
            return data[:-1] if scenario=='truncated' else data
    failed=False
    try:result=g.wait_desktop(Kernel(),Symbols(symbols) if scenario=='symbols-object' else symbols,reference,out/scenario,clock=lambda:timer[0],sleep=lambda t:timer.__setitem__(0,timer[0]+t))
    except (ValueError,TimeoutError):failed=True
    assert failed==(scenario not in ('desktop','symbols-object'))
    if scenario in ('desktop','symbols-object'):assert result['ready'] and len(reads)==2 and timer[0]<3
    assert all(n<=32768 for _,n in reads)
    cases.append(dict(scenario=scenario,failed=failed,reads=len(reads),seconds=timer[0]))
published=json.loads((out/'locked/result.json').read_text());assert not published['ready']
assert all(not x['ready'] for x in published['samples'])
(out/'result.json').write_text(json.dumps(dict(result='PASS',cases=cases,hardware=False),indent=2)+'\n')
print('PASS actual desktop/reference SHA, locked/transition/console refusal, bounded band reads, short read and geometry rejection')
print('EVIDENCE',out)
