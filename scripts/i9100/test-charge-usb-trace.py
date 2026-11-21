#!/usr/bin/env python3
"""Verify actual trace retention/decoding with an existing-owner stand-in."""
import importlib.util,json,struct
from pathlib import Path
from datetime import datetime
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('usb_trace_test',HERE/'inspect-charge-usb.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
repo=HERE.parents[1];out=repo/'out'/('charge-usb-trace-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
tag='0123456789abcdef';loader='fedcba9876543210';source=m.fingerprint(tag,loader)
package=out/'package';package.mkdir();(package/'manifest.json').write_text(json.dumps(dict(control_tag=tag,standalone_charge_control_tag=loader)))
def record(fault=0,proof=0,matched=True):
    words=[0]*32;words[:8]=[m.MAGIC,1,128,7,24000000,0,3 if fault else 2,proof]
    words[8]=100;words[27]=fault;words[29]=source if matched else source^1
    raw=struct.pack('<32I',*words);words[-1]=m.fnv(raw[:-4]);return struct.pack('<32I',*words)
cases=[]
for case in ('healthy','failed-stop','old-source','bad-crc','missing','partial-read'):
    directory=out/case;commands=[];raw=record(1,0x201 if case=='failed-stop' else 0x101,case!='old-source')
    if case=='bad-crc':raw=raw[:-1]+bytes([raw[-1]^1])
    if case=='missing':raw=bytes(128)
    class Session:
        def command(self,verb):
            commands.append(verb);assert verb in ('read-memory 7ffe0300 80','read-memory 7ffe0400 80')
            address=verb.split()[1];payload=raw[:-1] if case=='partial-read' else raw
            return f'OK DATA {address} 00000080',payload
    stopped=False
    try:result=m.capture(Session(),directory,tag,package)
    except ValueError:stopped=True
    assert stopped==(case=='partial-read') and len(commands)==(1 if stopped else 2)
    if not stopped:
        parsed=result['records']['fault'];assert parsed['available']==(case not in ('bad-crc','missing'))
        assert (directory/'fault.bin').read_bytes()==raw
        if parsed['available']:
            assert parsed['source_matches']==(case!='old-source')
            assert parsed['stop_result']==('failed-stop' if case=='failed-stop' else 'confirmed-off')
    cases.append(dict(case=case,read_commands=len(commands),stop=stopped,hardware=False))
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,cases=cases),indent=2)+'\n')
print('PASS original RAM bytes, CRC/source checks, immutable stop outcome and partial-read refusal without another command')
print('EVIDENCE',out)
