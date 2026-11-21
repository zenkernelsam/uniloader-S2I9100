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
    raw=record(1,0x201 if case=='failed-stop' else 0x101,case!='old-source')
    if case=='bad-crc':raw=raw[:-1]+bytes([raw[-1]^1])
    if case=='missing':raw=bytes(128)
    if case=='partial-read':raw=raw[:-1]
    stopped=False
    try:parsed=m.decode(raw,source)
    except ValueError:stopped=True
    assert stopped==(case in ('bad-crc','missing','partial-read'))
    if not stopped:
        assert parsed['source_matches']==(case!='old-source')
        assert parsed['stop_result']==('failed-stop' if case=='failed-stop' else 'confirmed-off')
    cases.append(dict(case=case,rejected=stopped,hardware=False))

class Session:
    def command(self,verb):
        raise AssertionError(f'Legacy BUILD issued an unsafe trace read: {verb}')

result=m.capture(Session(),out/'unsupported-build',tag,package)
assert result['available'] is False and result['records']=={}
assert json.loads((out/'unsupported-build/result.json').read_text())==result
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,cases=cases),indent=2)+'\n')
print('PASS offline trace decoding and zero serial commands for a BUILD without a mapped trace export')
print('EVIDENCE',out)
