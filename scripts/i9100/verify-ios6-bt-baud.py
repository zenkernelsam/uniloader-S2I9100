#!/usr/bin/env python3
"""Execute original UART open and capture default termios for actual baud model."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('original_bt_uart_baud',Path(__file__).with_name('verify-ios6-btserver.py'))
original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--producer',type=Path,help='Audit actual kernel-control/native baud output')
    a=p.parse_args();out=a.output.resolve()
    if not out.is_relative_to(ROOT/'uniloader-S2I9100/out') or out.exists():p.error('Fresh loader/out only')
    image=original.CATALOG.MachO(original.IMAGE)
    if image.uuid!=original.UUID or hashlib.sha256(image.raw).hexdigest()!=original.IMAGE_SHA:raise RuntimeError('Original BTServer changed')
    results={}
    for label,speed in [('default-speed',0),('explicit-115200',115200),('explicit-921600',921600),('explicit-3000000',3000000)]:
        native=original.Native(image,device_speed=speed)
        returned=native.call(0xdf1d8,0,0)
        if returned or native.attributes is None:raise RuntimeError('Original UART setup did not complete')
        attrs=struct.unpack('<4I20s2I',native.attributes)
        target=speed or 2400000
        if attrs[-2:]!=(target,target) or attrs[2]!=0x38b00:raise RuntimeError('Original default baud/format changed')
        results[label]=dict(baud=target,termios_hex=native.attributes.hex(),return_value=returned,
            socket=[c for c in native.calls if c.get('name')=='_socket'],set_option=[c for c in native.calls if c.get('name')=='_setsockopt'])
    producer=None
    if a.producer:
        source=a.producer.resolve()
        if not source.is_relative_to(ROOT/'xnu-S2I9100/out'):p.error('Producer stays in XNU out')
        record=json.loads((source/'manifest.json').read_text());emitted=source/'native-baud.json'
        if record.get('result')!='PASS' or hashlib.sha256(emitted.read_bytes()).hexdigest()!=record.get('native_baud_sha256'):
            raise RuntimeError('Actual native baud producer is incomplete or changed')
        proof=json.loads(emitted.read_text())
        if proof.get('model_fixture') is not True or proof.get('hardware_tested') is not False or proof.get('result')!='PASS':
            raise RuntimeError('Native baud model lost provenance')
        if proof['termios_hex']!=results['default-speed']['termios_hex'] or proof['nominal_baud']!=2400000 or proof['actual_computed_baud']!=2400000:
            raise RuntimeError('Actual native baud output disagrees with original default termios')
        if proof['callback_errno']!=0 or proof['peer_nominal_baud']!=2400000 or proof['early_host_change'] or proof['commands']!=2:
            raise RuntimeError('Actual two-endpoint baud protocol failed')
        producer=dict(path=str(source.relative_to(ROOT)),manifest_sha256=hashlib.sha256((source/'manifest.json').read_bytes()).hexdigest(),
            emitted_sha256=hashlib.sha256(emitted.read_bytes()).hexdigest(),
            scope='Original ARM44B termios equals actual C control/worker/UART model return; socket/proc/controller/clock facades, no hardware')
    report=dict(result='PASS',hardware_tested=False,device_contacted=False,original_image_sha256=original.IMAGE_SHA,
        original_uuid=original.UUID,results=results,producer=producer,
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),dependencies=dict(
            uart_verifier=hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest(),
            macho_analyzer=hashlib.sha256(Path(original.CATALOG.__file__).read_bytes()).hexdigest()),
        scope='Original Cortex-A9 UART configuration/baud selection with libc/socket facade; actual producer optional; no full daemon or electrical acceptance')
    out.mkdir(parents=True);(out/'native-baud.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS original ARM44B termios default2.4Mbps and supported explicit baud values'+('; actual native driver callback output matched' if producer else '')+'; no hardware')


if __name__=='__main__':main()
