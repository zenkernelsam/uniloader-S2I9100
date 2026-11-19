#!/usr/bin/env python3
"""Raw HCI proof exporter fault/round-trip checks without controller contact."""
import importlib.util
import json
from pathlib import Path
import struct
from datetime import datetime
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('bt_proof_export',Path(__file__).with_name('export-bt-controller-proof.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.guard.cap()
out=m.REPO/'out'/('bt-proof-check-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));out.mkdir()
def proof(revision):
    return dict(schema=1,kind='i9100-bt-rom-probe',model_fixture=True,completed=True,fault=False,error=0,cleanup_error=0,valid_fields=31,generation=1,
        raw=dict(version=struct.pack('<BBHBHH',0,6,revision,6,15,0x4103).hex(),name=(b'\0BCM4330B1'+bytes(239)).hex(),
        address=bytes([0,1,2,3,4,5,6]).hex(),buffer=bytes.fromhex('00 fd 03 40 08 00 00 00').hex(),features=(b'\0'+bytes(8)).hex()))
rom=out/'rom.json';patched=out/'patched.json';rom.write_text(json.dumps(proof(1)));patched.write_text(json.dumps(proof(2)))
args=SimpleNamespace(rom=rom,patched=patched,source_note='Original-shaped test replies only',mark_reviewed=False,output=out/'export')
target,result=m.export(args);assert result['model_fixture'] and not result['board_data_reviewed']
value=json.loads((target/'controller-proof.json').read_text());assert value['rom']['hci_revision']==1 and value['patched']['hci_revision']==2 and value['model_fixture']
def reject(f):
    try:f()
    except ValueError:return
    raise AssertionError('Bad original controller proof accepted')
reject(lambda:m.export(args))
firmware=out/'fixture.hcd';firmware.write_bytes(bytes.fromhex('4c fc 05 00 00 20 00 ab 4e fc 04 01 00 20 00'))
hcd_args=SimpleNamespace(hcd=firmware,controller_proof=target/'controller-proof.json',ram_base=0x200000,ram_bytes=0x10000,
    launch_address=0x200001,timeout_ms=10000,source_note='model export propagation',mark_reviewed=True,output=out/'bad-review')
reject(lambda:m.guard.prepare(hcd_args))
args.output=out/'reviewed';args.mark_reviewed=True;reject(lambda:m.export(args));args.mark_reviewed=False
bad=proof(2);bad['raw']['address']='00000000b13043';patched.write_text(json.dumps(bad));args.output=out/'different';reject(lambda:m.export(args))
bad=proof(2);bad['valid_fields']=1;patched.write_text(json.dumps(bad));reject(lambda:m.export(args))
(out/'test-result.json').write_text(json.dumps(dict(result='PASS',hardware_tested=False,scope='Recorded raw HCI replies only; separate ROM/patched, exact bytes/status/BDADDR, model-review and output guards'),indent=2)+'\n')
print('PASS raw ROM/patched proof export and review/identity/length/overwrite guards; EVIDENCE',out)
