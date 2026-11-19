#!/usr/bin/env python3
"""Offline HCD preparation round-trip and range/default-address fault checks."""
import importlib.util
import json
from pathlib import Path
from datetime import datetime
from types import SimpleNamespace
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('prepare_bt_hcd',here/'prepare-bt-hcd.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.cap()
out=m.REPO/'out'/('bt-hcd-check-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));out.mkdir()
firmware=bytes.fromhex('4c fc 05 00 00 20 00 ab 4e fc 04 01 00 20 00')
source=out/'fixture.hcd';source.write_bytes(firmware)
rom=dict(hci_version=6,lmp_version=6,hci_revision=1,manufacturer=15,lmp_subversion=0x4103)
proof=out/'controller.json';proof.write_text(json.dumps(dict(rom=rom,patched=dict(rom,hci_revision=2),factory_bdaddr_hci_hex='010203040506'))+'\n')
args=SimpleNamespace(hcd=source,controller_proof=proof,ram_base=0x200000,ram_bytes=0x10000,launch_address=0x200001,timeout_ms=30000,
 source_note='explicit model fixture; not original firmware or actual hardware proof',mark_reviewed=False,output=out/'prepared')
target,record=m.prepare(args);assert len(record['records'])==2 and not record['board_data_reviewed'] and not record['device_contacted']
assert source.read_bytes()==firmware and (target/'firmware.hcd').read_bytes()==firmware
def rejected(f):
 try:f()
 except ValueError:return
 raise AssertionError('Invalid original HCD/controller fixture was accepted')
rejected(lambda:m.prepare(args))
rejected(lambda:m.parse_hcd(firmware[:-1],0x200000,0x10000,0x200001))
rejected(lambda:m.parse_hcd(firmware,0x300000,0x10000,0x300001))
rejected(lambda:m.parse_hcd(firmware+b'\0',0x200000,0x10000,0x200001))
rejected(lambda:m.parse_hcd(bytes.fromhex('01 fc 06 01 02 03 04 05 06')+firmware,0x200000,0x10000,0x200001))
rejected(lambda:m.controller_proof(dict(rom=rom,patched=rom,factory_bdaddr_hci_hex='000000b13043')))
rejected(lambda:m.controller_proof(dict(rom=dict(rom,manufacturer=1),patched=rom,factory_bdaddr_hci_hex='010203040506')))
(out/'test-result.json').write_text(json.dumps(dict(result='PASS',hardware_tested=False,default_reviewed=False,scope='Model HCD round trip/default/range/truncated/vendor opcode/controller source failures; not a firmware compatibility result'),indent=2)+'\n')
print('PASS HCD retained copy/hash/index/profile/defaultOFF/range/truncation/vendor/default-address guards; EVIDENCE',out)
