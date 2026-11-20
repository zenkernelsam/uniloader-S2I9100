#!/usr/bin/env python3
"""Bind optional IDMAC32 admission to original card/host evidence; no device access."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[3]
def check(record,card,controller,require_reviewed=False):
    expected={'schema','kind','model_fixture','board_reviewed','cid','host_physical','clock_record_sha256','source_note','descriptor_bits','dma_interface'}
    if not isinstance(record,dict)or set(record)!=expected or type(record['schema'])is not int or record['schema']!=1 or record['kind']!='GT-I9100-IDMAC32':
        raise ValueError('Exact original IDMAC32 evidence schema required')
    if type(record['model_fixture'])is not bool or type(record['board_reviewed'])is not bool or record['model_fixture']and record['board_reviewed']:
        raise ValueError('Explicit original IDMAC source/review required')
    if require_reviewed and (record['model_fixture']or not record['board_reviewed']):raise ValueError('Model or unreviewed IDMAC evidence cannot qualify deployment')
    if not isinstance(record['cid'],list)or len(record['cid'])!=4 or any(type(value)is not int or not 0<=value<1<<32 for value in record['cid']):
        raise ValueError('Exact original CID words required')
    if record['cid']!=card['cid']or type(record['host_physical'])is not int or record['host_physical']!=0x12550000 or record['descriptor_bits']!=32 or type(record['descriptor_bits'])is not int or record['dma_interface']!=0 or type(record['dma_interface'])is not int:
        raise ValueError('IDMAC evidence differs from original card/32bit host')
    if not isinstance(record['source_note'],str)or not record['source_note'].strip():raise ValueError('Describe original host/owner observation')
    if not isinstance(controller,dict)or type(controller.get('schema'))is not int or controller['schema']!=2 or controller.get('host_physical')!=0x12550000 or controller.get('model_fixture')is not record['model_fixture']:
        raise ValueError('Original matching controller provenance required')
    if require_reviewed and controller.get('clock_and_pins_reviewed')is not True:raise ValueError('Original inherited clocks/pins have not been reviewed')
    raw_hex=controller.get('clock_record_hex')
    if not isinstance(raw_hex,str)or not re.fullmatch('[0-9a-f]{1024}',raw_hex):raise ValueError('Original complete clock/host observation required')
    if not isinstance(record['clock_record_sha256'],str)or not re.fullmatch('[0-9a-f]{64}',record['clock_record_sha256']):raise ValueError('Exact original clock SHA256 required')
    raw=bytes.fromhex(raw_hex)
    if hashlib.sha256(raw).hexdigest()!=record['clock_record_sha256']:raise ValueError('IDMAC evidence detached from original clock/host capture')
    path=Path(__file__).with_name('emmc-clock-evidence.py')
    if controller.get('clock_decoder_sha256')!=hashlib.sha256(path.read_bytes()).hexdigest():raise ValueError('Original clock decoder source changed')
    spec=importlib.util.spec_from_file_location('idmac_clock',path);clock=importlib.util.module_from_spec(spec);spec.loader.exec_module(clock)
    capture=clock.decode(raw,require_admitted=True)
    if capture['model_fixture']!=record['model_fixture']or capture['registers']!=controller.get('registers') or capture['ciu_clock_hz']!=controller.get('ciu_clock_hz'):
        raise ValueError('Original IDMAC model/clock/register provenance disagrees')
    hcon=capture['registers']['host_hcon'];version=capture['registers']['host_version']&65535
    if (hcon>>7)&7!=1 or (hcon>>16)&3!=0 or not 0x2000<=version<0x240a:
        raise ValueError('Host is not the reviewed older IDMAC32 generation')
    if capture['registers']['host_bmod']&1 or capture['registers']['host_idsts']&(15<<13):
        raise ValueError('Original IDMAC engine is still reset or active')
    return dict(result='PASS',model_fixture=record['model_fixture'],source_reviewed=record['board_reviewed'],
      host_version=version,host_hcon=hcon,device_contacted=False,hardware_tested=False,
      limitations='Integrity and explicit source review only; native allocation rechecks both Normal-NC aliases; physical DMA performance is unproven')
