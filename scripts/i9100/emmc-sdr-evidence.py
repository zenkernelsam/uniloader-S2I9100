#!/usr/bin/env python3
"""Validate retained original board/voltage evidence for explicit SDR initialization."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[3]

def bounded(path):
    path=Path(path).resolve()
    if not path.is_relative_to(ROOT)or not path.is_file()or not 0<path.stat().st_size<=65536:
        raise ValueError('Use original bounded SDR evidence inside project')
    return path.read_bytes()

def check(board,transport,card,controller,require_reviewed=False):
    required={'schema','kind','model_fixture','board_reviewed','cid','width','high_speed','target_hz','vcc_mv',
      'clock_record_sha256','source_note','voltage_observation','board_sources'}
    if not isinstance(board,dict)or set(board)!=required or board['schema']!=1 or board['kind']!='GT-I9100-SDR':
        raise ValueError('Exact SDR board evidence schema required')
    if type(board['model_fixture'])is not bool or type(board['board_reviewed'])is not bool:
        raise ValueError('Explicit SDR source/review flags required')
    if board['board_reviewed']and board['model_fixture']or require_reviewed and (board['model_fixture']or not board['board_reviewed']):
        raise ValueError('Model or unreviewed board cannot qualify SDR')
    if board['cid']!=card['cid']or any(type(board[k])is not int or board[k]!=v for k,v in transport.items()):
        raise ValueError('SDR board evidence differs from exact card/transport')
    if not isinstance(board['source_note'],str)or not board['source_note'].strip():raise ValueError('Original device/session note required')
    raw_hex=controller.get('clock_record_hex')
    if not isinstance(raw_hex,str)or not re.fullmatch('[0-9a-f]{1024}',raw_hex)or board['clock_record_sha256']!=hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest():
        raise ValueError('SDR board detached from original pre-probe clock record')
    spec=importlib.util.spec_from_file_location('sdr_original_clock',Path(__file__).with_name('emmc-clock-evidence.py'))
    clock=importlib.util.module_from_spec(spec);spec.loader.exec_module(clock)
    captured=clock.decode(bytes.fromhex(raw_hex),require_admitted=True)
    if captured['model_fixture']!=board['model_fixture']:raise ValueError('SDR board review disagrees with actual clock provenance')
    voltage=board['voltage_observation']
    if not isinstance(voltage,dict)or set(voltage)!={'millivolts','method','path','sha256'}or type(voltage['millivolts'])is not int or not 3200<=voltage['millivolts']<=3400:
        raise ValueError('SDR3300mV class needs an original measured VCC observation')
    if not isinstance(voltage['method'],str)or not voltage['method'].strip():raise ValueError('Describe actual VCC measurement method')
    original=bounded(ROOT/voltage['path'])
    if hashlib.sha256(original).hexdigest()!=voltage['sha256']:raise ValueError('Original VCC evidence changed')
    # Board-source references are pinned independently; a note naming MMC
    # cannot itself prove data pad wiring or turn a model into hardware.
    vendor=ROOT/'research/vendor-linux-u1-a0346556/android_kernel_samsung_smdk4210-a0346556698e62405a04b010c4f4197bdc9fec06'
    wanted=('arch/arm/mach-exynos/mach-u1.c','arch/arm/mach-exynos/setup-mshci-gpio.c','drivers/mmc/host/mshci.c','include/linux/mmc/mmc.h')
    if not isinstance(board['board_sources'],dict)or set(board['board_sources'])!=set(wanted):raise ValueError('All original board/pad/controller/EXT_CSD sources required')
    hashes={}
    for name in wanted:
        path=vendor/name;raw=path.read_bytes();actual=hashlib.sha256(raw).hexdigest()
        if board['board_sources'][name]!=actual:raise ValueError('Pinned SDR board source changed')
        hashes[name]=actual
    return dict(result='PASS',source_reviewed=board['board_reviewed'],model_fixture=board['model_fixture'],
      hardware_tested=False,device_contacted=False,voltage_evidence_sha256=voltage['sha256'],board_sources=hashes,
      limitations='Only integrity and explicit source review checked; no electrical measurement is performed by this host validator')
