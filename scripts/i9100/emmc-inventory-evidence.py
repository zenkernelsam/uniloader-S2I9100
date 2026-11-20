#!/usr/bin/env python3
"""Validate exact current eMMC evidence bytes against a supplied native profile."""
import json
import struct
import zlib
import hashlib
import importlib.util
from pathlib import Path

def u32(value):
    if type(value)is not int or not 0<=value<1<<32:raise ValueError('Invalid unsigned evidence field')
    return value
def gpt(raw,sectors,self_lba):
    if len(raw)<1024 or len(raw)%512:raise ValueError('Require header512 followed by complete GPT entries')
    header=bytearray(raw[:512]);size=struct.unpack_from('<I',header,12)[0];stored=struct.unpack_from('<I',header,16)[0]
    if header[:8]!=b'EFI PART' or struct.unpack_from('<I',header,8)[0]!=0x10000 or not 92<=size<=512 or any(header[20:24]):raise ValueError('Invalid GPT header')
    header[16:20]=bytes(4)
    if zlib.crc32(header[:size])!=stored:raise ValueError('GPT header CRC invalid')
    current,other,first,last=struct.unpack_from('<4Q',header,24);array,count,stride,entries_crc=struct.unpack_from('<QIII',header,72)
    if current!=self_lba or other!=(sectors-1 if self_lba==1 else 1) or not 2<=first<=last<sectors-1 or not 1<=count<=128 or stride!=128:
        raise ValueError('GPT geometry invalid')
    needed=count*128;entries=raw[512:512+needed]
    if len(raw)!=512+((needed+511)&~511) or zlib.crc32(entries)!=entries_crc:raise ValueError('GPT array/length CRC invalid')
    blocks=(needed+511)//512
    if array<2 or array+blocks>sectors or (self_lba==1 and array+blocks>first) or (self_lba!=1 and not last<array<self_lba):
        raise ValueError('GPT array location invalid')
    parts=[];guid=set();names=set()
    for n in range(count):
        item=entries[n*128:(n+1)*128]
        if not any(item[:16]):continue
        lo,hi=struct.unpack_from('<QQ',item,32);full_name=item[56:128].decode('utf-16le');name=full_name.split('\0',1)[0]
        if '\0' in full_name and any(full_name[len(name):].replace('\0','')):raise ValueError('GPT name has nonzero trailing characters')
        if not any(item[16:32]) or item[16:32] in guid or not first<=lo<=hi<=last or name in names or not name or not name.isascii():
            raise ValueError('Malformed GPT partition identity/geometry')
        if any(lo<p['start_lba']+p['sectors'] and p['start_lba']<=hi for p in parts):raise ValueError('Overlapping partitions')
        guid.add(item[16:32]);names.add(name);parts.append(dict(number=n+1,name=name,start_lba=lo,sectors=hi-lo+1,unique_guid=item[16:32].hex()))
    return dict(crc=stored,entries_crc=entries_crc,disk_guid=bytes(header[56:72]).hex(),first=first,last=last,parts=parts,entries=entries)

def check(profile,raws,model,clock_reviewed):
    if set(raws)!={'cid','gpt-primary','gpt-backup','pit','controller'}:raise ValueError('Require CID/twoGPT/PIT/controller original evidence')
    card=profile['card'];host=profile['host'];sectors=card['sectors']
    if len(raws['cid'])!=16 or struct.unpack('<4I',raws['cid'])!=tuple(card['cid']):raise ValueError('Current CID words disagree')
    primary=gpt(raws['gpt-primary'],sectors,1);backup=gpt(raws['gpt-backup'],sectors,sectors-1)
    if primary['entries']!=backup['entries'] or primary['disk_guid']!=backup['disk_guid'] or primary['first']!=backup['first'] or primary['last']!=backup['last']:
        raise ValueError('Primary/backup table mismatch')
    if (primary['crc'],backup['crc'],primary['entries_crc'],primary['disk_guid'])!=(card['primary_crc'],card['backup_crc'],card['entries_crc'],card['disk_guid']):
        raise ValueError('Current GPT evidence does not match approved card fields')
    parts={p['name']:p for p in primary['parts']}
    if len(parts)!=12:raise ValueError('This driver requires the original complete 12-partition table')
    for role,name,start,count,number,pitid in (('system','FACTORYFS',344064,3145728,9,10),('data','DATAFS',3489792,12582912,10,11)):
        p=parts.get(name)
        if not p or (p['start_lba'],p['sectors'],p['number'],p['unique_guid'])!=(start,count,number,card[role+'_guid']):raise ValueError('Different native volume partition')
    pit=raws['pit']
    if len(pit)<28 or struct.unpack_from('<I',pit)[0]!=0x12349876:raise ValueError('Invalid PIT evidence')
    count=struct.unpack_from('<I',pit,4)[0]
    if not 1<=count<=32 or len(pit)!=28+count*132:raise ValueError('PIT entries/length mismatch')
    found={};used=set()
    for n in range(count):
        item=pit[28+n*132:28+(n+1)*132];name_raw=item[36:68]
        if b'\0' not in name_raw:raise ValueError('Unterminated PIT name')
        name=name_raw.split(b'\0',1)[0].decode('ascii')
        if name in parts:
            kind,device,identifier=struct.unpack_from('<III',item);start,sectors=struct.unpack_from('<II',item,20)
            if name in found or identifier in used or (kind,device,start,sectors)!=(0,2,parts[name]['start_lba'],parts[name]['sectors']):raise ValueError('PIT/GPT disagreement')
            found[name]=identifier;used.add(identifier)
    if set(found)!=set(parts) or found['FACTORYFS']!=10 or found['DATAFS']!=11:raise ValueError('Incomplete PIT role mapping')
    controller=json.loads(raws['controller'])
    required={'schema','model_fixture','ciu_clock_hz','clock_and_pins_reviewed','host_physical','registers','measurement_note'}
    if controller.get('schema')==2:required|={'clock_record_hex','clock_decoder_sha256'}
    if set(controller)!=required or controller['schema']not in (1,2) or controller['model_fixture']is not model or controller['clock_and_pins_reviewed']is not clock_reviewed:
        raise ValueError('Controller evidence provenance mismatch')
    if controller['host_physical']!=0x12550000 or controller['ciu_clock_hz']!=host['ciu_clock_hz'] or not isinstance(controller['measurement_note'],str) or not controller['measurement_note'].strip():
        raise ValueError('CIU measurement/provenance missing')
    keys={'cmu_ip_gate','cmu_source_gate','source_mux','source_divider','clksel','gpk0_mux','gpk0_pull','gpk0_drive','gpk0_data','gic_enable'}
    decoded=None
    if controller['schema']==2:
        tool=Path(__file__).with_name('emmc-clock-evidence.py')
        if controller['clock_decoder_sha256']!=hashlib.sha256(tool.read_bytes()).hexdigest():raise ValueError('Clock decoder source drift')
        spec=importlib.util.spec_from_file_location('emmc_clock',tool);clock=importlib.util.module_from_spec(spec);spec.loader.exec_module(clock)
        raw_hex=controller['clock_record_hex']
        if not isinstance(raw_hex,str)or len(raw_hex)!=1024 or any(c not in '0123456789abcdef'for c in raw_hex):raise ValueError('Exact512B clock record required')
        decoded=clock.decode(bytes.fromhex(raw_hex),require_admitted=True);keys=set(clock.FIELDS)
        if decoded['model_fixture']is not model or decoded['registers']!=controller['registers'] or decoded['ciu_clock_hz']!=host['ciu_clock_hz'] or decoded['xxti_hz']!=host.get('xxti_hz')or decoded['xusbxti_hz']!=host.get('xusbxti_hz'):
            raise ValueError('Clock record/root frequencies disagree with actual profile')
    elif not model or clock_reviewed:
        raise ValueError('Legacy hand-entered controller capture cannot become hardware reviewed')
    regs=controller['registers']
    if set(regs)!=keys:raise ValueError('Incomplete inherited controller register capture')
    for name,value in regs.items():u32(value)
    if not regs['cmu_ip_gate']&(1<<9) or not regs['cmu_source_gate']&(1<<16) or regs['gic_enable']&(1<<13) or not regs['gpk0_data']&4:
        raise ValueError('Controller clocks/power/IRQ owner do not match native admission')
    for field,mask in (('source_mux',0xf0000),('source_divider',0xff0f),('clksel',0xffffffff),('gpk0_mux',0xffff),('gpk0_pull',0xff),('gpk0_drive',0xff)):
        if regs[field]&mask!=host[field]:raise ValueError('Inherited host profile does not match current controller capture')
    return dict(primary_crc=primary['crc'],backup_crc=backup['crc'],entries_crc=primary['entries_crc'],partitions=12,
                pit_count=count,controller_evidence_only=True,clock_record_verified=decoded is not None,actual_electrical_measurement_verified=False)
