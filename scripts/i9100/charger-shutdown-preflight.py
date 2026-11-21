#!/usr/bin/env python3
"""Qualify a normal charging shutdown on the existing verified kernel owner.

This module never opens a port, sends a reboot, writes clock state or retries a
failed read. Original bytes are retained before qualification. Only the caller
may issue its already authorized halt after this one bounded observation.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preflight_epoch',HERE/'charge-handoff.py')
epoch=importlib.util.module_from_spec(spec);spec.loader.exec_module(epoch)

def require(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def rtc_checksum(raw):
    require(len(raw)==48,'Exact sealed RTC size required')
    value=2166136261
    for byte in raw[:-4]:value=((value^byte)*16777619)&0xffffffff
    return value

def rtc_publication(raw,header_after):
    require(len(raw)==48 and len(header_after)==8,'Exact RTC publication evidence required')
    words=struct.unpack('<12I',raw);version,sequence=words[:2]
    after_version,after_sequence=struct.unpack('<2I',header_after)
    require(version in (1,2) and sequence>0 and not sequence&1 and after_version==version,
            'RTC publisher is incomplete or changed format')
    if version==1:
        require(words[11]==0 and after_sequence==sequence,'Legacy RTC publisher changed or is incomplete')
    else:
        require(words[11]==rtc_checksum(raw),'RTC sealed publication checksum differs')
        require(sequence<=after_sequence<=sequence+2,'RTC publication reset or advanced beyond the single read window')
    return dict(version=version,sequence=sequence,producer_sequence_after=after_sequence,
                sealed=version==2,publication_advanced=after_sequence!=sequence)

def rtc_time(low,high,control):
    require(not high>>24,'RTC time has reserved bytes')
    raw=struct.pack('<II',low,high)[:7]
    require(control&3!=1,'Unsupported RTC BCD12 format')
    def number(value):
        if control&1:
            require(value&15<=9 and value>>4<=9,'Invalid packed BCD time')
            return (value>>4)*10+(value&15)
        return value
    mode24=bool(control&2)
    hour_mask=(0x3f if control&1 else 0x1f) if mode24 else 0x0f
    require(not raw[2]&~(hour_mask|0x40),'RTC hour reserved bits')
    require(raw[3] in (1,2,4,8,16,32,64),'RTC weekday is not one-hot')
    second,minute,hour,month,year,day=(number(raw[0]),number(raw[1]),
        number(raw[2]&hour_mask),number(raw[4]),number(raw[5]),number(raw[6]))
    require(0<=hour<24 if mode24 else 1<=hour<=12,'RTC hour range')
    if not mode24:
        if hour==12:hour=0
        if raw[2]&0x40:hour+=12
    require(year<=(99 if control&1 else 127),'RTC year range')
    current=datetime(2000+year,month,day,hour,minute,second,tzinfo=timezone.utc)
    return int((current-datetime(2000,1,1,tzinfo=timezone.utc)).total_seconds())

def qualify(before,rtc_raw,rtc_after,after,tag,duration_seconds):
    require(len(rtc_raw)==48 and len(rtc_after)==8,'Exact RTC evidence required')
    first,last=epoch.decode_epoch(before,0),epoch.decode_epoch(after,0)
    require(0<=duration_seconds<=5,'Shutdown observation exceeded its freshness budget')
    require(first['sequence']<last['sequence'] and
        2000000000<=last['sampled_ns']-first['sampled_ns']<=5000000000,
        'Charging publication did not advance within the live pre-halt observation')
    for row in (first,last):
        require(row['valid']==row['present']==row['connected']==1 and
            not row['timeout'] and not row['thermal_block'] and row['reason'] in (0,-4),
            'Current charging epoch is invalid, disconnected or blocked')
        require(row['sampled_ns']>0 and row['rtc_seconds']>0 and
            2500<=row['millivolts']<=4300 and 50<=row['temperature_deci_c']<=400,
            'Epoch lacks a valid voltage/temperature/RTC sample')
        require((row['full'] and not row['enabled'] and not row['charging']) or
            (not row['full'] and row['enabled'] and row['charging'] and row['elapsed_ns']>0),
            'Charging enable and measured state do not match the epoch')
        limit=(5400 if row['recharging'] else 18000)*1000000000
        require(row['elapsed_ns']<limit,'Original charging safety period already expired')
    require(first['revision']==last['revision'] and first['sub_charger']==last['sub_charger'] and
        first['full']==last['full'] and first['recharging']==last['recharging'] and
        first['elapsed_ns']<=last['elapsed_ns'],'Charging cycle changed during the single observation')
    words=struct.unpack('<12I',rtc_raw)
    publication=rtc_publication(rtc_raw,rtc_after)
    require(words[2]==15 and words[8]==1 and
        words[3]<=0xffff and words[3]&255==words[3]>>8,'RTC transaction is not a completed stable read')
    control=words[3]&255
    start,end=rtc_time(words[4],words[5],control),rtc_time(words[6],words[7],control)
    seconds=(words[10]<<32)|words[9]
    require(start<=end<=start+1 and seconds==end,'RTC raw bytes differ from the published clock')
    require(first['rtc_seconds']<=seconds<=last['rtc_seconds'] and
        1<=last['rtc_seconds']-first['rtc_seconds']<=6,
        'Battery-backed RTC did not advance with the live charging publication')
    return dict(qualified=True,kernel_tag=tag,epoch_before=first,epoch_after=last,
        rtc=dict(**publication,controls=words[3],seconds=seconds,
                 mode=('BCD24' if control&1 else 'binary24') if control&2 else 'binary12'),
        duration_seconds=duration_seconds,
        raw_sha256={name:sha(raw) for name,raw in (
            ('epoch-before.bin',before),('rtc-read.bin',rtc_raw),
            ('rtc-read-after.bin',rtc_after),('epoch-after.bin',after))},
        limit='One completed pre-halt observation. Actual sealed next-boot epoch must still qualify independently.')

def capture(kernel,symbols,target):
    require(not target.exists(),'Fresh preflight evidence required')
    target.mkdir();began=time.monotonic()
    try:
        require('_i9100_charge_epoch_live' in symbols.values and '_i9100_rtc_read_diag' in symbols.values,
                'Kernel lacks raw charging deadline/RTC evidence; halt not sent')
        epoch_address=symbols.values['_i9100_charge_epoch_live']
        rtc_address=symbols.values['_i9100_rtc_read_diag']
        retained={}
        for name,address,count in (('epoch-before.bin',epoch_address,128),
                ('rtc-read.bin',rtc_address,48),('rtc-read-after.bin',rtc_address,8),
                ('epoch-after.bin',epoch_address,128)):
            if name=='epoch-after.bin':
                # One fresh Power tick must occur during this observation.
                # A frozen but CRC-valid RAM record cannot authorize halt.
                time.sleep(2.1)
            require(time.monotonic()-began<5,'Pre-halt read budget elapsed; no retry')
            raw=kernel.read(address,count);(target/name).write_bytes(raw);retained[name]=raw
        result=qualify(retained['epoch-before.bin'],retained['rtc-read.bin'],
                retained['rtc-read-after.bin'],retained['epoch-after.bin'],
                symbols.tag,time.monotonic()-began)
        (target/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
        return result
    except BaseException as error:
        (target/'STOP.json').write_text(json.dumps(dict(qualified=False,error=str(error),
             kernel_tag=symbols.tag,halt_sent=False,retry=False),indent=2)+'\n',encoding='utf8')
        raise

def verify_retained(target,tag):
    value=json.loads((target/'result.json').read_text(encoding='utf8'))
    result=qualify(*((target/name).read_bytes() for name in (
        'epoch-before.bin','rtc-read.bin','rtc-read-after.bin','epoch-after.bin')),
        tag,value['duration_seconds'])
    require(result==value,'Retained pre-halt qualification changed')
    return result
