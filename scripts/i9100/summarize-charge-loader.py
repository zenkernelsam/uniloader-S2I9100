#!/usr/bin/env python3
"""Summarize retained charger logs without opening a port or inferring sample times."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[2]
MAX_BYTES = 64 * 1024 * 1024
_sense_spec=importlib.util.spec_from_file_location('loader_charge_sense',Path(__file__).with_name('charge-sense.py'))
_sense=importlib.util.module_from_spec(_sense_spec);_sense_spec.loader.exec_module(_sense)
STATUS = re.compile(
    rb'^I9CHG1 valid=(?P<valid>[01]) soc=(?P<soc>\d+) mv=(?P<millivolts>\d+) '
    rb'temp=(?P<temperature_deci_c>-?\d+) charging=(?P<charging>[01]) '
    rb'reason=(?P<reason>-?\d+)\r*$', re.MULTILINE)
TIMED_STATUS = re.compile(
    rb'^I9CHG2 seq=(?P<sequence>[0-9a-f]{8}) ms=(?P<measured_ms>[0-9a-f]{16}) '
    rb'valid=(?P<valid>[01]) soc=(?P<soc>\d+) mv=(?P<millivolts>\d+) '
    rb'temp=(?P<temperature_deci_c>-?\d+) charging=(?P<charging>[01]) '
    rb'reason=(?P<reason>-?\d+) full=(?P<full>[01]) timeout=(?P<timeout>[01]) '
    rb'recharging=(?P<recharging>[01]) elapsed=(?P<charge_elapsed_seconds>\d+)\r*$',re.MULTILINE)

def decode_liveness(raw):
    """Decode complete first-packet records; receipt time is not sample time."""
    pattern=rb'^I9LV1 ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})\r*\n'
    result=[]
    for match in re.finditer(pattern,raw,re.MULTILINE):
        values=[int(field,16) for field in match.groups()]
        if values[0]&~0x103 or values[4]>4:
            raise ValueError('Unknown wake probe or epoch result in first-packet record')
        wire_probe=values[0];values[0]&=3
        if values[5]>=1<<31:values[5]-=1<<32
        result.append(dict(zip(('wake_probe','completed_wfi','irq89_acks','policy_polls','epoch_result','reason'),values),
                           wake_probe_wire=wire_probe,wfi_inhibited=bool(wire_probe&0x100),
                           end_offset=match.end(),measurement_time_available=False))
    return result

def decode_rtc_reads(raw):
    pattern=rb'^I9RT1 ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})\r*\n'
    result=[]
    for match in re.finditer(pattern,raw,re.MULTILINE):
        values=[int(x,16) for x in match.groups()]
        if values[0]>15 or values[4]>9 or values[5]&1:
            raise ValueError('Unknown RTC raw record')
        result.append(dict(zip(('read_mask','controls','first_low','first_high','status','sequence'),values),
                           end_offset=match.end(),measurement_time_available=False))
    return result

def decode_status(raw,receipts):
    matches=sorted([(match,1) for match in STATUS.finditer(raw)]+
                   [(match,2) for match in TIMED_STATUS.finditer(raw)],key=lambda item:item[0].start())
    samples=[];cursor=0;segment=0;previous=None
    for match,version in matches:
        if match.end()==len(raw) or raw[match.end()]!=10:continue
        row={key:int(value,16 if key in ('sequence','measured_ms') else 10) for key,value in match.groupdict().items()}
        row['version']=version
        for key in ('reason','temperature_deci_c'):
            value=row[key]
            if not -(1<<31)<=value<=0xffffffff:raise ValueError('Charger int32 field outside wire range')
            if version==2 and value>(1<<31)-1:raise ValueError('Timed charger int field must use signed decimal')
            row[key+'_wire']=value
            if value>=1<<31:row[key]=value-(1<<32)
        if row['soc']>100 or row['millivolts']>10000:raise ValueError('Charger measurement outside its protocol range')
        row['end_offset']=match.end()+1
        row['start_offset']=match.start()
        while cursor<len(receipts) and receipts[cursor]['total']<row['end_offset']:cursor+=1
        row['host_received_at']=receipts[cursor]['time'] if cursor<len(receipts) else None
        if version==2:
            if not row['sequence']:raise ValueError('Timed charger sequence is zero')
            row['interval_available']=False
            if previous and previous['version']==2:
                seq_delta=(row['sequence']-previous['sequence'])&0xffffffff
                elapsed=row['measured_ms']-previous['measured_ms']
                if seq_delta!=1 or not 0<elapsed<=120000:
                    segment+=1
                    row['segment_break']='sequence discontinuity or measured clock reset/gap; no rate across this boundary'
                elif row['valid'] and previous['valid']:
                    row['interval_available']=True;row['interval_ms']=elapsed
                    row['observed_soc_change']=row['soc']-previous['soc']
                    row['observed_millivolts_change']=row['millivolts']-previous['millivolts']
            else:
                segment+=1;row['segment_break']='first timed sample after capture/legacy data'
            row['measurement_segment']=segment
        samples.append(row);previous=row
    return samples


def confined(path):
    path = path.resolve()
    if not path.is_relative_to(REPO / 'out'):
        raise ValueError('Evidence paths must stay inside this repository out')
    return path


def read_bounded(path):
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f'Evidence exceeds the size limit: {path}')
    return data


def summarize(path, allow_partial=False, completed_observation=False):
    path = confined(path)
    raw = read_bounded(path / 'received.bin')
    events_raw = read_bounded(path / 'events.jsonl')
    lines = events_raw.splitlines()
    partial_event = bool(events_raw and not events_raw.endswith(b'\n'))
    if partial_event:
        if not allow_partial:
            raise ValueError('Event stream has an unfinished record')
        lines = lines[:-1]
    events = [json.loads(line) for line in lines if line.strip()]
    done = [e for e in events if e.get('phase') == 'DONE']
    closed = bool(events and events[-1].get('phase') == 'CLOSED')
    complete = not partial_event and len(done) == 1 and closed and not any(
        e.get('phase') == 'STOP' for e in events)
    observed=[e for e in events if e.get('phase')=='OBSERVATION_COMPLETE']
    interval_complete=False
    if completed_observation:
        if (allow_partial or partial_event or len(observed)!=1 or not events or
            events[-1].get('phase')!='OBSERVATION_COMPLETE' or
            any(e.get('phase') in ('SEND','ACK','DONE','STOP','CLOSED') for e in events) or
            observed[0].get('writes')!=0 or observed[0].get('bytes')!=len(raw)):
            raise ValueError('Frozen observation is not a completed, pre-command interval')
        begins=[e for e in events if e.get('phase')=='BEGIN']
        if len(begins)!=1 or not isinstance(begins[0].get('pid'),int) or begins[0]['pid']<=0:
            raise ValueError('Frozen observation lacks its original process owner')
        interval_complete=True
    if not complete and not interval_complete and not allow_partial:
        raise ValueError(f'Capture has not completed normally; keep its owner: {path}')
    if complete and done[0].get('bytes') != len(raw):
        raise ValueError('DONE byte count and retained capture differ')
    identities = [e['device'] for e in events if e.get('phase') == 'CHARGER_IDENTITY']
    if len(identities) != 1 or not identities[0].get('instance', '').upper().endswith(
            '\\S2I9100-CHG'):
        raise ValueError('Capture lacks the distinct standalone-charger identity')

    receipts = [e for e in events if e.get('phase') == 'CHARGER_RX']
    previous = 0
    for receipt in receipts:
        total, count = receipt['total'], receipt['bytes']
        if not isinstance(total, int) or not isinstance(count, int) or count <= 0 or total != previous + count:
            raise ValueError('Receipt byte offsets are discontinuous')
        previous = total
    if (complete or interval_complete) and receipts and previous != len(raw):
        raise ValueError('Receipt offsets and completed capture differ')

    samples=decode_status(raw,receipts)
    valid = [row for row in samples if row['valid']]
    begin = next((e['time'] for e in events if e.get('phase') == 'DTR_OK'), None)
    end = done[0]['time'] if complete else observed[0]['time'] if interval_complete else None
    seconds = ((datetime.fromisoformat(end) - datetime.fromisoformat(begin)).total_seconds()
               if begin and end else None)
    ranges = {key: {'minimum': min(row[key] for row in valid),
                    'maximum': max(row[key] for row in valid)}
              for key in ('soc', 'millivolts', 'temperature_deci_c')} if valid else {}
    transitions=[]
    for n,row in enumerate(valid):
        if n and (row['reason'],row['charging'])!=(valid[n-1]['reason'],valid[n-1]['charging']):
            transitions.append(dict(index=n,before=valid[n-1],after=row))
    return {
        'capture': str(path), 'complete': complete, 'closed': closed,
        'interval_complete': interval_complete,
        'partial_event_record': partial_event,
        'device': identities[0], 'bytes': len(raw),
        'received_sha256': hashlib.sha256(raw).hexdigest(),
        'events_sha256': hashlib.sha256(events_raw).hexdigest(),
        'host_opened_at': begin, 'host_completed_at': end, 'host_capture_seconds': seconds,
        'sample_count': len(samples), 'valid_sample_count': len(valid),
        'state_transitions': transitions,
        'invalid_sample_count': len(samples) - len(valid),
        'reasons': dict(Counter(str(row['reason']) for row in samples)),
        'charging_sample_count': sum(bool(row['charging']) for row in valid),
        'first_valid': valid[0] if valid else None, 'last_valid': valid[-1] if valid else None,
        'observed_soc_delta': valid[-1]['soc'] - valid[0]['soc'] if valid else None,
        'observed_millivolts_delta': valid[-1]['millivolts'] - valid[0]['millivolts'] if valid else None,
        'ranges': ranges, 'samples': samples,
        'charger_liveness': decode_liveness(raw),
        'charger_rtc_reads': decode_rtc_reads(raw),
        'charge_sense': _sense.grouped(raw,[row for row in samples if row['version']==2]),
        'charge_policy': _sense.grouped_policy(raw,[row for row in samples if row['version']==2]),
        'charge_download_stop': _sense.grouped_download(raw,[row for row in samples if row['version']==2]),
        'source_measurement_times_available': any(row['version']==2 for row in samples),
        'charge_rate_verified': False,
        'timing_limit': 'I9CHG2 device clock/sequence qualifies only uninterrupted measurement segments; gaps/reboots/legacy data are split. Host receipts can include buffered states. SOC and voltage changes do not measure milliamps or prove a charge rate.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True, help='Fresh evidence directory under repository out')
    parser.add_argument('--allow-partial', action='store_true', help='Read an ongoing capture, marking it incomplete; never reopen it')
    args = parser.parse_args()
    output = confined(args.output)
    if output.exists():
        parser.error('Use a fresh summary directory; retained evidence is never overwritten')
    result = {'schema': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
              'serial_openers': 0, 'device_writes': 0,
              'captures': [summarize(path, args.allow_partial) for path in args.capture]}
    output.mkdir(parents=True)
    (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    for capture in result['captures']:
        print(json.dumps({key: capture[key] for key in (
            'capture', 'complete', 'sample_count', 'first_valid', 'last_valid',
            'ranges', 'reasons', 'charge_rate_verified')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
