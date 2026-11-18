#!/usr/bin/env python3
"""Summarize retained charger logs without opening a port or inferring sample times."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[2]
MAX_BYTES = 64 * 1024 * 1024
STATUS = re.compile(
    rb'^I9CHG1 valid=(?P<valid>[01]) soc=(?P<soc>\d+) mv=(?P<millivolts>\d+) '
    rb'temp=(?P<temperature_deci_c>-?\d+) charging=(?P<charging>[01]) '
    rb'reason=(?P<reason>-?\d+)\r*$', re.MULTILINE)


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


def summarize(path, allow_partial=False):
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
    if not complete and not allow_partial:
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
    if complete and receipts and previous != len(raw):
        raise ValueError('Receipt offsets and completed capture differ')

    samples = []
    cursor = 0
    for match in STATUS.finditer(raw):
        # A status without its final newline may still be arriving.
        if match.end() == len(raw) or raw[match.end()] != 10:
            continue
        row = {key: int(value) for key, value in match.groupdict().items()}
        row['end_offset'] = match.end() + 1
        while cursor < len(receipts) and receipts[cursor]['total'] < row['end_offset']:
            cursor += 1
        row['host_received_at'] = receipts[cursor]['time'] if cursor < len(receipts) else None
        samples.append(row)
    valid = [row for row in samples if row['valid']]
    begin = next((e['time'] for e in events if e.get('phase') == 'DTR_OK'), None)
    end = done[0]['time'] if complete else None
    seconds = ((datetime.fromisoformat(end) - datetime.fromisoformat(begin)).total_seconds()
               if begin and end else None)
    ranges = {key: {'minimum': min(row[key] for row in valid),
                    'maximum': max(row[key] for row in valid)}
              for key in ('soc', 'millivolts', 'temperature_deci_c')} if valid else {}
    return {
        'capture': str(path), 'complete': complete, 'closed': closed,
        'partial_event_record': partial_event,
        'device': identities[0], 'bytes': len(raw),
        'received_sha256': hashlib.sha256(raw).hexdigest(),
        'events_sha256': hashlib.sha256(events_raw).hexdigest(),
        'host_opened_at': begin, 'host_completed_at': end, 'host_capture_seconds': seconds,
        'sample_count': len(samples), 'valid_sample_count': len(valid),
        'invalid_sample_count': len(samples) - len(valid),
        'reasons': dict(Counter(str(row['reason']) for row in samples)),
        'charging_sample_count': sum(bool(row['charging']) for row in valid),
        'first_valid': valid[0] if valid else None, 'last_valid': valid[-1] if valid else None,
        'observed_soc_delta': valid[-1]['soc'] - valid[0]['soc'] if valid else None,
        'observed_millivolts_delta': valid[-1]['millivolts'] - valid[0]['millivolts'] if valid else None,
        'ranges': ranges, 'samples': samples,
        'source_measurement_times_available': False,
        'charge_rate_verified': False,
        'timing_limit': 'I9CHG1 has no device clock or sequence; host receipt times can include buffered states. Do not infer a charge rate or join boots.',
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
