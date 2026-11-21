#!/usr/bin/env python3
"""Retain charger USB RAM traces on an existing verified kernel owner only."""
import hashlib,json,struct
from pathlib import Path
from datetime import datetime,timezone

FIELDS=('magic','version','bytes','sequence','ticks_low','ticks_high','state','recovery',
 'polls','rx_count','setup_sequence','last_setup','ep0_completions','ep1_completions',
 'gintsts','last_rx_status','in0_ctl','in0_size','in0_int','out0_ctl','out0_size','out0_int',
 'in1_ctl','in1_size','in1_int','in1_free','pcgcctl','fault','flags','source_fingerprint','ep0_state','checksum')
MAGIC=0x55533949

def require(ok,message):
    if not ok:raise ValueError(message)

def fnv(raw):
    value=2166136261
    for byte in raw:value=((value^byte)*16777619)&0xffffffff
    return value

def fingerprint(kernel_tag,charger_tag):
    import re
    require(re.fullmatch('[0-9a-f]{16}',kernel_tag) and re.fullmatch('[0-9a-f]{16}',charger_tag),'Exact tags required')
    return fnv((kernel_tag+charger_tag).encode('ascii'))

def decode(raw,expected_source=None):
    require(len(raw)==128,'Exact USB trace size required')
    words=struct.unpack('<32I',raw);row=dict(zip(FIELDS,words))
    require(words[:3]==(MAGIC,1,128) and words[3]>0,'USB trace not published by the new loader')
    require(words[31]==fnv(raw[:-4]),'USB trace checksum differs; no reread')
    require(row['state']<=3 and row['fault']<=5 and row['ep0_state']<=4 and row['flags']<=15,
            'USB trace state differs')
    require(row['recovery'] in (0,1,0x101,0x201),'Unknown checked-stop proof')
    require((row['fault']>0)==(row['state']==3) and (not row['recovery'] or row['fault']>0),
            'Recovery/fault state is inconsistent')
    row.update(ticks=(row['ticks_high']<<32)|row['ticks_low'],
        recovery_leased=bool(row['recovery']&1),
        stop_result={0:'not-recorded',1:'confirmed-off',2:'failed-stop'}[(row['recovery']>>8)&3],
        source_matches=None if expected_source is None else row['source_fingerprint']==expected_source,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        limit='Retained original boot RAM snapshot; host receipt time is not its measurement time or proof of a live USB link')
    return row

def capture(session,target,kernel_tag,package=None):
    """Record that this BUILD cannot export the retained traces safely."""
    require(not target.exists(),'Fresh trace output required');target.mkdir()
    expected=None
    if package is not None:
        manifest=json.loads((Path(package)/'manifest.json').read_text(encoding='utf8'))
        require(manifest['control_tag']==kernel_tag,'Trace owner BUILD differs from package')
        expected=fingerprint(manifest['control_tag'],manifest['standalone_charge_control_tag'])
    # The retention page is outside the XNU direct map. The loader's
    # manifest describes its writes and does not grant XNU a read mapping.
    result=dict(time=datetime.now(timezone.utc).isoformat(),kernel_tag=kernel_tag,
                source_fingerprint=expected,available=False,records={},
                reason='This kernel cannot export the retained USB trace page')
    (target/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');return result

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description='Offline decode only; no port opener')
    p.add_argument('file',type=Path);p.add_argument('--kernel-tag');p.add_argument('--charger-tag');a=p.parse_args()
    expected=fingerprint(a.kernel_tag,a.charger_tag) if a.kernel_tag and a.charger_tag else None
    print(json.dumps(decode(a.file.read_bytes(),expected),indent=2))
