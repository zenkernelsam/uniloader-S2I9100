"""Read-only charger-to-XNU diagnostics from a matched Apple device tree.

Uses the existing BUILD-verified memory reader. No new serial owner, writes,
opener retry, MMIO or repeated reads to manufacture a valid observation.
"""
import hashlib
import json
import struct
from pathlib import Path

PROPERTY='i9100-charge-handoff'
MAGIC=0x48433949
FIELDS=('magic','version','bytes','flags','revision','sub_charger','polls','valid',
        'present','connected','percent','millivolts','temperature_deci_c','reason',
        'full','timeout','recharging','enabled_before','charging_before','enabled_after','charging_after',
        'sampled_low','sampled_high','stopped_low','stopped_high','published_low','published_high',
        'elapsed_seconds','qualified_samples','recovery_seconds','fault','checksum')


def checksum(raw):
    if len(raw)!=128:raise ValueError('Exact charger handoff size required')
    result=2166136261
    for byte in raw[:-4]:result=((result^byte)*16777619)&0xffffffff
    return result


def tree_properties(raw):
    """Bounded independent Apple flat-tree parser; return path/name/value."""
    if not 172<=len(raw)<=32768 or len(raw)&3:raise ValueError('Bounded aligned Apple tree required')
    at=0;nodes=0;result={}
    def node(depth,parent):
        nonlocal at,nodes
        nodes+=1
        if depth>8 or nodes>128 or at+8>len(raw):raise ValueError('Device tree node bounds differ')
        properties,children=struct.unpack_from('<2I',raw,at);at+=8
        if not 1<=properties<=128 or children>64:raise ValueError('Device tree count bounds differ')
        local={};offsets={}
        for _ in range(properties):
            if at+36>len(raw):raise ValueError('Truncated device-tree property')
            keyraw,length=struct.unpack_from('<32sI',raw,at)
            zero=keyraw.find(b'\0')
            if zero<=0 or any(keyraw[zero:]):raise ValueError('Malformed property name')
            name=keyraw[:zero].decode('ascii','strict');at+=36
            if name in local or length>len(raw)-at or ((length+3)&~3)>len(raw)-at:
                raise ValueError('Duplicate or truncated device-tree property')
            local[name]=raw[at:at+length];offsets[name]=at
            at+=(length+3)&~3
        name=local.get('name',b'')
        if not name or len(name)>64 or name[-1:]!=b'\0' or b'\0' in name[:-1]:
            raise ValueError('Device-tree node name differs')
        name=name[:-1].decode('ascii','strict')
        if not depth:
            if name!='device-tree':raise ValueError('Unexpected Apple tree root')
            path=''
        else:path=parent+'/'+name
        if path in result:raise ValueError('Duplicate device-tree node path')
        result[path]={'values':local,'offsets':offsets}
        for _ in range(children):node(depth+1,path)
    node(0,'')
    if at!=len(raw) or '/chosen' not in result:raise ValueError('Incomplete Apple device tree')
    slots=[(path,value['values'][PROPERTY]) for path,value in result.items() if PROPERTY in value['values']]
    if len(slots)!=1 or slots[0][0]!='/chosen' or len(slots[0][1])!=128:
        raise ValueError('Exactly one /chosen charger handoff slot required')
    return result


def decode(raw):
    if len(raw)!=128:raise ValueError('Charger handoff record size differs')
    if not any(raw):
        return dict(published=False,valid=False,reason='No supervised charger handoff was published for this boot')
    words=struct.unpack('<32I',raw)
    if words[:4]!=(MAGIC,1,128,7) or checksum(raw)!=words[-1]:
        raise ValueError('Partial or unknown charger handoff/checksum')
    result=dict(zip(FIELDS,words))
    for field in ('temperature_deci_c','reason'):
        if result[field]&0x80000000:result[field]-=1<<32
    if (result['revision']>15 or result['sub_charger']!=int(8<=result['revision']<=15) or
        any(result[field]>1 for field in ('valid','present','connected','full','timeout','recharging',
                                        'enabled_before','charging_before','enabled_after','charging_after'))):
        raise ValueError('Malformed charger handoff board/state fields')
    if (not result['valid'] or not result['present'] or not 3<=result['percent']<=100 or
        not 3600<=result['millivolts']<=4300 or not 50<=result['temperature_deci_c']<=400 or
        result['timeout'] or result['fault'] or result['qualified_samples']!=11 or
        result['recovery_seconds']<10 or result['enabled_after'] or result['charging_after']):
        raise ValueError('Handoff did not qualify fresh recovery and a checked charger stop')
    sampled=(result['sampled_high']<<32)|result['sampled_low']
    stopped=(result['stopped_high']<<32)|result['stopped_low']
    published=(result['published_high']<<32)|result['published_low']
    if not 0<sampled<=stopped<=published or published-sampled>60000000:
        raise ValueError('Charger handoff clocks are stale or inconsistent')
    result.update(published=True,valid=True,sampled_ticks=sampled,stopped_ticks=stopped,published_ticks=published,
                  sample_to_stop_nanoseconds=(stopped-sampled)*1000//24,
                  stop_to_publication_begin_nanoseconds=(published-stopped)*1000//24,
                  raw_sha256=hashlib.sha256(raw).hexdigest(),
                  limit='Measured loader sample/checked stop/publication-begin ticks. Publication timestamp precedes checksum and final slot writes; actual XNU power-driver arrival needs its own first valid sample. No net current inferred.')
    return result


def first_kernel_sample(handoff,samples):
    """Bound driver takeover by its first complete measurement on this boot.

    This port expresses its unchanged 24MHz MCT count as nanoseconds in
    mach_absolute_time. The observation dates a measurement, not the exact
    enable write, and cannot establish net charging current.
    """
    result=dict(usable=False,net_charging_verified=False,
        limit='First complete kernel power sample after loader stop: upper bound on reaching that sample, not the exact enable write, measured current or energy balance')
    if not handoff or not handoff.get('valid') or not handoff.get('root_stable'):
        result['reason']='Missing or partial handoff from this boot';return result
    first=[row for row in samples if row.get('polls')==1 and row.get('measurements_valid') is True]
    if len(first)!=1:
        result['reason']='First kernel sample absent or ambiguous; later samples cannot date takeover';return result
    row=first[0]
    if (row.get('revision')!=handoff['revision'] or row.get('sub_charger')!=handoff['sub_charger'] or
        any(row.get(field) not in (0,1) for field in ('enabled','connected','charging'))):
        result['reason']='Kernel board/state differs from loader handoff';return result
    stopped_ns=handoff['stopped_ticks']*1000//24
    sampled_ns=row.get('time_ns',0)
    if type(sampled_ns) is not int or sampled_ns<stopped_ns or sampled_ns-stopped_ns>600000000000:
        result['reason']='Kernel/loader clock interval is inconsistent or too old';return result
    result.update(usable=True,first_sample_ns=sampled_ns,loader_stop_ns=stopped_ns,
        observed_interval_ns=sampled_ns-stopped_ns,enabled=row['enabled'],connected=row['connected'],
        charging=row['charging'],kernel_reason=row['reason'],sequence=row['sequence'],
        source='Same BUILD and loader tree identity plus its native first Power measurement')
    return result


def capture(kernel,symbols,out):
    """Capture one immutable tree using its exact local package reference."""
    if not hasattr(symbols,'path'):return None  # Existing log-only/legacy readers have no package.
    package=Path(symbols.path).resolve().parent
    manifest_path=package/'manifest.json'
    if not manifest_path.is_file():return None
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('standalone_charge_handoff') is not True:return None
    if manifest.get('control_tag')!=symbols.tag or manifest['artifacts']['mach_kernel']['sha256'][:16]!=symbols.tag:
        raise ValueError('Handoff package/BUILD identity differs')
    reference=(package/'dtb').read_bytes()
    artifact=manifest.get('standalone_charge_handoff_tree',{})
    if artifact.get('bytes')!=len(reference) or artifact.get('sha256')!=hashlib.sha256(reference).hexdigest():
        raise ValueError('Package device-tree artifact changed before the handoff read')
    expected=tree_properties(reference)
    if '_DTRootNode' not in symbols.values:raise ValueError('Reviewed kernel lacks its actual device-tree root symbol')
    root=kernel.u32(symbols['_DTRootNode'])
    if root<0x80000000 or root>0xffffffff-len(reference) or root&3:
        raise ValueError('Live Apple device-tree root is absent or misaligned')
    raw=kernel.read(root,len(reference));(out/'charge-handoff-tree.bin').write_bytes(raw)
    stable=kernel.u32(symbols['_DTRootNode'])==root
    actual=tree_properties(raw)
    if set(actual)!=set(expected):raise ValueError('Live device-tree paths differ from the reviewed package')
    mutable={'i9100-prev-boot','i9100-boot-source',PROPERTY}
    for path,node in actual.items():
        if set(node['values'])!=set(expected[path]['values']):raise ValueError('Live tree property list differs')
        for key,value in node['values'].items():
            before=expected[path]['values'][key]
            if len(before)!=len(value) or (not(path=='/chosen' and key in mutable) and before!=value):
                raise ValueError('Live tree value differs from its exact package reference')
    record=actual['/chosen']['values'][PROPERTY]
    (out/'charge-handoff.bin').write_bytes(record)
    try:result=decode(record)
    except ValueError as error:
        result=dict(published=any(record),valid=False,error=str(error),raw_sha256=hashlib.sha256(record).hexdigest())
    result.update(tree_root=hex(root),root_stable=stable,tree_sha256=hashlib.sha256(raw).hexdigest(),
                  package_reference_sha256=hashlib.sha256(reference).hexdigest(),kernel_tag=symbols.tag)
    if not stable:result.update(valid=False,error='Live tree root changed during the single observation')
    (out/'charge-handoff.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result
