#!/usr/bin/env python3
"""Canonical 256B i9100 current-card/HFS boot record; no hardware commands."""
import hashlib
import json
from pathlib import Path
import struct
import zlib
ROOT=Path(__file__).resolve().parents[3]
REPO=ROOT/'uniloader-S2I9100'
PROPERTY='i9100-emmc-boot'
BYTES=256

def bounded(path,limit):
    path=Path(path).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file() or not 0<path.stat().st_size<=limit:
        raise ValueError('Use a bounded file inside this project')
    raw=path.read_bytes()
    if not 0<len(raw)<=limit:raise ValueError('Input grew while reading')
    return raw

def uint(value,limit=(1<<32)-1):
    if type(value)is not int or not 0<=value<=limit:raise ValueError('Integer range/type mismatch')
    return value

def hexbytes(value,size):
    if not isinstance(value,str) or len(value)!=size*2 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Use exact lowercase raw-byte hex')
    raw=bytes.fromhex(value)
    if not any(raw):raise ValueError('Missing nonzero identity')
    return raw

def encode(profile,reviewed,pair_sha,system,data,model=False,transport=None,idmac=False):
    if type(reviewed)is not bool or type(model)is not bool or type(idmac)is not bool or reviewed and model:raise ValueError('Model data cannot be hardware reviewed')
    if set(profile)!= {'host','card'}:raise ValueError('Unexpected native profile fields')
    host=profile['host'];card=profile['card']
    host_fields=('ciu_clock_hz','source_mux','source_divider','clksel','gpk0_mux','gpk0_pull','gpk0_drive','xxti_hz','xusbxti_hz')
    if set(host)!=set(host_fields):raise ValueError('Exact inherited CIU/pin profile required')
    values=[uint(host[name]) for name in host_fields]
    clk,mux,divider,sel,pins,pull,drive,xtal,usb=values
    if not 400000<=clk<=200000000 or mux&~0xf0000 or divider&~0xff0f or sel==0xffffffff or pins!=0x3133 or pull&~255 or drive&~255 or xtal!=24000000 or usb!=24000000:
        raise ValueError('Unsupported inherited CIU/GPK0 profile')
    card_fields=('cid','primary_crc','backup_crc','entries_crc','disk_guid','system_guid','data_guid','sectors')
    if set(card)!=set(card_fields) or not isinstance(card['cid'],list) or len(card['cid'])!=4:
        raise ValueError('Exact current card+doubleGPT/PIT identity required')
    cid=[uint(v) for v in card['cid']]
    if not any(cid) or uint(card['sectors'],(1<<64)-1)!=30777344:raise ValueError('Different card capacity')
    guids=[hexbytes(card[name],16) for name in ('disk_guid','system_guid','data_guid')]
    if guids[1]==guids[2]:raise ValueError('Duplicate volume partition GUID')
    volume=[]
    for item in (system,data):
        if set(item)!={'create_date','finder_volume_id'}:raise ValueError('Exact stable HFS volume identity required')
        date=uint(item['create_date']);identifier=hexbytes(item['finder_volume_id'],8)
        if not date:raise ValueError('Missing HFS creation identity')
        volume.append((date,identifier))
    if volume[0][1]==volume[1][1]:raise ValueError('Duplicate HFS volume ID')
    transport_values=None
    if transport is not None:
        if not isinstance(transport,dict)or set(transport)!={'width','high_speed','target_hz','vcc_mv'}:
            raise ValueError('Exact explicit SDR transport requested')
        width,hs,target,vcc=[uint(transport[k])for k in ('width','high_speed','target_hz','vcc_mv')]
        if width not in (4,8)or hs not in (0,1)or vcc!=3300 or not 0<target<=(52000000 if hs else 20000000)or target>clk//2:
            raise ValueError('Unsupported SDR width/timing/clock/board voltage')
        transport_values=(int(reviewed),width,hs,target,clk,vcc,*cid)
    b=bytearray(BYTES);b[:4]=b'I9EB';struct.pack_into('<III',b,4,4 if idmac else 3 if transport_values else 2,BYTES,int(reviewed)|(2 if model else 0))
    struct.pack_into('<8I',b,16,int(reviewed),*values[:7]);struct.pack_into('<4I',b,48,*cid)
    struct.pack_into('<3I',b,64,*[uint(card[name]) for name in ('primary_crc','backup_crc','entries_crc')])
    b[76:124]=b''.join(guids);struct.pack_into('<Q',b,124,card['sectors'])
    for at,(date,identifier) in zip((132,144),volume):struct.pack_into('<I',b,at,date);b[at+4:at+12]=identifier
    b[156:188]=hexbytes(pair_sha,32);struct.pack_into('<II',b,188,xtal,usb)
    if transport_values:struct.pack_into('<10I',b,196,*transport_values)
    if idmac:struct.pack_into('<II',b,236,1,int(reviewed))
    struct.pack_into('<I',b,252,zlib.crc32(b[:252]));return bytes(b)

def decode(raw):
    version=struct.unpack_from('<I',raw,4)[0]if len(raw)>=8 else 0
    if len(raw)!=BYTES or raw[:4]!=b'I9EB' or version not in (2,3,4)or struct.unpack_from('<I',raw,8)[0]!=BYTES or any(raw[244 if version==4 else 236 if version==3 else 196:252]) or zlib.crc32(raw[:252])!=struct.unpack_from('<I',raw,252)[0]:
        raise ValueError('Malformed/partial/CRC-invalid native boot record')
    flags=struct.unpack_from('<I',raw,12)[0];host=struct.unpack_from('<8I',raw,16)
    if flags&~3 or flags==3 or host[0]>1 or bool(flags&1)!=bool(host[0]):raise ValueError('Invalid review/model flags')
    profile={'host':dict(zip(('ciu_clock_hz','source_mux','source_divider','clksel','gpk0_mux','gpk0_pull','gpk0_drive'),host[1:])),
             'card':dict(cid=list(struct.unpack_from('<4I',raw,48)),primary_crc=struct.unpack_from('<I',raw,64)[0],
               backup_crc=struct.unpack_from('<I',raw,68)[0],entries_crc=struct.unpack_from('<I',raw,72)[0],
               disk_guid=raw[76:92].hex(),system_guid=raw[92:108].hex(),data_guid=raw[108:124].hex(),sectors=struct.unpack_from('<Q',raw,124)[0])}
    profile['host'].update(zip(('xxti_hz','xusbxti_hz'),struct.unpack_from('<II',raw,188)))
    volumes=[dict(create_date=struct.unpack_from('<I',raw,at)[0],finder_volume_id=raw[at+4:at+12].hex()) for at in (132,144)]
    transport=None
    if version>=3 and any(raw[196:236]):
        values=struct.unpack_from('<10I',raw,196)
        if values[0]!=host[0]or values[4]!=host[1]or list(values[6:])!=profile['card']['cid']:
            raise ValueError('SDR review/CID/CIU differs from card boot contract')
        transport=dict(zip(('width','high_speed','target_hz','vcc_mv'),(values[1],values[2],values[3],values[5])))
    idmac=False
    if version==4:
        enabled,review=struct.unpack_from('<II',raw,236)
        if enabled!=1 or review!=host[0]:raise ValueError('IDMAC review differs from original boot contract')
        idmac=True
    if encode(profile,bool(flags&1),raw[156:188].hex(),*volumes,model=bool(flags&2),transport=transport,idmac=idmac)!=raw:raise ValueError('Noncanonical record')
    result=dict(flags=flags,profile=profile,system=volumes[0],data=volumes[1],pair_manifest_sha256=raw[156:188].hex())
    if transport:result['transport']=transport
    if idmac:result['idmac']=True
    return result

def read_prepared(folder,require_reviewed=False):
    folder=Path(folder).resolve()
    if not folder.is_relative_to(REPO/'out'):raise ValueError('Prepared profile escaped retained loader out')
    manifest=json.loads(bounded(folder/'manifest.json',65536));raw=bounded(folder/'emmc-boot.bin',BYTES)
    contract=decode(raw)
    if manifest.get('schema')!=1 or manifest.get('kind')!='i9100-emmc-boot-contract' or manifest.get('result')!='PASS' or manifest.get('device_contacted')is not False:
        raise ValueError('Missing successful offline profile preparation')
    if manifest['record_sha256']!=hashlib.sha256(raw).hexdigest() or manifest['record']!=contract:
        raise ValueError('Prepared contract/manifest mismatch')
    if manifest['contract_tool_sha256']!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest():raise ValueError('Contract encoder changed')
    if 'transport'in contract and require_reviewed:
        receipt=manifest.get('sdr_board_evidence')
        if not receipt:raise ValueError('SDR record lacks independent original board evidence')
        board_raw=bounded(ROOT/receipt['path'],65536)
        if hashlib.sha256(board_raw).hexdigest()!=receipt['sha256']:raise ValueError('Original SDR board evidence changed')
        board=json.loads(board_raw);transport=contract['transport']
        tool=Path(__file__).with_name('emmc-sdr-evidence.py')
        if receipt.get('verifier_sha256')!=hashlib.sha256(tool.read_bytes()).hexdigest():raise ValueError('SDR board verifier changed')
    if require_reviewed and contract['flags']!=1:raise ValueError('Require an independently reviewed non-model boot profile')
    if require_reviewed:
        import importlib.util
        spec=importlib.util.spec_from_file_location('emmc_inventory',Path(__file__).with_name('emmc-inventory-evidence.py'))
        validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
        if manifest.get('preparer_sha256')!=hashlib.sha256(Path(__file__).with_name('prepare-emmc-boot.py').read_bytes()).hexdigest() or manifest.get('evidence_checker_sha256')!=hashlib.sha256(Path(__file__).with_name('emmc-inventory-evidence.py').read_bytes()).hexdigest():
            raise ValueError('Prepared profile has no current evidence validator')
        inventory_raw=bounded(ROOT/manifest['inventory']['path'],65536)
        if hashlib.sha256(inventory_raw).hexdigest()!=manifest['inventory']['sha256']:raise ValueError('Current native inventory changed')
        inventory=json.loads(inventory_raw)
        if inventory['profile']!=contract['profile'] or inventory['model_fixture']is not False or inventory['clock_and_pins_reviewed']is not True:
            raise ValueError('Review was not bound to original non-model inventory')
        raws={}
        for name,item in inventory['evidence'].items():
            evidence=bounded(ROOT/item['path'],4*1024*1024)
            if len(evidence)!=item['bytes'] or hashlib.sha256(evidence).hexdigest()!=item['sha256']:raise ValueError('Original eMMC identity/controller capture changed')
            raws[name]=evidence
        validator.check(contract['profile'],raws,False,True)
        if contract.get('idmac'):
            record=manifest.get('idmac_board_evidence');tool_idmac=Path(__file__).with_name('emmc-idmac-evidence.py')
            if not record or record.get('verifier_sha256')!=hashlib.sha256(tool_idmac.read_bytes()).hexdigest():raise ValueError('IDMAC original host proof/verifier missing')
            raw_idmac=bounded(ROOT/record['path'],65536)
            if hashlib.sha256(raw_idmac).hexdigest()!=record['sha256']:raise ValueError('Original IDMAC host evidence changed')
            spec=importlib.util.spec_from_file_location('idmac_evidence',tool_idmac);verifier_idmac=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier_idmac)
            verifier_idmac.check(json.loads(raw_idmac),contract['profile']['card'],json.loads(raws['controller']),True)
        if 'transport'in contract:
            controller=json.loads(raws['controller'])
            spec=importlib.util.spec_from_file_location('sdr_evidence',tool);verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
            verifier.check(board,transport,contract['profile']['card'],controller,True)
        receipt=manifest.get('verified_backup')
        if not receipt or receipt.get('model_fixture')is not False or receipt.get('verifier_sha256')!=hashlib.sha256(Path(__file__).with_name('emmc-read-evidence.py').read_bytes()).hexdigest():
            raise ValueError('Reviewed boot profile has no current original full-user backup proof')
        spec=importlib.util.spec_from_file_location('emmc_read_evidence',Path(__file__).with_name('emmc-read-evidence.py'))
        backup_checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(backup_checker)
        backup_folder=(ROOT/receipt['path']).resolve();backup=backup_checker.verify_acquisition(backup_folder,True,True)
        if hashlib.sha256((backup_folder/'manifest.json').read_bytes()).hexdigest()!=receipt['manifest_sha256'] or backup['whole_user_area']!=receipt['whole_user_area']:
            raise ValueError('Original backup proof changed after internal-root review')
        if any(backup['card'][key]!=contract['profile']['card'][key]for key in ('cid','sectors','disk_guid','system_guid','data_guid','primary_crc','backup_crc','entries_crc')):
            raise ValueError('Original backup card/table differs from boot contract')
        pair_raw=bounded(ROOT/manifest['pair']['path'],256*1024)
        if hashlib.sha256(pair_raw).hexdigest()!=contract['pair_manifest_sha256']:raise ValueError('Paired volume preparation changed')
    return raw,manifest

def add_device_tree(tree,record):
    """Parse the actual Apple tree; add only one property to /chosen.
    No raw name scan, duplicate properties, trailing bytes or malformed child
    counts are accepted. Existing properties/children stay byte-identical."""
    if len(tree)>65536:raise ValueError('Device tree exceeds bounded boot format')
    decode(record)
    chosen=[];nodes=0
    def node(pos,parent,depth=0):
        nonlocal nodes
        nodes+=1
        if nodes>256:raise ValueError('Too many device tree nodes')
        if depth>16 or pos+8>len(tree):raise ValueError('Malformed device tree depth/length')
        start=pos;count,children=struct.unpack_from('<II',tree,pos);pos+=8
        if count>256 or children>256:raise ValueError('Unbounded DT node')
        properties={};raws=[]
        for _ in range(count):
            if pos+36>len(tree):raise ValueError('Truncated DT property')
            name_raw=tree[pos:pos+32];length=struct.unpack_from('<I',tree,pos+32)[0]
            if b'\0' not in name_raw or any(name_raw[name_raw.index(0)+1:]) or length>65536:raise ValueError('Malformed DT property')
            name=name_raw.split(b'\0',1)[0].decode('ascii');end=pos+36+((length+3)&~3)
            if not name or name in properties or end>len(tree):raise ValueError('Duplicate/truncated DT property')
            properties[name]=tree[pos+36:pos+36+length];raws.append(tree[pos:end]);pos=end
        node_name=properties.get('name',b'').rstrip(b'\0').decode('ascii')
        path=parent+'/'+node_name;body=b''.join(raws);extra=b''
        if path=='/device-tree/chosen':
            if PROPERTY in properties:raise ValueError('Native boot property already present')
            chosen.append(start);extra=PROPERTY.encode().ljust(32,b'\0')+struct.pack('<I',BYTES)+record
        tails=[]
        for _ in range(children):pos,child=node(pos,path,depth+1);tails.append(child)
        return pos,struct.pack('<II',count+bool(extra),children)+body+extra+b''.join(tails)
    end,result=node(0,'')
    if end!=len(tree) or len(chosen)!=1 or len(result)>65536:raise ValueError('Expected exactly one bounded /chosen node')
    return result
