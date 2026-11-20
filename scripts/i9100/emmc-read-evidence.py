#!/usr/bin/env python3
"""Import framed read-only eMMC acquisition into retained, non-deployable evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import zlib

ROOT=Path(__file__).resolve().parents[3];REPO=ROOT/'uniloader-S2I9100'
SECTORS=30777344;CHUNK=1024*1024;MAX_TEXT=131072;MODEL_FLAG=0x80000000;SAFE_FLAGS=15
NAMES={1:'mbr.bin',2:'gpt-primary-header.bin',3:'gpt-primary-array.bin',4:'gpt-backup-header.bin',
       5:'gpt-backup-array.bin',6:'pit.bin',16:'device-dev.txt',17:'cid.txt',18:'sectors.txt',19:'card-type.txt',
       20:'mountinfo.txt',21:'swaps.txt',22:'iomem.txt',23:'clock-summary.txt',24:'logical-block-size.txt'}
TEXT_ORDER=list(range(16,25));TABLE_ORDER=list(range(1,7))

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for raw in iter(lambda:f.read(CHUNK),b''):h.update(raw)
    return h.hexdigest()
def file_item(path):
    path=Path(path).resolve();return dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=sha(path))
def project_file(path):
    path=Path(path).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():raise ValueError('Input must be a regular project file')
    return path
def exact(stream,n):
    raw=stream.read(n)
    if len(raw)!=n:raise ValueError('Partial acquisition frame; keep incomplete evidence')
    return raw
def nonce(raw):
    if not isinstance(raw,str) or not re.fullmatch('[0-9a-f]{32}',raw) or not any(bytes.fromhex(raw)):
        raise ValueError('Use an exact nonzero lowercase 16-byte nonce')
    return bytes.fromhex(raw)
def header(raw):
    if len(raw)!=128 or raw[:8]!=b'I9ROSTR1' or struct.unpack_from('<II',raw,8)!=(1,128) or any(raw[108:124]) or not any(raw[76:108]) or zlib.crc32(raw[:124])!=struct.unpack_from('<I',raw,124)[0]:
        raise ValueError('Unknown/damaged read-only stream header')
    mode,chunk,sectors=struct.unpack_from('<IIQ',raw,16);flags=struct.unpack_from('<I',raw,72)[0]
    if mode not in (1,2) or chunk!=CHUNK or flags&~MODEL_FLAG!=SAFE_FLAGS or not 1<=sectors<=0xffffffff:
        raise ValueError('Unsupported acquisition mode/geometry/safeguards')
    model=bool(flags&MODEL_FLAG)
    if not model and sectors!=SECTORS:raise ValueError('Different eMMC capacity')
    cid=list(struct.unpack_from('<4I',raw,32));major,minor=struct.unpack_from('<II',raw,64)
    if not any(cid) or not any(raw[48:64]) or (major,minor)!=(179,0):raise ValueError('Wrong read-only Linux block identity')
    return dict(mode=mode,chunk_bytes=chunk,sectors=sectors,cid=cid,major=major,minor=minor,flags=flags,model_fixture=model,
                nonce=raw[48:64].hex(),producer_source_sha256=raw[76:108].hex())
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def check_tables(values,observed):
    validator=module('i9100_inventory','emmc-inventory-evidence.py')
    mbr=values[1][1]
    if len(mbr)!=512 or mbr[510:]!=b'\x55\xaa':raise ValueError('Missing protective MBR')
    active=[]
    for i in range(4):
        entry=mbr[446+i*16:462+i*16]
        if any(entry):active.append(entry)
    if len(active)!=1 or active[0][4]!=0xee or struct.unpack_from('<II',active[0],8)!=(1,observed['sectors']-1):
        raise ValueError('Different/hybrid protective MBR')
    expected_offsets={1:0,2:512,4:(observed['sectors']-1)*512,6:0x4400}
    for k,off in expected_offsets.items():
        if values[k][0]!=off:raise ValueError('Acquisition table came from wrong LBA')
    for hk,ak in ((2,3),(4,5)):
        if len(values[hk][1])!=512 or values[ak][0]!=struct.unpack_from('<Q',values[hk][1],72)[0]*512:
            raise ValueError('GPT array offset mismatch')
    primary=validator.gpt(values[2][1]+values[3][1],observed['sectors'],1)
    backup=validator.gpt(values[4][1]+values[5][1],observed['sectors'],observed['sectors']-1)
    if any(primary[k]!=backup[k] for k in ('entries','disk_guid','first','last','parts')):
        raise ValueError('Primary/backup acquisition disagrees')
    if len(primary['parts'])!=12:raise ValueError('Require the actual 12 partition table')
    by_name={p['name']:p for p in primary['parts']}
    expected_names={'EFS','SBL1','SBL2','PARAM','KERNEL','RECOVERY','CACHE','MODEM','FACTORYFS','DATAFS','UMS','HIDDEN'}
    if set(by_name)!=expected_names:raise ValueError('Partition set differs from native layout')
    native_geometry=observed['sectors']==SECTORS
    for name,start,count,number in (('FACTORYFS',344064,3145728,9),('DATAFS',3489792,12582912,10)):
        row=by_name[name]
        if (row['start_lba'],row['sectors'],row['number'])!=(start,count,number):native_geometry=False
    if not native_geometry and not observed['model_fixture']:raise ValueError('Native slice geometry changed')
    pit=values[6][1]
    if len(pit)<28 or struct.unpack_from('<I',pit)[0]!=0x12349876:raise ValueError('PIT header absent')
    count=struct.unpack_from('<I',pit,4)[0]
    if not 1<=count<=32 or len(pit)!=28+count*132:raise ValueError('PIT length disagreement')
    found={};ids=set()
    for i in range(count):
        item=pit[28+i*132:28+(i+1)*132];name_raw=item[36:68]
        if b'\0' not in name_raw:raise ValueError('Unterminated PIT name')
        name=name_raw.split(b'\0',1)[0].decode('ascii')
        if name not in by_name:continue
        kind,dev,identifier=struct.unpack_from('<III',item);lo,n=struct.unpack_from('<II',item,20)
        if name in found or identifier in ids or (kind,dev,lo,n)!=(0,2,by_name[name]['start_lba'],by_name[name]['sectors']):
            raise ValueError('PIT/GPT slice mismatch')
        found[name]=identifier;ids.add(identifier)
    if set(found)!=expected_names or found['FACTORYFS']!=10 or found['DATAFS']!=11:raise ValueError('PIT role identities missing')
    return dict(sectors=observed['sectors'],cid=observed['cid'],primary_crc=primary['crc'],backup_crc=backup['crc'],
                entries_crc=primary['entries_crc'],disk_guid=primary['disk_guid'],
                system_guid=by_name['FACTORYFS']['unique_guid'],data_guid=by_name['DATAFS']['unique_guid'],parts=primary['parts'],pit=found,
                native_layout_compatible=native_geometry)

def check_metadata(values,observed):
    texts={k:values[k][1].decode('utf8','strict') for k in TEXT_ORDER}
    if texts[16]!=f"{observed['major']}:{observed['minor']}\n" or texts[18]!=str(observed['sectors'])+'\n' or texts[19]!='MMC\n' or texts[24]!='512\n':
        raise ValueError('Source sysfs identity/geometry disagreement')
    if texts[17]!=''.join(f'{v:08x}' for v in observed['cid'])+'\n':raise ValueError('CID textual word ordering mismatch')
    rows=texts[20].splitlines()
    for row in rows:
        fields=row.split()
        if len(fields)<10 or not re.fullmatch('[0-9]+:[0-9]+',fields[2]) or ' - ' not in row:raise ValueError('Malformed mountinfo evidence')
        major,minor=map(int,fields[2].split(':'))
        if major==observed['major'] and minor<=12:raise ValueError('Internal block mount existed during capture')
    if len(texts[21].splitlines())!=1 or not texts[21].startswith('Filename'):raise ValueError('Active swap prevents quiescent backup')
    if '12550000' not in texts[22].lower() or not re.search(r'(mshci|dwmmc|dwmci)',texts[22],re.I):
        raise ValueError('IOMEM does not identify actual DWMMC/MSHCI host')
    return dict(mounts_internal_clear=True,swap_clear=True,clock_summary_available=not texts[23].startswith('UNAVAILABLE:'),
                ciu_clock_verified=False,host_physical=0x12550000)

def import_stream(source,output,expected_nonce,source_note,process_exit=None,model_source=False):
    source=project_file(source);output=Path(output).resolve();wanted=nonce(expected_nonce)
    if not output.is_relative_to(REPO/'out') or output.exists():raise ValueError('Use a fresh retained loader out directory')
    if not source_note.strip():raise ValueError('Source/session note is required')
    if type(model_source)is not bool or process_exit is not None and type(process_exit)is not int:raise ValueError('Exact acquisition provenance types required')
    output.mkdir(parents=True);meta={};digest=hashlib.sha256();stream_digest=hashlib.sha256();raw_item=None
    stamp=source.stat()
    with source.open('rb') as f:
        h=exact(f,128);observed=header(h)
        stream_digest.update(h)
        if bytes.fromhex(observed['nonce'])!=wanted:raise ValueError('Acquisition nonce mismatch')
        crc=zlib.crc32(h);sequence=0;data_count=0;data_crc=0;order=0;phase='pre'
        raw_output=None;partial=output/'mmcblk0-user.partial'
        if observed['mode']==2:raw_output=partial.open('xb')
        try:
            while True:
                frame=exact(f,32)
                if frame[:4]!=b'I9RF' or zlib.crc32(frame[:28])!=struct.unpack_from('<I',frame,28)[0]:raise ValueError('Frame header CRC mismatch')
                seq,kind_flags,n,offset,pcrc=struct.unpack_from('<IIIQI',frame,4);kind=kind_flags&65535;flags=kind_flags>>16
                if seq!=sequence or n>CHUNK:raise ValueError('Frame sequence/length mismatch')
                payload=exact(f,n)
                stream_digest.update(frame);stream_digest.update(payload)
                if zlib.crc32(payload)!=pcrc:raise ValueError('Acquired payload CRC mismatch')
                sequence+=1
                if kind==10:raise ValueError('Collector reported incomplete/changed media')
                if kind==9:
                    if phase!='post' or order!=6 or flags or offset or n!=32:raise ValueError('Premature END marker')
                    total,dcrc,scrc,frames,mode=struct.unpack_from('<QIIII',payload)
                    if any(payload[24:]) or (total,dcrc,scrc,frames,mode)!=(data_count,data_crc,crc,sequence-1,observed['mode']):
                        raise ValueError('Stream END accounting mismatch')
                    if observed['mode']==2 and data_count!=observed['sectors']*512 or observed['mode']==1 and data_count:
                        raise ValueError('Whole-user backup coverage incomplete')
                    if f.read(1):raise ValueError('Trailing acquisition bytes after END')
                    break
                if flags not in (0,1):raise ValueError('Unknown frame flags')
                if phase=='pre':
                    pre_order=TEXT_ORDER+TABLE_ORDER
                    if flags or order>=len(pre_order) or kind!=pre_order[order]:raise ValueError('Metadata/table order mismatch')
                    if kind>=16 and (offset or not 0<n<=MAX_TEXT):raise ValueError('Metadata frame offset/bound mismatch')
                    meta[kind]=(offset,payload);order+=1
                    if order==len(pre_order):phase='data' if observed['mode']==2 else 'post';order=0
                elif phase=='data' and kind==8:
                    if flags or offset!=data_count or not n or n%512 or n!=min(CHUNK,observed['sectors']*512-data_count):
                        raise ValueError('Missing/overlapping/short backup block')
                    assert raw_output is not None;raw_output.write(payload);digest.update(payload);data_crc=zlib.crc32(payload,data_crc);data_count+=n
                    if data_count==observed['sectors']*512:phase='post';order=0
                else:
                    if phase!='post' or flags!=1 or order>=6 or kind!=TABLE_ORDER[order] or (offset,payload)!=meta[kind]:
                        raise ValueError('Post-capture table drift/order mismatch')
                    order+=1
                crc=zlib.crc32(payload,zlib.crc32(frame,crc))
            tables=check_tables(meta,dict(observed,model_fixture=observed['model_fixture'] or model_source));metadata=check_metadata(meta,observed)
        finally:
            if raw_output is not None:raw_output.flush();os.fsync(raw_output.fileno());raw_output.close()
    source_receipt=file_item(source)
    final_stamp=source.stat()
    if (stamp.st_dev,stamp.st_ino,stamp.st_size,stamp.st_mtime_ns)!=(final_stamp.st_dev,final_stamp.st_ino,final_stamp.st_size,final_stamp.st_mtime_ns) or source_receipt['sha256']!=stream_digest.hexdigest():
        raise ValueError('Acquisition source changed during validation')
    # Only a terminal zero process exit qualifies a non-model acquisition;
    # EOF/END alone does not prove its final exclusive close succeeded.
    terminal=process_exit==0
    if process_exit not in (None,0):raise ValueError('Collector did not complete successfully')
    for kind,(off,raw) in meta.items():(output/NAMES[kind]).write_bytes(raw)
    (output/'cid.bin').write_bytes(struct.pack('<4I',*observed['cid']))
    (output/'gpt-primary.bin').write_bytes(meta[2][1]+meta[3][1]);(output/'gpt-backup.bin').write_bytes(meta[4][1]+meta[5][1])
    evidence={name:file_item(output/file) for name,file in (('cid','cid.bin'),('gpt-primary','gpt-primary.bin'),('gpt-backup','gpt-backup.bin'),('pit','pit.bin'))}
    if observed['mode']==2:
        if sha(partial)!=digest.hexdigest():raise ValueError('Host backup changed while writing')
        # Read the acquired whole bytes, rather than trusting the separate
        # table frames, to prove they belong to this actual backup image.
        with partial.open('rb') as f:
            for kind in TABLE_ORDER:
                at,expected=meta[kind];f.seek(at)
                if f.read(len(expected))!=expected:raise ValueError('Backup image/table frame disagreement')
        complete=output/'mmcblk0-user.img';partial.rename(complete);raw_item=file_item(complete)
    # Capture result remains unreviewed: a read-only TWRP observation has
    # Linux's active host clock/pins, not the future loader's idle profile.
    manifest=dict(schema=1,kind='i9100-emmc-read-acquisition',result='PASS',hardware_tested=False,device_contacted=False,
       source_note=source_note,source=source_receipt,process_exit_code=process_exit,source_process_terminal=terminal,
       device_observed=not observed['model_fixture'] and not model_source and terminal,model_fixture=observed['model_fixture'] or model_source,
       source_is_model=model_source,
       capture_header=observed,card={k:v for k,v in tables.items() if k not in ('parts','pit')},
       partitions=tables['parts'],pit_ids=tables['pit'],metadata=metadata,evidence=evidence,
       original_files={NAMES[k]:file_item(output/NAMES[k]) for k in meta},whole_user_area=raw_item,
       deployment_authorized=False,boot_ready=False,current_clock_and_pins_reviewed=False,
       evidence_checker_sha256=sha(Path(__file__).with_name('emmc-inventory-evidence.py')),
       importer_sha256=sha(__file__),requirements='Current native idle clock/pins, independently checked full backup and later deployment approval are separate; model evidence never hardware')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
    return output,manifest

def verify_acquisition(folder,require_backup=False,require_device=False):
    """Rehash actual retained bytes; never trust a PASS label or model as a
    currently usable restoration copy. Stream/source and complete image are
    independently hashed again before later planning can use this record."""
    folder=Path(folder).resolve()
    if not folder.is_relative_to(REPO/'out'):raise ValueError('Acquisition proof escaped retained project out')
    raw=(folder/'manifest.json').read_bytes()
    if len(raw)>256*1024:raise ValueError('Oversized acquisition manifest')
    m=json.loads(raw)
    if m.get('schema')!=1 or m.get('kind')!='i9100-emmc-read-acquisition' or m.get('result')!='PASS' or m.get('importer_sha256')!=sha(__file__):
        raise ValueError('Acquisition was not checked by the current importer')
    if m.get('evidence_checker_sha256')!=sha(Path(__file__).with_name('emmc-inventory-evidence.py')):
        raise ValueError('Acquisition table validator changed')
    if m.get('boot_ready')is not False or m.get('deployment_authorized')is not False or m.get('current_clock_and_pins_reviewed')is not False:
        raise ValueError('Read-only evidence must not assert deployment or idle clock approval')
    if type(m.get('source_is_model'))is not bool or type(m.get('source_process_terminal'))is not bool or m['model_fixture']!=(m['capture_header']['model_fixture']or m['source_is_model']) or m['source_process_terminal']!=(m['process_exit_code']==0) or m['device_observed']!=(not m['model_fixture']and m['source_process_terminal']):
        raise ValueError('Model/source/process provenance was altered')
    if require_device and (m.get('model_fixture')is not False or m.get('device_observed')is not True or m.get('source_process_terminal')is not True or m.get('process_exit_code')!=0):
        raise ValueError('Require completed original non-model device acquisition')
    entries=[m['source'],*m['original_files'].values(),*m['evidence'].values()]
    if set(m['original_files'])!=set(NAMES.values())or set(m['evidence'])!={'cid','gpt-primary','gpt-backup','pit'}:
        raise ValueError('Missing exact retained acquisition evidence set')
    for filename,item in m['original_files'].items():
        if (ROOT/item['path']).resolve()!=folder/filename:raise ValueError('Original acquisition evidence path changed')
    if m['whole_user_area']:entries.append(m['whole_user_area'])
    if require_backup and not m['whole_user_area']:raise ValueError('A metadata inventory is not a full-user backup')
    for item in entries:
        path=project_file(ROOT/item['path'])
        if path.stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:raise ValueError('Retained backup/evidence bytes changed')
    with (ROOT/m['source']['path']).open('rb')as f:
        if header(exact(f,128))!=m['capture_header']:raise ValueError('Acquisition header provenance changed')
    expected_raw={'cid':struct.pack('<4I',*m['capture_header']['cid']),
      'gpt-primary':(folder/NAMES[2]).read_bytes()+(folder/NAMES[3]).read_bytes(),
      'gpt-backup':(folder/NAMES[4]).read_bytes()+(folder/NAMES[5]).read_bytes(),'pit':(folder/NAMES[6]).read_bytes()}
    for name,expected in expected_raw.items():
        if (ROOT/m['evidence'][name]['path']).read_bytes()!=expected:raise ValueError('Canonical acquisition evidence disagrees with original table frames')
    values={kind:(0,(folder/NAMES[kind]).read_bytes()) for kind in TEXT_ORDER}
    offsets={1:0,2:512,4:(m['capture_header']['sectors']-1)*512,6:0x4400}
    offsets[3]=struct.unpack_from('<Q',(folder/NAMES[2]).read_bytes(),72)[0]*512
    offsets[5]=struct.unpack_from('<Q',(folder/NAMES[4]).read_bytes(),72)[0]*512
    values.update({kind:(offsets[kind],(folder/NAMES[kind]).read_bytes()) for kind in TABLE_ORDER})
    tables=check_tables(values,dict(m['capture_header'],model_fixture=m['model_fixture']));check_metadata(values,m['capture_header'])
    card={k:v for k,v in tables.items() if k not in ('parts','pit')}
    if card!=m['card'] or tables['parts']!=m['partitions'] or tables['pit']!=m['pit_ids']:raise ValueError('Retained acquisition table/manifest mismatch')
    if m['whole_user_area']:
        image=project_file(ROOT/m['whole_user_area']['path'])
        if image.stat().st_size!=m['capture_header']['sectors']*512:raise ValueError('Backup user-area size mismatch')
        with image.open('rb') as f:
            for kind in TABLE_ORDER:
                offset,wanted=values[kind];f.seek(offset)
                if f.read(len(wanted))!=wanted:raise ValueError('Current backup table bytes changed')
    return m

def main():
    if os.name!='posix':raise RuntimeError('Run importer/hashes within the WSL CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--stream',type=Path,required=True);p.add_argument('--nonce',required=True)
    p.add_argument('--source-note',required=True);p.add_argument('--process-exit',type=int);p.add_argument('--model-source',action='store_true');p.add_argument('--output',type=Path)
    a=p.parse_args();output=a.output or REPO/'out'/('emmc-acquisition-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    folder,m=import_stream(a.stream,output,a.nonce,a.source_note,a.process_exit,a.model_source);print(json.dumps(dict(output=str(folder),model=m['model_fixture'],
      device_observed=m['device_observed'],boot_ready=False,whole_user_bytes=m['whole_user_area']['bytes'] if m['whole_user_area'] else 0),indent=2))
if __name__=='__main__':main()
