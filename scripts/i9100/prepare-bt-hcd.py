#!/usr/bin/env python3
"""Audit/copy a project-local original Bluetooth HCD; never contact a device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from datetime import datetime
REPO=Path(__file__).resolve().parents[2];ROOT=REPO.parent.resolve()
MAX_HCD=1024*1024


def cap():
    if os.name!='posix':raise RuntimeError('Run inside WSL with the project CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    if set(os.sched_getaffinity(0))-set(range(14)) or os.getpriority(os.PRIO_PROCESS,0)<10:raise RuntimeError('Missing CPU envelope')


def source(path,limit):
    path=path.resolve()
    if not path.is_relative_to(ROOT) or not path.is_file() or not 0<path.stat().st_size<=limit:raise ValueError('Require bounded project-local input')
    raw=path.read_bytes()
    if len(raw)>limit:raise ValueError('Input changed size while reading')
    return raw,dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def parse_hcd(raw,base,span,launch):
    if not raw or len(raw)>MAX_HCD or not 0<=base<=0xffffffff or not 0<span<=16*1024*1024 or base+span>0x100000000:
        raise ValueError('Unsupported actual Bluetooth RAM geometry')
    if not 0<=launch<=0xffffffff or launch!=0xffffffff and not base<=launch&~1<base+span:
        raise ValueError('Reviewed launch address is outside controller RAM')
    at=0;records=[];wrote=launched=False
    while at<len(raw):
        if len(raw)-at<3:raise ValueError('Truncated HCD command header')
        op,length=struct.unpack_from('<HB',raw,at);end=at+3+length
        if end>len(raw) or launched or len(records)>=65536:raise ValueError('Truncated/late/unbounded HCD command')
        address=None
        if op==0xfc2e:
            if length or records:raise ValueError('Minidriver is permitted only as the first empty record')
        elif op==0xfc4c:
            if length<=4:raise ValueError('RAM write must contain an address and data')
            address=struct.unpack_from('<I',raw,at+3)[0]
            if not base<=address or address+length-4>base+span:raise ValueError('RAM write outside reviewed controller range')
            wrote=True
        elif op==0xfc4e:
            if length!=4 or not wrote:raise ValueError('Launch must follow reviewed RAM writes')
            address=struct.unpack_from('<I',raw,at+3)[0]
            if address!=launch:raise ValueError('HCD launch differs from separately reviewed address')
            launched=True
        else:raise ValueError(f'Unsupported HCD opcode {op:04x}; inspect the original asset before expanding policy')
        records.append(dict(offset=at,bytes=end-at,opcode=op,payload_bytes=length,address=address,
                            sha256=hashlib.sha256(raw[at:end]).hexdigest()))
        at=end
    if not wrote or not launched:raise ValueError('HCD lacks a reviewed write/launch sequence')
    return records


def controller_proof(data):
    def version(value):
        required=('hci_version','lmp_version','hci_revision','manufacturer','lmp_subversion')
        if set(value)!=set(required) or any(type(value[key]) is not int for key in required):raise ValueError('Exact raw controller version fields required')
        for key in required:
            maximum=255 if key in ('hci_version','lmp_version') else 65535
            if not 0<=value[key]<=maximum:raise ValueError('Version field range')
        if value['manufacturer']!=15:raise ValueError('Controller manufacturer is not Broadcom')
        return dict(value)
    rom=version(data['rom']);patched=version(data['patched'])
    addr=bytes.fromhex(data['factory_bdaddr_hci_hex'])
    if len(addr)!=6 or addr in (bytes(6),b'\xff'*6,b'\x00\x00\x00\xb1\x30\x43'):raise ValueError('Invalid/default controller address')
    # Bluetooth addresses use HCI little-endian octets. Ethernet multicast
    # bits are unrelated; never invent a new address or apply MAC bit rules.
    return dict(rom=rom,patched=patched,factory_bdaddr_hci_hex=addr.hex())


def prepare(args):
    if not args.source_note.strip():raise ValueError('Original asset/controller/RAM provenance note required')
    image,im=source(args.hcd,MAX_HCD);proof,pm=source(args.controller_proof,16384)
    controller=controller_proof(json.loads(proof));records=parse_hcd(image,args.ram_base,args.ram_bytes,args.launch_address)
    if not 5000<=args.timeout_ms<=300000:raise ValueError('Timeout outside bootstrap range')
    output=args.output.resolve() if args.output else REPO/'out'/('bt-hcd-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    if not output.is_relative_to((REPO/'out').resolve()) or output.exists():raise ValueError('Use a fresh loader out directory')
    manifest=dict(schema=1,kind='i9100-bcm-bluetooth-ram-bootstrap',hardware_tested=False,device_contacted=False,
        board_data_reviewed=bool(args.mark_reviewed),source_note=args.source_note,inputs=dict(hcd=im,controller_proof=pm),
        profile=dict(**controller,ram_base=args.ram_base,ram_bytes=args.ram_bytes,launch_address=args.launch_address,
            timeout_ms=args.timeout_ms,hcd_sha256=im['sha256']),records=records,
        requirements='Actual U1 power/rails/LPO and fresh UART0 generation, identity/BDADDR/RAM/launch reviewed separately; no on-device write by this tool')
    output.mkdir(parents=True);(output/'firmware.hcd').write_bytes(image);(output/'controller-proof.source.json').write_bytes(proof)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    if hashlib.sha256((output/'firmware.hcd').read_bytes()).hexdigest()!=im['sha256']:raise RuntimeError('Retained HCD copy changed')
    return output,manifest


def main():
    cap();p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hcd',type=Path,required=True);p.add_argument('--controller-proof',type=Path,required=True)
    p.add_argument('--ram-base',type=lambda text:int(text,0),required=True);p.add_argument('--ram-bytes',type=lambda text:int(text,0),required=True)
    p.add_argument('--launch-address',type=lambda text:int(text,0),required=True);p.add_argument('--timeout-ms',type=int,default=30000)
    p.add_argument('--source-note',required=True);p.add_argument('--mark-reviewed',action='store_true');p.add_argument('--output',type=Path)
    output,m=prepare(p.parse_args());print(json.dumps(dict(output=str(output),records=len(m['records']),hcd_sha256=m['profile']['hcd_sha256'],
        board_data_reviewed=m['board_data_reviewed'],hardware_tested=False,device_contacted=False),indent=2))


if __name__=='__main__':main()
