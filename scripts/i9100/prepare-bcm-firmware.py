#!/usr/bin/env python3
"""Prepare a local BCM4330 RAM-staging manifest; never open USB or change a radio."""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
ROOT=REPO.parent.resolve()
MAX_RAM=4*1024*1024

def cap():
    if os.name!="posix":
        raise RuntimeError("Run packaging inside WSL with the project CPU envelope")
    if os.environ.get("I9100_CPU_CAPPED")!="1":
        os.execvpe("taskset",["taskset","-c","0-13","nice","-n10","ionice","-c2","-n7",
                             sys.executable,"-B",*sys.argv],dict(os.environ,I9100_CPU_CAPPED="1"))
    if set(os.sched_getaffinity(0))-set(range(14)) or os.getpriority(os.PRIO_PROCESS,0)<10:
        raise RuntimeError("Missing CPU envelope")

def read(path,limit):
    path=path.resolve()
    if not path.is_relative_to(ROOT) or not path.is_file() or path.stat().st_size>limit:
        raise ValueError("Input must be a bounded project-local file: "+str(path))
    data=path.read_bytes()
    if len(data)>limit:
        raise ValueError("Input grew during reading")
    return data,dict(path=str(path.relative_to(ROOT)),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def parse_mac(data):
    text=data.decode("ascii").strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",text):
        raise ValueError("Expected one factory MAC address, no placeholders or extra records")
    mac=bytes.fromhex(text.replace(":",""))
    if mac[0]&1 or not any(mac):
        raise ValueError("Factory MAC must be nonzero unicast")
    return mac

def pack_nvram(raw,mac):
    # Same CR/comment/record rules as pinned process_nvram_vars. Preserve
    # value bytes; reject unsupported keys/duplicates instead of changing
    # calibration, stripping value spaces, or inventing a country/MAC.
    if not raw or len(raw)>=4096 or b"\0" in raw:
        raise ValueError("Expected nonempty stock NVRAM text shorter than4096B")
    entries=[]
    keys=set()
    for line in raw.decode("ascii").replace("\r","").split("\n"):
        line=line.split("#",1)[0]
        if not line.strip():
            continue
        key,sep,value=line.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z0-9_.]{1,64}",key) or key in keys:
            raise ValueError("Unsupported or duplicate NVRAM key: "+key)
        record=line.encode("ascii")
        if len(record)>512 or any(ch<32 or ch>126 for ch in record):
            raise ValueError("Nonprintable or oversized NVRAM record")
        if key=="macaddr" and parse_mac(value.encode("ascii"))!=mac:
            raise ValueError("Stock NVRAM MAC differs from the separately sourced factory MAC; review stock customization first")
        if key=="macaddr" and len(value)!=17:
            raise ValueError("MAC record has unsupported surrounding whitespace")
        keys.add(key)
        entries.append(record)
    if "macaddr" not in keys or len(entries)>128:
        raise ValueError("Missing factory-matching macaddr or too many NVRAM records")
    base=b"\0".join(entries)+b"\0"
    # Samsung download_nvram adds a terminal NUL after process_nvram_vars'
    # four-byte pad; the kernel then applies final word padding and rev7 WAR.
    packed=base+b"\0"*((-len(base))%4+1)
    if len(packed)>4096:
        raise ValueError("Packed NVRAM exceeds driver limit")
    return packed,sorted(keys)

def layout(ram,rev,fw,nv):
    if ram<16384 or ram>MAX_RAM or ram%4 or fw<8 or fw>MAX_RAM or nv<3 or nv>4096 or not 0<=rev<=255:
        raise ValueError("Geometry exceeds the supported RAM staging profile")
    fp=(fw+3)&~3
    np=(nv+3)&~3
    address=ram-4-np
    if rev==7 and address&0x3c==0x3c and np>4:
        address-=4
        np+=4
    if address<0 or fp>address:
        raise ValueError("Firmware and NVRAM regions overlap")
    words=np//4
    return dict(ram_bytes=ram,firmware_bytes=fw,firmware_padded=fp,nvram_bytes=nv,nvram_padded=np,
                nvram_address=address,token_address=ram-4,token=((~words&0xffff)<<16)|words)

def prepare(args):
    if not args.source_note.strip() or not 0<=args.chip_revision<=15:
        raise ValueError("Source note and actual chip revision are required")
    image,im=read(args.firmware,MAX_RAM)
    raw,nm=read(args.nvram,4096)
    factory,fm=read(args.factory_mac_file,128)
    mac=parse_mac(factory)
    packed,keys=pack_nvram(raw,mac)
    geometry=layout(args.ram_bytes,args.sdio_revision,len(image),len(packed))
    output=args.output.resolve() if args.output else REPO/"out"/("bcm-firmware-"+datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not output.is_relative_to((REPO/"out").resolve()) or output.exists():
        raise ValueError("Output must be a NEW folder under this loader's out")
    manifest=dict(schema=1,kind="bcm4330-halted-ram-staging",chip_id=0x4330,chip_revision=args.chip_revision,
                  sdio_core_revision=args.sdio_revision,layout=geometry,verified_factory_mac=mac.hex(":"),
                  board_data_reviewed=args.mark_reviewed,hardware_tested=False,radio_started=False,
                  source_note=args.source_note,inputs=dict(firmware=im,nvram=nm,factory_mac=fm),nvram_keys=keys,
                  files={"firmware.bin":dict(bytes=len(image),sha256=hashlib.sha256(image).hexdigest()),
                         "nvram.packed.bin":dict(bytes=len(packed),sha256=hashlib.sha256(packed).hexdigest())},
                  required_before_hardware="Fresh native F1 host, actual DMP/CM3+D11 held-reset/RAM proof, reviewed original assets; no core activation API in this delivery")
    output.mkdir(parents=True)
    (output/"firmware.bin").write_bytes(image)
    (output/"nvram.packed.bin").write_bytes(packed)
    (output/"nvram.original.txt").write_bytes(raw)
    (output/"factory-mac.source.txt").write_bytes(factory)
    for name,meta in manifest["files"].items():
        if hashlib.sha256((output/name).read_bytes()).hexdigest()!=meta["sha256"]:
            raise RuntimeError("Output verification failed; incomplete folder retained")
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    return output,manifest

def main():
    cap()
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firmware",type=Path,required=True)
    p.add_argument("--nvram",type=Path,required=True)
    p.add_argument("--factory-mac-file",type=Path,required=True)
    p.add_argument("--chip-revision",type=int,required=True)
    p.add_argument("--sdio-revision",type=int,required=True)
    p.add_argument("--ram-bytes",type=int,required=True,help="Actual size from chip RAM probe, not a copied nominal value")
    p.add_argument("--source-note",required=True)
    p.add_argument("--mark-reviewed",action="store_true",help="Mark original asset/revision/board data as reviewed; no hardware action")
    p.add_argument("--output",type=Path)
    args=p.parse_args()
    out,manifest=prepare(args)
    print(json.dumps(dict(output=str(out),hardware_tested=False,board_data_reviewed=manifest["board_data_reviewed"],
                         files=manifest["files"]),indent=2))

if __name__=="__main__":
    main()
