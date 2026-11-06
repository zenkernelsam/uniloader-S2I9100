#!/usr/bin/env python3
"""Correct the two BPBs of a locally generated SD candidate, preserving all files."""
from pathlib import Path
import struct
import sys
image=Path(sys.argv[1]).resolve()
repo=Path(__file__).resolve().parents[2]
assert image.is_relative_to(repo/'out') and image.name=='sd-ios6-oneshot.img'
with image.open('r+b') as f:
    mbr=f.read(512);part=struct.unpack_from('<I',mbr,454)[0]
    assert mbr[510:]==b'\x55\xaa' and part==2048
    f.seek(part*512);boot=bytearray(f.read(512))
    backup=struct.unpack_from('<H',boot,50)[0]
    assert struct.unpack_from('<I',boot,28)[0] in (0,part) and backup==6
    f.seek((part+backup)*512);assert f.read(512)==boot
    struct.pack_into('<I',boot,28,part)
    for sector in (part,part+backup):
        f.seek(sector*512);f.write(boot)
print('PASS primary and backup FAT BPB hidden-sector fields')
