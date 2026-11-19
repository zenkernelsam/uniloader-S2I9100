#!/usr/bin/env python3
"""Read the local iOS6 HFS image and preserve the original charging artwork.

Only extracts explicitly named SpringBoard PNGs. Never mounts or edits HFS,
and keeps Apple's original bytes separately from normalized previews.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path


def chunk(kind, data):
    return (struct.pack('>I', len(data)) + kind + data +
            struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff))


def png_rgb(width, height, rgb):
    if len(rgb) != width * height * 3:
        raise ValueError('Exact RGB dimensions required')
    rows = b''.join(b'\0' + rgb[y * width * 3:(y + 1) * width * 3]
                    for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b''))


def decode_png(raw):
    """Decode bounded original PNG/CgBI; return RGBA premultiplied on black."""
    if raw[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('Original asset is not PNG')
    at = 8
    compressed = bytearray()
    cgbi = False
    size = None
    ended = False
    while at < len(raw):
        if at + 12 > len(raw):
            raise ValueError('Truncated PNG chunk')
        n = struct.unpack_from('>I', raw, at)[0]
        kind = raw[at + 4:at + 8]
        if n > len(raw) - at - 12:
            raise ValueError('PNG chunk length exceeds file')
        data = raw[at + 8:at + 8 + n]
        crc = struct.unpack_from('>I', raw, at + 8 + n)[0]
        if zlib.crc32(kind + data) & 0xffffffff != crc:
            raise ValueError('Original PNG CRC differs')
        if kind == b'CgBI':
            cgbi = True
        elif kind == b'IHDR':
            if size is not None or n != 13:
                raise ValueError('Unknown PNG header')
            w, h, bits, color, comp, filt, inter = struct.unpack('>2I5B', data)
            if not (1 <= w <= 2048 and 1 <= h <= 2048 and bits == 8 and
                    color in (2, 6) and comp == filt == inter == 0):
                raise ValueError('Unsupported original PNG pixel layout')
            size = (w, h, 4 if color == 6 else 3)
        elif kind == b'IDAT':
            compressed += data
        elif kind == b'IEND':
            if n:
                raise ValueError('Bad PNG terminator')
            ended = True
            at += 12
            break
        at += 12 + n
    if size is None or not ended or at != len(raw):
        raise ValueError('Incomplete original PNG')
    w, h, step = size
    expected = h * (1 + w * step)
    dec = zlib.decompressobj(-15 if cgbi else 15)
    decoded = dec.decompress(compressed, expected + 1)
    if len(decoded) != expected or not dec.eof or dec.unused_data or dec.unconsumed_tail:
        raise ValueError('PNG decoded size/stream differs')
    previous = bytearray(w * step)
    rgba = bytearray()
    for y in range(h):
        start = y * (w * step + 1)
        filt = decoded[start]
        row = bytearray(decoded[start + 1:start + 1 + w * step])
        if filt > 4:
            raise ValueError('Unknown PNG row filter')
        for x in range(len(row)):
            a = row[x - step] if x >= step else 0
            b = previous[x]
            c = previous[x - step] if x >= step else 0
            if filt == 1:
                predictor = a
            elif filt == 2:
                predictor = b
            elif filt == 3:
                predictor = (a + b) // 2
            elif filt == 4:
                p = a + b - c
                distances = (abs(p - a), abs(p - b), abs(p - c))
                predictor = (a, b, c)[distances.index(min(distances))]
            else:
                predictor = 0
            row[x] = (row[x] + predictor) & 255
        for x in range(w):
            pixel = row[x * step:(x + 1) * step]
            a = pixel[3] if step == 4 else 255
            r, g, b = (pixel[2], pixel[1], pixel[0]) if cgbi else pixel[:3]
            if not cgbi:
                r, g, b = ((v * a + 127) // 255 for v in (r, g, b))
            rgba += bytes((r, g, b, a))
        previous = row
    return w, h, bytes(rgba), cgbi


def main():
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice',
                    '-c2', '-n7', sys.executable, '-B', __file__, *sys.argv[1:]],
                   dict(os.environ, I9100_CPU_CAPPED='1'))
    project = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, default=project / 'assets/ios6-extract/ROOTFS6.HFS')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image = args.image.resolve()
    out = args.output.resolve()
    if not image.is_relative_to(project / 'assets') or not image.is_file():
        parser.error('Read-only image must be inside project assets')
    if not out.is_relative_to(project / 'assets') or out.exists():
        parser.error('Fresh project assets directory required')
    out.mkdir(parents=True)
    listing = subprocess.run(['fls', '-r', '-p', str(image)], capture_output=True, check=True)
    (out / 'hfs-paths.txt').write_bytes(listing.stdout)
    (out / 'hfs-listing-stderr.txt').write_bytes(listing.stderr)
    names = [f'BatteryBG_{n}@2x.png' for n in range(1, 18)]
    names += ['BatteryHUD@2x.png', 'BatteryReflectionMask@2x.png']
    prefix = 'System/Library/CoreServices/SpringBoard.app/'
    entries = {}
    for line in listing.stdout.decode('utf-8', 'strict').splitlines():
        match = re.fullmatch(r'r/r ([0-9]+):\s*(.*)', line)
        if match and match[2].startswith(prefix) and match[2][len(prefix):] in names:
            name = match[2][len(prefix):]
            if name in entries:
                raise ValueError('Duplicate original image entry')
            entries[name] = match[1]
    if set(entries) != set(names):
        raise ValueError('Original iOS6 battery asset set incomplete')
    originals = out / 'original'
    decoded_dir = out / 'decoded'
    originals.mkdir()
    decoded_dir.mkdir()
    records = []
    for name in names:
        result = subprocess.run(['icat', str(image), entries[name]], capture_output=True, check=True)
        raw = result.stdout
        (originals / name).write_bytes(raw)
        w, h, rgba, cgbi = decode_png(raw)
        (decoded_dir / (name + '.rgba')).write_bytes(rgba)
        rgb = b''.join(rgba[i:i + 3] for i in range(0, len(rgba), 4))
        (decoded_dir / name).write_bytes(png_rgb(w, h, rgb))
        records.append(dict(name=name, path=prefix + name, inode=int(entries[name]),
                            bytes=len(raw), original_sha256=hashlib.sha256(raw).hexdigest(),
                            width=w, height=h, cgbi=cgbi,
                            decoded_rgba_sha256=hashlib.sha256(rgba).hexdigest()))
    manifest = dict(source='Local iOS6 BrightonMaps10B329 SpringBoard resources',
                    image=str(image.relative_to(project)), image_bytes=image.stat().st_size,
                    hfs_listing_sha256=hashlib.sha256(listing.stdout).hexdigest(),
                    operation='read-only fls/icat; HFS never mounted or modified',
                    decode='CgBI BGRA premultiplied; black composite; PNG CRC checked', assets=records)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(result='PASS', source_assets=len(records), output=str(out))), flush=True)


if __name__ == '__main__':
    main()
