#!/usr/bin/env python3
"""Prepare local iOS6 battery sprites for a freestanding RGB565 renderer.

Retains all 17 native levels. Low red is an explicitly recorded derivative;
firmware artwork stays in project assets, outside the source repositories.
"""
import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path


def bilinear(data, width, height, x, y, channel):
    x = max(0, min((width - 1) * 256, x))
    y = max(0, min((height - 1) * 256, y))
    ix, fx = divmod(x, 256)
    iy, fy = divmod(y, 256)
    nx, ny = min(ix + 1, width - 1), min(iy + 1, height - 1)
    a = data[(iy * width + ix) * 4 + channel]
    b = data[(iy * width + nx) * 4 + channel]
    c = data[(ny * width + ix) * 4 + channel]
    d = data[(ny * width + nx) * 4 + channel]
    return (a * (256 - fx) * (256 - fy) + b * fx * (256 - fy) +
            c * (256 - fx) * fy + d * fx * fy + 32768) // 65536


def resize_rgb(data, width, height, target_w, target_h):
    result = bytearray(target_w * target_h * 3)
    for y in range(target_h):
        sy = ((2 * y + 1) * height * 128 // target_h) - 128
        for x in range(target_w):
            sx = ((2 * x + 1) * width * 128 // target_w) - 128
            for c in range(3):
                result[(y * target_w + x) * 3 + c] = bilinear(data, width, height, sx, sy, c)
    return result


def main():
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice',
                    '-c2', '-n7', sys.executable, '-B', __file__, *sys.argv[1:]],
                   dict(os.environ, I9100_CPU_CAPPED='1'))
    import importlib.util
    import lz4.block
    project = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, out = args.input.resolve(), args.output.resolve()
    if not source.is_relative_to(project / 'assets') or not (source / 'manifest.json').is_file():
        parser.error('Original extraction inside project assets required')
    if not out.is_relative_to(project / 'assets') or out.exists():
        parser.error('Fresh project assets output required')
    metadata = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
    entries = {x['name']: x for x in metadata['assets']}
    spec = importlib.util.spec_from_file_location('original_png', Path(__file__).with_name('extract-charge-art.py'))
    png = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(png)
    out.mkdir(parents=True)
    width, body_h, height = 396, 194, 258
    originals = []
    for n in range(1, 18):
        name = f'BatteryBG_{n}@2x.png'
        entry = entries[name]
        raw = (source / 'original' / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry['original_sha256']:
            raise ValueError('Original artwork changed since extraction')
        w, h, rgba, cgbi = png.decode_png(raw)
        if (w, h, cgbi) != (528, 258, True):
            raise ValueError('Only the verified iOS6 battery family is accepted')
        originals.append(resize_rgb(rgba, w, h, width, body_h))
    mask_raw = (source / 'original' / 'BatteryReflectionMask@2x.png').read_bytes()
    if hashlib.sha256(mask_raw).hexdigest() != entries['BatteryReflectionMask@2x.png']['original_sha256']:
        raise ValueError('Original reflection mask changed')
    mw, mh, mask, _ = png.decode_png(mask_raw)
    red = bytearray(originals[1])
    empty = originals[0]
    # Recolor only the native fill contribution; glass/highlights stay native.
    for i in range(0, len(red), 3):
        r, g, b = red[i:i + 3]
        er, eg, eb = empty[i:i + 3]
        if g - max(r, b) > 10 and g > eg:
            fill = max(0, g - eg)
            red[i] = min(255, er + fill)
            red[i + 1] = min(255, eg + fill // 10)
            red[i + 2] = min(255, eb + fill // 12)
    frames = originals + [red]
    blocks = []
    frame_records = []
    for index, body in enumerate(frames):
        rgb = bytearray(width * height * 3)
        rgb[:len(body)] = body
        for y in range(58):
            my = min(mh - 1, y * mh // 58)
            a = mask[(my * mw) * 4 + 3]
            fade = a * (58 - y) * 46 // (58 * 255)
            source_y = body_h - 1 - y
            for x in range(width):
                for c in range(3):
                    rgb[((body_h + 6 + y) * width + x) * 3 + c] = body[(source_y * width + x) * 3 + c] * fade // 255
        raw = bytearray()
        for i in range(0, len(rgb), 3):
            r, g, b = rgb[i:i + 3]
            raw += struct.pack('<H', ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3))
        compressed = lz4.block.compress(bytes(raw), store_size=False)
        if lz4.block.decompress(compressed, uncompressed_size=len(raw)) != raw:
            raise ValueError('Packed frame does not roundtrip')
        blocks.append(compressed)
        preview = png.png_rgb(width, height, bytes(rgb))
        (out / f'level-{index:02d}.png').write_bytes(preview)
        frame_records.append(dict(index=index, source=f'BatteryBG_{index + 1}@2x.png' if index < 17 else 'red derivative of BatteryBG_2@2x.png',
                                  raw_sha256=hashlib.sha256(raw).hexdigest(), compressed_bytes=len(compressed)))
    table_size = 32 + len(blocks) * 8
    at = table_size
    table = bytearray()
    for block in blocks:
        table += struct.pack('<II', at, len(block))
        at += len(block)
    pack = (struct.pack('<4s7I', b'I9B1', 1, width, height, len(blocks), width * height * 2, table_size, at) +
            table + b''.join(blocks))
    if len(pack) > 2 * 1024 * 1024:
        raise ValueError('Local artwork exceeds loader resource budget')
    (out / 'battery.i9b').write_bytes(pack)
    manifest = dict(source_manifest=str((source / 'manifest.json').relative_to(project)),
                    source_manifest_sha256=hashlib.sha256((source / 'manifest.json').read_bytes()).hexdigest(),
                    pack_sha256=hashlib.sha256(pack).hexdigest(), pack_bytes=len(pack),
                    format='I9B1 bounded LZ4 RGB565, 17 native frames plus red derivative',
                    width=width, height=height, body_height=body_h, original_scale='3/4 bilinear, original aspect retained',
                    reflection='Native reflection alpha mask, vertically mirrored body with dim falloff', frames=frame_records)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(result='PASS', frames=len(frames), bytes=len(pack), output=str(out))), flush=True)


if __name__ == '__main__':
    main()
