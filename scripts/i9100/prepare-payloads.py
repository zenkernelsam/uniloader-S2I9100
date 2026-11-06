#!/usr/bin/env python3
"""Generate the minimal GT-I9100 Apple device tree and empty ramdisk."""
import argparse
import struct
from pathlib import Path


def property_bytes(name, value):
    encoded = name.encode('ascii')
    if len(encoded) > 31:
        raise ValueError('Device-tree property name is too long')
    return encoded.ljust(32, b'\0') + struct.pack('<I', len(value)) + value + b'\0' * (-len(value) % 4)


def node(properties, children=()):
    return struct.pack('<II', len(properties), len(children)) + b''.join(
        property_bytes(name, value) for name, value in properties) + b''.join(children)


def device_tree():
    # iOS 7 MobileGestalt reads /chosen/display-scale as four-byte native
    # uint32 OSData. Missing data becomes scale 0, and GraphicsServices then
    # divides pixel dimensions by zero. This is integer 1, not float 1.0.
    # backboardd also reads /chosen/display-rotation (u32 angle); absent read
    # logs as a miss on the live path probe, so publish an explicit zero.
    chosen = node([('name', b'chosen\0'), ('firmware-version', b'uniLoader-i9100\0'),
                   ('debug-enabled', b'\1'), ('display-scale', struct.pack('<I', 1)),
                   ('display-rotation', struct.pack('<I', 0))])
    # backboardd reads region-info on the machine node for MobileGestalt.
    return node([('name', b'device-tree\0'), ('model', b'Samsung Galaxy S2 (GT-I9100)\0'),
                 ('compatible', b'samsung,i9100\0samsung,exynos4210\0'),
                 ('region-info', b'LL/A\0')], [chosen])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('blob_directory', type=Path)
    parser.add_argument('--dt-only', action='store_true', help='Preserve the existing ramdisk payload')
    args = parser.parse_args()
    args.blob_directory.mkdir(parents=True, exist_ok=True)
    tree = device_tree()
    (args.blob_directory/'dtb').write_bytes(tree)
    if not args.dt_only:
        (args.blob_directory/'ramdisk').write_bytes(b'')
    print(f'Generated Apple device tree ({len(tree)} bytes), display-scale uint32=1; '
          + ('existing ramdisk preserved' if args.dt_only else 'empty ramdisk'))


if __name__ == '__main__':
    main()
