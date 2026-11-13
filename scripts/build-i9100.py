#!/usr/bin/env python3
"""Build sibling XNU and uniLoader GT-I9100 sources into a raw zImage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tarfile
import uuid


def run(*command, cwd):
    print('+', ' '.join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, check=True)


def git_head(path):
    try:
        head = subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],stderr=subprocess.DEVNULL).decode().strip()
        dirty = bool(subprocess.check_output(['git','-C',str(path),'status','--porcelain']))
        return {'commit':head,'dirty':dirty}
    except subprocess.CalledProcessError:
        return {'commit':None,'dirty':True}


def kernel_identity(kernel):
    data = kernel.read_bytes()
    if struct.unpack_from('<I', data)[0] != 0xfeedface:
        raise ValueError('Expected 32-bit Mach-O kernel')
    result = {}
    cursor = 28
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > len(data):
            raise ValueError('Invalid Mach-O load command')
        if command == 0x1b:
            result['uuid'] = str(uuid.UUID(bytes=data[cursor+8:cursor+24])).upper()
        if command == 5:
            result['entry_vm'] = hex(struct.unpack_from('<I', data, cursor+16+15*4)[0])
        cursor += size
    if set(result) != {'uuid', 'entry_vm'}:
        raise ValueError('Kernel has no UUID or LC_UNIXTHREAD entry')
    return result


def main():
    loader = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xnu', type=Path, default=loader.parent/'xnu-S2I9100')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--skip-kernel', action='store_true')
    parser.add_argument('--extra-cmdline', default='')
    parser.add_argument('--archives', action='store_true', help='Also create boot.img and Odin tar archives')
    args = parser.parse_args()
    xnu = args.xnu.resolve()
    if args.jobs < 1 or not (xnu/'osfmk/arm/pmap.c').is_file():
        parser.error('Provide the XNU source directory and a positive job count')
    if any(c in args.extra_cmdline for c in '\n\r"\\') or not args.extra_cmdline.isascii():
        parser.error('Extra command line must be single-line ASCII without quotes or backslashes')
    if sys.platform not in ('darwin', 'linux'):
        parser.error('This build recipe supports macOS and Linux hosts')
    prefix = os.environ.get('I9100_CROSS_COMPILE','arm-none-eabi-')
    for tool in ('make', prefix+'gcc', prefix+'objcopy'):
        if not shutil.which(tool):
            parser.error(f'Required tool not found: {tool}')
    if not args.skip_kernel:
        run('make', '-C', xnu, 'TARGET_CONFIGS=RELEASE ARM EXYNOS4210_I9100', f'-j{args.jobs}', cwd=loader)
    kernel = xnu/'BUILD/obj/RELEASE_ARM_EXYNOS4210_I9100/mach_kernel'
    symbols = kernel.with_name('mach_kernel.sys')
    assym = kernel.parent/'osfmk/RELEASE/assym.s'
    for needed in (kernel, symbols, assym):
        if not needed.is_file():
            parser.error(f'Kernel or matching symbols missing: {needed}')
    identity = kernel_identity(kernel)
    if kernel_identity(symbols) != identity:
        parser.error('Kernel and unstripped symbols have different identities')
    helpers = loader/'scripts/i9100'
    run(sys.executable, helpers/'mkraw.py', kernel, loader/'blob/Image', cwd=loader)
    run(sys.executable, helpers/'prepare-payloads.py', loader/'blob', cwd=loader)
    run('make', 'ARCH=arm', f'CROSS_COMPILE={prefix}', 'i9100_defconfig', cwd=loader)
    cfg = loader/'.config'
    if args.extra_cmdline:
        lines = cfg.read_text().splitlines()
        lines = [line[:-1]+' '+args.extra_cmdline+'"' if line.startswith('CONFIG_XNU_CMDLINE=') else line for line in lines]
        cfg.write_text('\n'.join(lines)+'\n')
    # start.S includes the blobs with .incbin; force their assembly after generation.
    (loader/'arch/arm/start.S').touch()
    run('make', 'ARCH=arm', f'CROSS_COMPILE={prefix}', f'-j{args.jobs}', cwd=loader)
    out = loader/'out'
    out.mkdir(exist_ok=True)
    shutil.copy2(loader/'uniLoader', out/'zImage')
    shutil.copy2(symbols, out/'mach_kernel.sys')
    shutil.copy2(assym, out/'assym.s')
    names = ['zImage', 'mach_kernel.sys', 'assym.s']
    if args.archives:
        run(sys.executable, helpers/'mkbootimg.py', out/'zImage', out/'boot.img', cwd=loader)
        for archive, image in [('zImage.tar','zImage'),('boot.tar','boot.img')]:
            with tarfile.open(out/archive, 'w', format=tarfile.USTAR_FORMAT) as tf:
                tf.add(out/image, arcname=image)
        names += ['boot.img', 'zImage.tar', 'boot.tar']
    manifest = {'xnu':git_head(xnu), 'uniloader':git_head(loader),
                'kernel':identity,'extra_cmdline':args.extra_cmdline,'artifacts':{}}
    for name in names:
        data = (out/name).read_bytes()
        manifest['artifacts'][name] = {'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    for repo in (xnu, loader):
        source_manifest = repo/'SOURCE_MANIFEST.json'
        if source_manifest.is_file():
            manifest[repo.name]['source_manifest_sha256'] = hashlib.sha256(source_manifest.read_bytes()).hexdigest()
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'Raw image, matching symbols and manifest: {out}')


if __name__ == '__main__':
    main()
