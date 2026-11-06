#!/usr/bin/env python3
"""Build and verify an i9100 KERNEL-only candidate, without deleting old files."""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
from zoneinfo import ZoneInfo


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, cwd, log):
    result = subprocess.run(list(map(str, argv)), cwd=cwd, text=True, capture_output=True)
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        print((result.stdout + result.stderr)[-3000:], file=sys.stderr)
        raise RuntimeError(f'Command failed; see {log}')


def main():
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        os.execvpe('taskset', ['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
            sys.executable, __file__, *sys.argv[1:]], dict(os.environ, I9100_CPU_CAPPED='1'))
    loader = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    kernel = args.kernel.resolve()
    if not output.is_relative_to(loader/'out') or output.exists():
        parser.error('Use a new output directory inside loader out')
    if not kernel.is_relative_to(loader.parent/'xnu'):
        parser.error('Kernel must come from the matching XNU worktree')
    if not kernel.is_file() or not kernel.with_name('mach_kernel.sys').is_file():
        parser.error('Wait for the kernel link to finish before packaging')
    output.mkdir(parents=True)
    helpers = loader/'scripts/i9100'
    raw = output/'Image.raw'
    run([sys.executable, helpers/'mkraw.py', kernel, raw], loader, output/'mkraw.log')
    import lz4.block
    raw_data = raw.read_bytes()
    blob = output/'Image.lz4'
    blob.write_bytes(lz4.block.compress(raw_data, store_size=False))
    assert lz4.block.decompress(blob.read_bytes(), uncompressed_size=len(raw_data)) == raw_data
    run(['gcc','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',
        helpers/'test-lz4.c','-o',output/'test-lz4'], loader, output/'test-lz4-build.log')
    run([output/'test-lz4', blob, raw], loader, output/'test-lz4.log')
    build = output/'loader'
    run([sys.executable, helpers/'relink-loader.py', '--output', build,
        '--kernel-blob', blob, 'arch/arm/start.S', 'arch/arm/load-kernel.c',
        'arch/arm/lz4dec.c', 'board/samsung/board-i9100.c',
        'drivers/samsung/dwc2cdc4210.c', 'main/main.c'], loader, output/'loader-build.log')
    shutil.copyfile(build/'zImage', output/'zImage')
    shutil.copyfile(kernel, output/'mach_kernel')
    shutil.copyfile(kernel.with_name('mach_kernel.sys'), output/'mach_kernel.sys')
    data = (output/'zImage').read_bytes()
    assert struct.unpack_from('<I', data, 0x24)[0] == 0x016f2818
    assert struct.unpack_from('<I', data, 0x28)[0] == 0x40008000
    assert struct.unpack_from('<I', data, 0x2c)[0] == 0x40008000 + len(data)
    assert len(data) < 8*1024*1024
    assert b'ios7lab_vmabi=0' in data
    assert 'S2I9100-OS6'.encode('utf-16le') in data
    symbols = subprocess.check_output(['arm-none-eabi-nm','-n',str(build/'uniLoader.o')],text=True)
    (output/'loader-symbols.txt').write_text(symbols)
    sym = {row.split()[2]: int(row.split()[0],16) for row in symbols.splitlines()
        if len(row.split()) == 3 and row.split()[0][0] in '0123456789abcdef'}
    packed_blob = data[sym['_kernel_start']-0x48000000:sym['_kernel_end']-0x48000000]
    assert packed_blob == blob.read_bytes()
    assert lz4.block.decompress(packed_blob, uncompressed_size=len(raw_data)) == raw_data
    raw_end = 0x40001000 + len(raw_data)
    dt_pa = raw_end + 0x1000000
    assert dt_pa + (loader/'blob/dtb').stat().st_size + 2112 < 0x43e00000
    assert raw_end < sym['__payload_start']
    spec = importlib.util.spec_from_file_location('identity', loader/'scripts/build-i9100.py')
    identity_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity_module)
    identity = identity_module.kernel_identity(output/'mach_kernel')
    assert identity == identity_module.kernel_identity(output/'mach_kernel.sys')
    archive = output/'i9100-ios6-kernel.tar'
    with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as tf:
        tf.add(output/'zImage',arcname='zImage')
    with tarfile.open(archive,'r') as tf:
        assert [m.name for m in tf.getmembers()] == ['zImage']
        assert tf.extractfile('zImage').read() == data
    names = ['zImage','i9100-ios6-kernel.tar','mach_kernel','mach_kernel.sys','Image.raw','Image.lz4']
    manifest = {
        'created': datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(),
        'purpose': 'GT-I9100 KERNEL partition; iOS6 offline candidate, hardware unverified',
        'loader': identity_module.git_head(loader),
        'xnu': identity_module.git_head(loader.parent/'xnu'),
        'kernel': identity,
        'usb_serial': 'S2I9100-OS6',
        'memory': {'load_pa':hex(0x40001000),'raw_end':hex(raw_end),
            'device_tree_pa':hex(dt_pa),'payload_staging_pa':hex(sym['__payload_start'])},
        'checks': ['zImage header/end/8MiB limit','exact embedded LZ4 block',
            'Python and production C decoder match raw Mach-O','ASan/UBSan malformed blocks',
            'iOS6 bootarg and distinct USB serial','tar contains exactly zImage'],
        'artifacts': {name:{'bytes':(output/name).stat().st_size,'sha256':sha(output/name)} for name in names}}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'result':'PASS package checks','output':str(output),
        'zImage_bytes':len(data),'tar_sha256':sha(archive),'kernel':identity},indent=2))


if __name__ == '__main__':
    main()
