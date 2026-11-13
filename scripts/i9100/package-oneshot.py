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
    parser.add_argument('--control', action='store_true', help='Enable serial maintenance resets')
    parser.add_argument('--ls-bootstrap', action='store_true', help='Bound the observed iOS6 LS/MI initialization cycle')
    parser.add_argument('--ls-ui-timeout',action='store_true',help='Development 5s receive timeout for the witnessed AppStore query')
    parser.add_argument('--audio-property-lock',action='store_true',help='Private mediaserverd correction for the witnessed property callback lock inversion')
    parser.add_argument('--xpc-diag', action='store_true', help='Retain XPC boundary metadata in kernel RAM')
    parser.add_argument('--reboot-download-fallback', action='store_true',
                        help='Recover normal iOS reboot requests into Download after filesystem shutdown')
    parser.add_argument('--tcc-development', action='store_true',
                        help='Explicit unconfined tccd initialization when no Sandbox policy exists')
    parser.add_argument('--mdns-development', action='store_true',
                        help='Explicit unconfined MDNS initialization when no Sandbox policy exists')
    parser.add_argument('--panic-recovery', action='store_true',
                        help='Retain panic log over USB then reset to Download after 180 seconds')
    parser.add_argument('--panic-test', action='store_true',
                        help='Explicit qualification-only controlled panic command')
    parser.add_argument('--home-test', action='store_true',help='One diagnostic Menu press/release after HID open')
    parser.add_argument('--ios6-hid', action='store_true',help='Use the verified iOS6 serialized input ABI')
    parser.add_argument('--input-test', action='store_true',help='Explicit bounded serial input tests; idle until requested')
    parser.add_argument('--aks-development', action='store_true',help='Explicit S2 no-passcode state; no secure keys')
    parser.add_argument('--control-bootargs-only', action='store_true',
                        help='Diagnostic: control loader bootargs with a baseline kernel; no command capability claim')
    args = parser.parse_args()
    if args.audio_property_lock and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--audio-property-lock requires --control, --xpc-diag and --ios6-hid')
    if args.ls_ui_timeout and (not args.control or not args.xpc_diag):
        parser.error('--ls-ui-timeout requires --control and --xpc-diag')
    if args.ls_bootstrap and not args.control:
        parser.error('--ls-bootstrap requires --control')
    if args.xpc_diag and not args.control:
        parser.error('--xpc-diag requires --control')
    if args.reboot_download_fallback and not args.control:
        parser.error('--reboot-download-fallback requires --control')
    if args.tcc_development and not args.control:
        parser.error('--tcc-development requires --control')
    if args.mdns_development and not args.control:
        parser.error('--mdns-development requires --control')
    if args.panic_recovery and not args.control:
        parser.error('--panic-recovery requires --control')
    if args.panic_test and not args.panic_recovery:
        parser.error('--panic-test requires --panic-recovery')
    if args.home_test and (not args.control or not args.xpc_diag):
        parser.error('--home-test requires --control and --xpc-diag')
    if args.ios6_hid and not args.control:
        parser.error('--ios6-hid requires --control')
    if args.input_test and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--input-test requires --control, --xpc-diag and --ios6-hid')
    if args.input_test and args.home_test:
        parser.error('Use requested input tests or the automatic Home test, not both')
    if args.aks_development and not args.control:
        parser.error('--aks-development requires --control')
    if args.control_bootargs_only and not args.control:
        parser.error('--control-bootargs-only requires --control')
    output = args.output.resolve()
    kernel = args.kernel.resolve()
    if not output.is_relative_to(loader/'out') or output.exists():
        parser.error('Use a new output directory inside loader out')
    if not kernel.is_relative_to(loader.parent/'xnu-S2I9100'):
        parser.error('Kernel must come from the matching XNU repository')
    if not kernel.is_file() or not kernel.with_name('mach_kernel.sys').is_file():
        parser.error('Wait for the kernel link to finish before packaging')
    output.mkdir(parents=True)
    helpers = loader/'scripts/i9100'
    dt_spec=importlib.util.spec_from_file_location('i9100_dt',helpers/'prepare-payloads.py')
    dt_module=importlib.util.module_from_spec(dt_spec);dt_spec.loader.exec_module(dt_module)
    dt_blob=output/'dtb'
    dt_blob.write_bytes(dt_module.device_tree())
    raw = output/'Image.raw'
    run([sys.executable, helpers/'mkraw.py', kernel, raw], loader, output/'mkraw.log')
    import lz4.block
    raw_data = raw.read_bytes()
    if args.audio_property_lock and b'i9100audiolock\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit audio property lock capability')
    if args.reboot_download_fallback and b'i9100rebootdownload\0' not in raw_data:
        raise RuntimeError('Kernel lacks the i9100 PE reboot recovery capability')
    if args.tcc_development and b'i9100tccdev\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit tccd development capability')
    if args.mdns_development and b'i9100mdnsdev\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit MDNS development capability')
    if args.panic_recovery and b'i9100panicrecovery\0' not in raw_data:
        raise RuntimeError('Kernel lacks the panic-to-Download capability')
    if args.home_test and b'i9100hometest\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit Home test capability')
    if args.ios6_hid and b'i9100hidabi\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit iOS6 HID wire capability')
    if args.input_test and b'i9100inputtest\0' not in raw_data:
        raise RuntimeError('Kernel lacks the bounded input test mailbox')
    if args.ls_ui_timeout and b'i9100lsuitimeout\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit UI receive deadline')
    if args.aks_development and b'i9100aksdev\0' not in raw_data:
        raise RuntimeError('Kernel lacks the explicit AKS development state')
    blob = output/'Image.lz4'
    blob.write_bytes(lz4.block.compress(raw_data, store_size=False))
    assert lz4.block.decompress(blob.read_bytes(), uncompressed_size=len(raw_data)) == raw_data
    run(['gcc','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',
        helpers/'test-lz4.c','-o',output/'test-lz4'], loader, output/'test-lz4-build.log')
    run([output/'test-lz4', blob, raw], loader, output/'test-lz4.log')
    build = output/'loader'
    run([sys.executable, helpers/'relink-loader.py', '--output', build,
        *(['--control', '--control-tag', sha(kernel)[:16]] if args.control else []),
        *(['--ls-bootstrap'] if args.ls_bootstrap else []),
        *(['--ls-ui-timeout'] if args.ls_ui_timeout else []),
        *(['--audio-property-lock'] if args.audio_property_lock else []),
        *(['--xpc-diag'] if args.xpc_diag else []),
        *(['--reboot-download-fallback'] if args.reboot_download_fallback else []),
        *(['--tcc-development'] if args.tcc_development else []),
        *(['--mdns-development'] if args.mdns_development else []),
        *(['--panic-recovery'] if args.panic_recovery else []),
        *(['--panic-test'] if args.panic_test else []),
        *(['--home-test'] if args.home_test else []),
        *(['--ios6-hid'] if args.ios6_hid else []),
        *(['--input-test'] if args.input_test else []),
        *(['--aks-development'] if args.aks_development else []),
        '--kernel-blob', blob, '--dtb-blob', dt_blob, 'arch/arm/start.S', 'arch/arm/load-kernel.c',
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
    assert dt_blob.read_bytes() in data
    assert b'ios7lab_vmabi=0' in data
    if args.control:
        assert b'i9100control=1' in data
    if args.ls_bootstrap:
        assert b'i9100lsbootstrap=1' in data
    if args.xpc_diag:
        assert b'i9100xpcdiag=1' in data
    if args.reboot_download_fallback:
        assert b'i9100rebootdownload=1' in data
    if args.tcc_development:
        assert b'i9100tccdev=1' in data
    if args.mdns_development:
        assert b'i9100mdnsdev=1' in data
    if args.panic_recovery:
        assert b'i9100panicrecovery=1' in data
    if args.panic_test:
        assert b'i9100panictest=1' in data
    if args.home_test:
        assert b'i9100hometest=1' in data
    assert (b'i9100hidabi=6' in data) == args.ios6_hid
    assert (b'i9100inputtest=1' in data) == args.input_test
    assert (b'i9100aksdev=1' in data) == args.aks_development
    assert (b'i9100lsuitimeout=1' in data) == args.ls_ui_timeout
    assert (b'i9100audiolock=1' in data) == args.audio_property_lock
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
        'xnu': identity_module.git_head(loader.parent/'xnu-S2I9100'),
        'kernel': identity,
        'usb_serial': 'S2I9100-OS6',
        'serial_control': args.control and not args.control_bootargs_only,
        'ls_bootstrap': args.ls_bootstrap,
        'ls_ui_timeout_ms': 5000 if args.ls_ui_timeout else 0,
        'audio_property_lock': args.audio_property_lock,
        'xpc_diag': args.xpc_diag,
        'reboot_download_fallback': args.reboot_download_fallback,
        'tcc_development_unconfined': args.tcc_development,
        'mdns_development_unconfined': args.mdns_development,
        'panic_recovery_seconds': 180 if args.panic_recovery else None,
        'panic_test_command': args.panic_test,
        'home_test_command': args.home_test,
        'hid_wire_abi': 6 if args.ios6_hid else 7,
        'input_test_commands': args.input_test,
        'aks_development_state_only': args.aks_development,
        'root_status_protocol': b'OK root=NO_ROOT' in raw_data,
        'diagnostic_control_bootargs_only': args.control_bootargs_only,
        'control_tag': sha(kernel)[:16] if args.control else None,
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
