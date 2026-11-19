#!/usr/bin/env python3
"""Incrementally relink a configured loader without deleting build artifacts."""
import argparse
import re
import os
from pathlib import Path
import shlex
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo


def run(arguments, cwd):
    print('+', shlex.join(map(str, arguments)), flush=True)
    subprocess.run(list(map(str, arguments)), cwd=cwd, check=True)


def main():
    if os.environ.get('I9100_CPU_CAPPED') != '1':
        env = dict(os.environ, I9100_CPU_CAPPED='1')
        os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10',
            'ionice', '-c2', '-n7', sys.executable, __file__, *sys.argv[1:]], env)
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kernel-blob', type=Path)
    parser.add_argument('--dtb-blob', type=Path)
    parser.add_argument('--control', action='store_true')
    parser.add_argument('--control-tag')
    parser.add_argument('--charger-tag')
    parser.add_argument('--ls-bootstrap', action='store_true')
    parser.add_argument('--ls-ui-timeout',action='store_true')
    parser.add_argument('--audio-property-lock',action='store_true')
    parser.add_argument('--launchd-listener-guard',action='store_true')
    parser.add_argument('--quiet-charge-feedback',action='store_true')
    parser.add_argument('--hid-execution-trace',action='store_true')
    parser.add_argument('--hid-fixed-cadence',action='store_true')
    parser.add_argument('--slab-publication-trace',action='store_true')
    parser.add_argument('--ui-execution-trace',action='store_true')
    parser.add_argument('--ui-retina-assets',action='store_true')
    parser.add_argument('--ui-keep-awake',action='store_true')
    parser.add_argument('--setup-native-layout',action='store_true')
    parser.add_argument('--setup-background-fit',action='store_true')
    parser.add_argument('--ui-density',type=int,choices=(1333,1500))
    parser.add_argument('--ui-density-metrics',action='store_true')
    parser.add_argument('--ui-canvas',type=int,choices=(360,))
    parser.add_argument('--system-sounds-unavailable',action='store_true')
    parser.add_argument('--xpc-diag', action='store_true')
    parser.add_argument('--charge-diag', action='store_true')
    parser.add_argument('--charge-probe', action='store_true')
    parser.add_argument('--standalone-charge', action='store_true')
    parser.add_argument('--reboot-download-fallback', action='store_true')
    parser.add_argument('--tcc-development', action='store_true')
    parser.add_argument('--mdns-development', action='store_true')
    parser.add_argument('--panic-recovery', action='store_true')
    parser.add_argument('--panic-test', action='store_true')
    parser.add_argument('--home-test', action='store_true')
    parser.add_argument('--ios6-hid', action='store_true')
    parser.add_argument('--input-test', action='store_true')
    parser.add_argument('--aks-development', action='store_true')
    parser.add_argument('--setup-dev-finish',action='store_true')
    parser.add_argument('sources', nargs='*')
    args = parser.parse_args()
    if args.audio_property_lock and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--audio-property-lock requires --control, --xpc-diag and --ios6-hid')
    if args.launchd_listener_guard and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--launchd-listener-guard requires --control, --xpc-diag and --ios6-hid')
    if args.quiet_charge_feedback and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--quiet-charge-feedback requires --control, --xpc-diag and --ios6-hid')
    if args.hid_execution_trace and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--hid-execution-trace requires --control, --xpc-diag and --ios6-hid')
    if args.hid_fixed_cadence and not args.hid_execution_trace:
        parser.error('--hid-fixed-cadence requires --hid-execution-trace')
    if args.slab_publication_trace and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--slab-publication-trace requires --control, --xpc-diag and --ios6-hid')
    if args.ui_execution_trace and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--ui-execution-trace requires --control, --xpc-diag and --ios6-hid')
    if args.ui_retina_assets and not args.ui_execution_trace:
        parser.error('--ui-retina-assets requires --ui-execution-trace')
    if args.ui_keep_awake and not args.ui_retina_assets:
        parser.error('--ui-keep-awake requires --ui-retina-assets')
    if args.setup_native_layout and not args.ui_retina_assets:
        parser.error('--setup-native-layout requires the verified --ui-retina-assets baseline')
    if args.setup_background_fit and not args.setup_native_layout:
        parser.error('--setup-background-fit requires --setup-native-layout')
    if args.ui_density and not args.setup_native_layout:
        parser.error('--ui-density requires --setup-native-layout')
    if args.ui_density_metrics and not args.ui_density:
        parser.error('--ui-density-metrics requires --ui-density')
    if args.ui_canvas and (not args.setup_native_layout or args.ui_density):
        parser.error('--ui-canvas requires native layout and the original integer display scale')
    if args.system_sounds_unavailable and (not args.control or not args.xpc_diag or not args.ios6_hid):
        parser.error('--system-sounds-unavailable requires --control, --xpc-diag and --ios6-hid')
    if args.ls_ui_timeout and (not args.control or not args.xpc_diag):
        parser.error('--ls-ui-timeout requires --control and --xpc-diag')
    if args.control and (not args.control_tag or len(args.control_tag) != 16 or
            any(c not in '0123456789abcdef' for c in args.control_tag)):
        parser.error('--control needs a 16 lowercase hex --control-tag')
    if args.ls_bootstrap and not args.control:
        parser.error('--ls-bootstrap requires --control')
    if args.xpc_diag and not args.control:
        parser.error('--xpc-diag requires --control')
    if args.charge_diag and not args.control:
        parser.error('--charge-diag requires --control')
    if args.charge_probe and not args.charge_diag:
        parser.error('--charge-probe requires --charge-diag')
    if args.standalone_charge and not args.control:
        parser.error('--standalone-charge requires --control')
    if args.standalone_charge and not re.fullmatch('[0-9a-f]{16}',args.charger_tag or ''):
        parser.error('--standalone-charge requires its source-qualified --charger-tag')
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
    if args.setup_dev_finish and (not args.control or not args.aks_development or not args.ios6_hid):
        parser.error('--setup-dev-finish requires control, iOS6 and the explicit AKS development state')
    output = args.output.resolve()
    if not output.is_relative_to(repo / 'out'):
        parser.error('Output must be inside the loader out directory')
    output.mkdir(parents=True, exist_ok=True)
    if args.kernel_blob:
        blob = args.kernel_blob.resolve()
        if not blob.is_relative_to(repo / 'out') or not blob.is_file():
            parser.error('Kernel blob must be a file inside loader out')
        if 'arch/arm/start.S' not in args.sources:
            parser.error('A new blob requires recompiling arch/arm/start.S')
    if args.dtb_blob:
        dt_blob=args.dtb_blob.resolve()
        if not dt_blob.is_relative_to(repo/'out') or not dt_blob.is_file():
            parser.error('DT blob must be a file inside loader out')
        if 'arch/arm/start.S' not in args.sources:
            parser.error('A new DT requires recompiling arch/arm/start.S')
    replacements = {}
    head = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=repo, text=True).strip()
    label = f'({head}) - date ' + datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    for source_name in args.sources:
        source = Path(source_name)
        if source.is_absolute() or '..' in source.parts or source.suffix not in ('.c', '.S'):
            parser.error('Use a repository-relative C or assembly source')
        original = source.with_suffix('.o')
        cmdfile = repo / original.parent / ('.' + original.name + '.cmd')
        command = shlex.split(cmdfile.read_text().splitlines()[0].split(':=', 1)[1])
        command = [arg for arg in command if not arg.startswith('-Wp,-MD,')]
        command = [arg for arg in command if not arg.startswith('-DVER_TAG=')]
        if source.suffix == '.c':
            command.append('-DVER_TAG="' + label + '"')
        if args.control and source_name == 'arch/arm/load-kernel.c':
            if args.aks_development:
                command.append('-DI9100_AKS_DEVELOPMENT_BUILD=1')
            if args.setup_dev_finish:
                command.append('-DI9100_SETUP_DEV_FINISH_BUILD=1')
            if args.input_test:
                command.append('-DI9100_INPUT_TEST_BUILD=1')
            if args.ios6_hid:
                command.append('-DI9100_IOS6_HID_BUILD=1')
            if args.home_test:
                command.append('-DI9100_HOME_TEST_BUILD=1')
            command.append('-DI9100_CONTROL_BUILD=1')
            command.append('-DI9100_CONTROL_TAG="' + args.control_tag + '"')
            if args.ls_bootstrap:
                command.append('-DI9100_LS_BOOTSTRAP_BUILD=1')
            if args.ls_ui_timeout:
                command.append('-DI9100_LS_UI_TIMEOUT_BUILD=1')
            if args.audio_property_lock:
                command.append('-DI9100_AUDIO_PROPERTY_LOCK_BUILD=1')
            if args.launchd_listener_guard:
                command.append('-DI9100_LAUNCHD_LISTENER_GUARD_BUILD=1')
            if args.quiet_charge_feedback:
                command.append('-DI9100_QUIET_CHARGE_BUILD=1')
            if args.hid_execution_trace:
                command.append('-DI9100_HID_EXECUTION_TRACE_BUILD=1')
            if args.hid_fixed_cadence:
                command.append('-DI9100_HID_FIXED_CADENCE_BUILD=1')
            if args.slab_publication_trace:
                command.append('-DI9100_SLAB_PUBLICATION_TRACE_BUILD=1')
            if args.ui_execution_trace:
                command.append('-DI9100_UI_EXECUTION_TRACE_BUILD=1')
            if args.ui_retina_assets:
                command.append('-DI9100_UI_RETINA_ASSETS_BUILD=1')
            if args.ui_keep_awake:
                command.append('-DI9100_UI_KEEP_AWAKE_BUILD=1')
            if args.setup_native_layout:
                command.append('-DI9100_SETUP_NATIVE_LAYOUT_BUILD=1')
            if args.setup_background_fit:
                command.append('-DI9100_SETUP_BACKGROUND_FIT_BUILD=1')
            if args.ui_density:
                command.append('-DI9100_UI_DENSITY_BUILD='+str(args.ui_density))
            if args.ui_density_metrics:
                command.append('-DI9100_UI_DENSITY_METRICS_BUILD=1')
            if args.ui_canvas:
                command.append('-DI9100_UI_CANVAS_BUILD='+str(args.ui_canvas))
            if args.system_sounds_unavailable:
                command.append('-DI9100_SYSTEM_SOUNDS_UNAVAILABLE_BUILD=1')
            if args.xpc_diag:
                command.append('-DI9100_XPC_DIAG_BUILD=1')
            if args.charge_diag:
                command.append('-DI9100_CHARGE_DIAG_BUILD=1')
            if args.charge_probe:
                command.append('-DI9100_CHARGE_PROBE_BUILD=1')
            if args.standalone_charge:
                command.append('-DI9100_STANDALONE_CHARGE_BUILD=1')
            if args.reboot_download_fallback:
                command.append('-DI9100_REBOOT_DOWNLOAD_BUILD=1')
            if args.tcc_development:
                command.append('-DI9100_TCC_DEVELOPMENT_BUILD=1')
            if args.mdns_development:
                command.append('-DI9100_MDNS_DEVELOPMENT_BUILD=1')
            if args.panic_recovery:
                command.append('-DI9100_PANIC_RECOVERY_BUILD=1')
            if args.panic_test:
                command.append('-DI9100_PANIC_TEST_BUILD=1')
        if source_name == 'board/samsung/board-i9100.c' and args.standalone_charge:
            command.append('-DI9100_STANDALONE_CHARGE_BUILD=1')
        if source_name == 'drivers/samsung/dwc2cdc4210.c' and args.control and args.standalone_charge:
            command.append('-DI9100_CONTROL_TAG="'+args.control_tag+'"')
            command.append('-DI9100_CHARGER_TAG="'+args.charger_tag+'"')
        if source_name == 'arch/arm/start.S' and args.kernel_blob:
            command.append('-DI9100_KERNEL_BLOB="' + str(blob) + '"')
        if source_name == 'arch/arm/start.S' and args.dtb_blob:
            command.append('-DI9100_DTB_BLOB="' + str(dt_blob) + '"')
        new_object = output / original
        new_object.parent.mkdir(parents=True, exist_ok=True)
        command[command.index('-o') + 1] = str(new_object)
        run(command, repo)
        replacements[str(original)] = new_object

    # Preserve the archive member list, replacing only newly built members.
    archives = []
    for group in ('soc', 'board', 'drivers', 'lib'):
        original = repo / group / 'lib.a'
        members = subprocess.check_output(['arm-none-eabi-ar', 't', original], text=True).splitlines()
        objects = []
        for member in members:
            matches = list((repo / group).rglob(member))
            if len(matches) != 1:
                raise ValueError(f'Archive member {group}/{member} is ambiguous: {matches}')
            rel = str(matches[0].relative_to(repo))
            objects.append(replacements.get(rel, matches[0]))
        archive = output / (group + '.a')
        if archive.exists():
            raise ValueError('Use a fresh output directory; archives must not retain stale members')
        run(['arm-none-eabi-ar', 'rcs', archive, *objects], repo)
        archives.append(archive)
    arch = ['arch/arm/start.o', 'arch/arm/load-kernel.o', 'arch/arm/memcpy.o', 'arch/arm/lz4dec.o']
    main_objects = ['main/boot.o', 'main/main.o', 'main/boot-fdt.o']
    direct = [replacements.get(name, repo / name) for name in arch + main_objects]
    gcc = 'arm-none-eabi-gcc'
    libgcc = subprocess.check_output([gcc, '-march=armv7-a', '-mfloat-abi=soft',
        '-print-libgcc-file-name'], text=True).strip()
    elf = output / 'uniLoader.o'
    run(['arm-none-eabi-ld', *direct, '--whole-archive', *archives,
        '--no-whole-archive', '--start-group', libgcc, '--end-group',
        '-o', elf, '--script=arch/arm/linker.lds'], repo)
    run(['arm-none-eabi-objcopy', '-O', 'binary', elf, output / 'zImage'], repo)


if __name__ == '__main__':
    main()
