#!/usr/bin/env python3
"""Incrementally relink a configured loader without deleting build artifacts."""
import argparse
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
    parser.add_argument('--control', action='store_true')
    parser.add_argument('--control-tag')
    parser.add_argument('--ls-bootstrap', action='store_true')
    parser.add_argument('--xpc-diag', action='store_true')
    parser.add_argument('--reboot-download-fallback', action='store_true')
    parser.add_argument('sources', nargs='*')
    args = parser.parse_args()
    if args.control and (not args.control_tag or len(args.control_tag) != 16 or
            any(c not in '0123456789abcdef' for c in args.control_tag)):
        parser.error('--control needs a 16 lowercase hex --control-tag')
    if args.ls_bootstrap and not args.control:
        parser.error('--ls-bootstrap requires --control')
    if args.xpc_diag and not args.control:
        parser.error('--xpc-diag requires --control')
    if args.reboot_download_fallback and not args.control:
        parser.error('--reboot-download-fallback requires --control')
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
            command.append('-DI9100_CONTROL_BUILD=1')
            command.append('-DI9100_CONTROL_TAG="' + args.control_tag + '"')
            if args.ls_bootstrap:
                command.append('-DI9100_LS_BOOTSTRAP_BUILD=1')
            if args.xpc_diag:
                command.append('-DI9100_XPC_DIAG_BUILD=1')
            if args.reboot_download_fallback:
                command.append('-DI9100_REBOOT_DOWNLOAD_BUILD=1')
        if source_name == 'arch/arm/start.S' and args.kernel_blob:
            command.append('-DI9100_KERNEL_BLOB="' + str(blob) + '"')
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
