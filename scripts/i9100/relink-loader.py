#!/usr/bin/env python3
"""Incrementally relink a configured loader without deleting build artifacts."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys


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
    parser.add_argument('sources', nargs='*')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(repo / 'out'):
        parser.error('Output must be inside the loader out directory')
    output.mkdir(parents=True, exist_ok=True)
    replacements = {}
    for source_name in args.sources:
        source = Path(source_name)
        if source.is_absolute() or '..' in source.parts or source.suffix not in ('.c', '.S'):
            parser.error('Use a repository-relative C or assembly source')
        original = source.with_suffix('.o')
        cmdfile = repo / original.parent / ('.' + original.name + '.cmd')
        command = shlex.split(cmdfile.read_text().splitlines()[0].split(':=', 1)[1])
        command = [arg for arg in command if not arg.startswith('-Wp,-MD,')]
        new_object = output / original
        new_object.parent.mkdir(parents=True, exist_ok=True)
        command[command.index('-o') + 1] = str(new_object)
        run(command, repo)
        replacements[str(original)] = new_object

    # Preserve the archive member list, replacing only newly built members.
    archives = []
    for group in ('drivers', 'lib', 'board', 'soc'):
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
