#!/usr/bin/env python3
"""Name retained first-media frames without reopening a dead process.

Shared-cache addresses use the slide saved with this exact task. Other
addresses remain live addresses until that task's own image map is available.
Saved r12 is not an active syscall number unless the original PC proves it.
"""
import os
import sys

if os.environ.get('I9100_CPU_CAPPED') != '1':
    os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice',
                         '-c2', '-n7', sys.executable, '-B', __file__, *sys.argv[1:]],
               dict(os.environ, I9100_CPU_CAPPED='1'))

import argparse
import importlib.util
import json
import mmap
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ROOT = REPO.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observations', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.observations.resolve(), args.output.resolve()
    if not source.is_relative_to(REPO / 'out') or not output.is_relative_to(ROOT / 'research'):
        parser.error('Read loader out observations and write research only')
    evidence = json.loads(source.read_text())
    observations = evidence.get('observations', evidence)
    peers = observations['media_first_threads']
    if (peers['published'] != 1 or peers['version'] not in (1, 2) or
            not 0 <= peers['count'] <= 16 or len(peers['rows']) != peers['count']):
        raise ValueError('Unknown first-media snapshot schema')
    spec = importlib.util.spec_from_file_location('peer_cache', HERE / 'symbolize-ios6-stacks.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    slide = peers['slide']
    lines = [f'Source: {source}', f'BUILD: {evidence.get("tag", "unspecified")}',
             f'First media PID={peers["pid"]} task={peers["task"]:08x} slide={slide:08x}',
             f'Peers={peers["count"]} capture_error={peers["error"]} callback_stage={peers["callback_stage"]}',
             'Retained peer registers with sequential own-task user reads; not an atomic user-memory snapshot.',
             '<redacted> identifies the image, not a proven private function.']
    with (ROOT / 'assets/ios6-extract/dyld_cache6_armv7').open('rb') as file:
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            cache = module.Cache(data)
            for row in peers['rows']:
                lines.append(f'THREAD tid={row["tid_high"]:08x}:{row["tid_low"]:08x} '
                             f'thread={row["thread"]:08x} state={row["state"]:x} error={row["error"]}')
                if row['error']:
                    continue
                lines.append('REGS ' + ' '.join(f'r{n}={value:08x}' for n, value in enumerate(row['registers'])))
                if peers['version'] == 2:
                    lines.append(f'PC_BYTES error={row["instruction_error"]} original={row["instruction_hex"]}')
                for label, value in [('PC', row['pc']), ('LR', row['lr'])] + [
                        (f'FRAME{n}', frame['lr']) for n, frame in enumerate(row['frame_rows'])]:
                    live = value & ~1
                    try:
                        description = cache.describe(live - slide) if live >= 0x30000000 else 'outside shared cache; own-task image map required'
                    except ValueError as error:
                        description = 'unresolved: ' + str(error)
                    lines.append(f'{label} live={value:08x} {description}')
                lines.append('HANDLER6 ' + ' '.join(f'{value:08x}' for value in row['handler_args']) +
                             f' observed={row["handler_args_observed"]}')
    with output.open('x', encoding='utf-8') as file:
        file.write('\n'.join(lines) + '\n')
    print('\n'.join(lines), flush=True)


if __name__ == '__main__':
    main()
