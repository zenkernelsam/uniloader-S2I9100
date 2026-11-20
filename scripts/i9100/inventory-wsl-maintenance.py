#!/usr/bin/env python3
"""Read-only bounded inventory of project-related WSL paths for maintenance."""
import json
import os
import subprocess
from pathlib import Path


def size(path):
    try:
        raw = subprocess.check_output(
            ['du', '-sx', '--block-size=1', '--', str(path)],
            text=True, stderr=subprocess.DEVNULL, timeout=45,
        )
        return int(raw.split()[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def inventory():
    rows = []
    for base in ('/root', '/tmp', '/home', '/opt'):
        for path in sorted(Path(base).iterdir()):
            # Do not follow the project bind mount or other mounted drives.
            symbolic = path.is_symlink()
            resolved = os.path.realpath(path)
            mounted = os.path.ismount(path) or resolved.startswith('/mnt/')
            rows.append({
                'path': str(path), 'resolved': resolved, 'symlink': symbolic,
                'mounted_or_drive_path': mounted,
                'allocated_bytes': None if symbolic or mounted else size(path),
                'kind': 'directory' if path.is_dir() else 'file',
            })
    processes = subprocess.check_output(
        ['ps', '-eo', 'pid,comm,args'], text=True,
    )
    # Read-only process inventory; no signals are sent.
    relevant = [line[:500] for line in processes.splitlines()
                if any(word in line.lower() for word in
                       ('i9100', 'qemu-system-arm', 'clang', 'make -', 'rawcom'))]
    return {'schema': 1, 'readonly': True, 'paths': rows,
            'project_processes': relevant}


if __name__ == '__main__':
    print(json.dumps(inventory(), indent=2))
