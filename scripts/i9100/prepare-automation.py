#!/usr/bin/env python3
"""Sequential, CPU-capped rebuild + control-enabled package (no device access)."""
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime

if os.environ.get('I9100_CPU_CAPPED') != '1':
    os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice', '-c2', '-n7',
                         sys.executable, __file__, *sys.argv[1:]], dict(os.environ, I9100_CPU_CAPPED='1'))
repo = Path(__file__).resolve().parents[2]
xnu = repo.parent / 'xnu'
label = 'control-' + datetime.now().strftime('%Y%m%d-%H%M%S')
kernel = xnu / 'out/automation' / label
package = repo / 'out/automation' / label
objects = ['pexpert/i9100_usbcdc.o', 'pexpert/i9100_timer.o', 'pexpert/pe_exynos4210_i9100.o',
           'osfmk/locore.o', 'osfmk/hw_lock.o', 'osfmk/ipc_kobject.o', 'osfmk/trap.o', 'bsd/kern_exec.o',
           'bsd/unix_syscalls.o', 'bsd/vfs_subr.o', 'bsd/kdebug.o', 'bsd/decmpfs.o', 'iokit/IOKitBSDInit.cpo',
           'iokit/IOPMrootDomain.cpo']
subprocess.run([sys.executable, xnu / 'tools/rebuild-i9100.py', '--output', kernel, '--link', *objects], check=True)
subprocess.run(['bash', repo / 'scripts/i9100/build-rawcom.sh'], check=True)
subprocess.run([sys.executable, repo / 'scripts/i9100/package-oneshot.py', '--kernel', kernel / 'mach_kernel',
                '--output', package, '--control'], check=True)
print('OFFLINE READY:', package, flush=True)
