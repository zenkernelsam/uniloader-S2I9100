#!/usr/bin/env python3
"""Sequential, CPU-capped rebuild + control-enabled package (no device access)."""
import os
from pathlib import Path
import subprocess
import sys
import argparse
from datetime import datetime

if os.environ.get('I9100_CPU_CAPPED') != '1':
    os.execvpe('taskset', ['taskset', '-c', '0-13', 'nice', '-n10', 'ionice', '-c2', '-n7',
                         sys.executable, __file__, *sys.argv[1:]], dict(os.environ, I9100_CPU_CAPPED='1'))
repo = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ls-bootstrap', action='store_true')
parser.add_argument('--xpc-diag', action='store_true')
parser.add_argument('--reboot-download-fallback', action='store_true')
parser.add_argument('--tcc-development', action='store_true')
parser.add_argument('--mdns-development', action='store_true')
parser.add_argument('--panic-recovery', action='store_true')
parser.add_argument('--panic-test', action='store_true')
args = parser.parse_args()
xnu = repo.parent / 'xnu'
label = 'control-' + datetime.now().strftime('%Y%m%d-%H%M%S')
kernel = xnu / 'out/automation' / label
package = repo / 'out/automation' / label
objects = ['pexpert/i9100_usbcdc.o', 'pexpert/i9100_timer.o', 'pexpert/pe_exynos4210_i9100.o',
           'osfmk/locore.o', 'osfmk/hw_lock.o', 'osfmk/debug.o', 'osfmk/ipc_kobject.o', 'osfmk/mach_msg.o', 'osfmk/mach_port.o', 'security/mac_base.o',
           'osfmk/ipc_right.o', 'osfmk/ipc_kmsg.o', 'osfmk/trap.o', 'bsd/kern_exec.o',
           'bsd/unix_syscalls.o', 'bsd/pthread_synch.o', 'bsd/kern_sig.o', 'bsd/sys_generic.o', 'bsd/param.o', 'bsd/vfs_subr.o', 'bsd/kdebug.o', 'bsd/decmpfs.o', 'iokit/IOKitBSDInit.cpo',
           'iokit/IOPMrootDomain.cpo', 'iokit/IOS7LeoDisplay.cpo', 'iokit/IOUserClient.cpo',
           'iokit/IOS7LeoHIDTouch.cpo',
           'iokit/i9100_power.o', 'iokit/i9100_power_bus.o', 'iokit/IOS7I9100Power.cpo',
           'osfmk/vm_map.o', 'bsd/kern_exit.o', 'osfmk/pmap.o']
subprocess.run([sys.executable, xnu / 'tools/rebuild-i9100.py', '--output', kernel, '--link', *objects], check=True)
subprocess.run(['bash', repo / 'scripts/i9100/build-rawcom.sh'], check=True)
subprocess.run([sys.executable, repo / 'scripts/i9100/package-oneshot.py', '--kernel', kernel / 'mach_kernel',
                '--output', package, '--control',
                *(['--ls-bootstrap'] if args.ls_bootstrap else []),
                *(['--xpc-diag'] if args.xpc_diag else []),
                *(['--reboot-download-fallback'] if args.reboot_download_fallback else []),
                *(['--tcc-development'] if args.tcc_development else []),
                *(['--mdns-development'] if args.mdns_development else []),
                *(['--panic-recovery'] if args.panic_recovery else []),
                *(['--panic-test'] if args.panic_test else [])], check=True)
print('OFFLINE READY:', package, flush=True)
