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
parser.add_argument('--ui-density',type=int,choices=(1333,1500),help='Qualify native iOS6 UI density before screen initialization')
parser.add_argument('--ui-density-metrics',action='store_true')
parser.add_argument('--ui-canvas',type=int,choices=(360,))
parser.add_argument('--system-sounds-unavailable',action='store_true')
parser.add_argument('--xpc-diag', action='store_true')
parser.add_argument('--charge-diag', action='store_true')
parser.add_argument('--panel-sleep',action='store_true')
parser.add_argument('--charge-probe', action='store_true')
parser.add_argument('--standalone-charge', action='store_true')
parser.add_argument('--charge-art',type=Path,help='Local iOS6 sprite pack for the standalone charger')
parser.add_argument('--reboot-download-fallback', action='store_true')
parser.add_argument('--tcc-development', action='store_true')
parser.add_argument('--mdns-development', action='store_true')
parser.add_argument('--panic-recovery', action=argparse.BooleanOptionalAction, default=True,
                    help='Retain panic logs and return to Download after 180s')
parser.add_argument('--panic-test', action='store_true')
parser.add_argument('--home-test', action='store_true')
parser.add_argument('--ios6-hid', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--input-test', action='store_true')
parser.add_argument('--aks-development', action='store_true')
parser.add_argument('--setup-dev-finish',action='store_true')
args = parser.parse_args()
if args.ls_ui_timeout and not args.xpc_diag:
    parser.error('--ls-ui-timeout requires --xpc-diag')
if args.audio_property_lock and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--audio-property-lock requires --xpc-diag and --ios6-hid')
if args.launchd_listener_guard and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--launchd-listener-guard requires --xpc-diag and --ios6-hid')
if args.quiet_charge_feedback and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--quiet-charge-feedback requires --xpc-diag and --ios6-hid')
if args.hid_execution_trace and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--hid-execution-trace requires --xpc-diag and --ios6-hid')
if args.hid_fixed_cadence and not args.hid_execution_trace:
    parser.error('--hid-fixed-cadence requires --hid-execution-trace')
if args.slab_publication_trace and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--slab-publication-trace requires --xpc-diag and --ios6-hid')
if args.ui_execution_trace and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--ui-execution-trace requires --xpc-diag and --ios6-hid')
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
if args.system_sounds_unavailable and (not args.xpc_diag or not args.ios6_hid):
    parser.error('--system-sounds-unavailable requires --xpc-diag and --ios6-hid')
if args.input_test and not args.ios6_hid:
    parser.error('--input-test requires --ios6-hid')
if args.input_test and args.home_test:
    parser.error('Use requested input tests or the automatic Home test, not both')
if args.panic_test and not args.panic_recovery:
    parser.error('--panic-test requires --panic-recovery')
if args.panel_sleep and not args.charge_diag:
    parser.error('--panel-sleep requires --charge-diag')
if args.charge_art and not args.standalone_charge:
    parser.error('--charge-art requires --standalone-charge')
xnu = repo.parent / 'xnu-S2I9100'
label = 'control-' + datetime.now().strftime('%Y%m%d-%H%M%S')
kernel = xnu / 'out/automation' / label
package = repo / 'out/automation' / label
objects = ['pexpert/i9100_usbcdc.o', 'pexpert/i9100_timer.o', 'pexpert/pe_exynos4210_i9100.o', 'osfmk/machine_routines_asm.o',
           'osfmk/locore.o', 'osfmk/loose_ends.o', 'osfmk/hw_lock.o', 'osfmk/debug.o', 'osfmk/ipc_kobject.o', 'osfmk/ipc_mig.o', 'osfmk/mach_msg.o', 'osfmk/mach_port.o', 'security/mac_base.o',
           'osfmk/ipc_right.o', 'osfmk/ipc_kmsg.o', 'osfmk/ipc_pset.o', 'osfmk/sync_sema.o', 'osfmk/trap.o', 'bsd/kern_exec.o',
           'bsd/unix_syscalls.o', 'bsd/pthread_synch.o', 'bsd/kern_sig.o', 'bsd/sys_generic.o', 'bsd/param.o', 'bsd/vfs_subr.o', 'bsd/kdebug.o', 'bsd/decmpfs.o', 'iokit/IOKitBSDInit.cpo',
           'iokit/IOPMrootDomain.cpo', 'iokit/IOS7LeoDisplay.cpo', 'iokit/IOUserClient.cpo', 'iokit/AppleARMPE.cpo',
           'iokit/IOS7LeoHIDTouch.cpo',
           'iokit/i9100_power.o', 'iokit/i9100_power_bus.o', 'iokit/IOS7I9100Power.cpo',
           'osfmk/vm_map.o', 'osfmk/vm_user.o', 'osfmk/mach_kernelrpc.o', 'bsd/kern_exit.o', 'osfmk/pmap.o']
subprocess.run([sys.executable, xnu / 'tools/rebuild-i9100.py', '--output', kernel, '--link', *objects], check=True)
subprocess.run(['bash', repo / 'scripts/i9100/build-rawcom.sh'], check=True)
subprocess.run([sys.executable, repo / 'scripts/i9100/package-oneshot.py', '--kernel', kernel / 'mach_kernel',
                '--output', package, '--control',
                *(['--ls-bootstrap'] if args.ls_bootstrap else []),
                *(['--ls-ui-timeout'] if args.ls_ui_timeout else []),
                *(['--audio-property-lock'] if args.audio_property_lock else []),
                *(['--launchd-listener-guard'] if args.launchd_listener_guard else []),
                *(['--quiet-charge-feedback'] if args.quiet_charge_feedback else []),
                *(['--hid-execution-trace'] if args.hid_execution_trace else []),
                *(['--hid-fixed-cadence'] if args.hid_fixed_cadence else []),
                *(['--slab-publication-trace'] if args.slab_publication_trace else []),
                *(['--ui-execution-trace'] if args.ui_execution_trace else []),
                *(['--ui-retina-assets'] if args.ui_retina_assets else []),
                *(['--ui-keep-awake'] if args.ui_keep_awake else []),
                *(['--setup-native-layout'] if args.setup_native_layout else []),
                *(['--setup-background-fit'] if args.setup_background_fit else []),
                *(['--ui-density',str(args.ui_density)] if args.ui_density else []),
                *(['--ui-density-metrics'] if args.ui_density_metrics else []),
                *(['--ui-canvas',str(args.ui_canvas)] if args.ui_canvas else []),
                *(['--system-sounds-unavailable'] if args.system_sounds_unavailable else []),
                *(['--xpc-diag'] if args.xpc_diag else []),
                *(['--charge-diag'] if args.charge_diag else []),
                *(['--panel-sleep'] if args.panel_sleep else []),
                *(['--charge-probe'] if args.charge_probe else []),
                *(['--standalone-charge'] if args.standalone_charge else []),
                *(['--charge-art',args.charge_art] if args.charge_art else []),
                *(['--reboot-download-fallback'] if args.reboot_download_fallback else []),
                *(['--tcc-development'] if args.tcc_development else []),
                *(['--mdns-development'] if args.mdns_development else []),
                *(['--panic-recovery'] if args.panic_recovery else []),
                *(['--panic-test'] if args.panic_test else []),
                *(['--home-test'] if args.home_test else []),
                *(['--ios6-hid'] if args.ios6_hid else []),
                *(['--input-test'] if args.input_test else []),
                *(['--aks-development'] if args.aks_development else []),
                *(['--setup-dev-finish'] if args.setup_dev_finish else [])], check=True)
print('OFFLINE READY:', package, flush=True)
