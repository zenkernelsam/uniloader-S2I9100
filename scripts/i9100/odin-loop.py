#!/usr/bin/env python3
"""Reviewed, one-shot KERNEL iteration plans. Default commands are offline.

Real-device commands: observe-download, execute. No driver changes, partition
options, process killing, serial retries, or automatic failed-run recovery.
"""
import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
ROOT = REPO.parent
OUT = REPO / 'out/automation'
CDC = r'USB\VID_0525&PID_A4A7\S2I9100-OS6'
HEIMDALL_SHA = '4ddae318a50509a1c5ed8f23dc2fadda2a7a4ef913b0cac47fef1b27843db708'
DLLS = ('libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll')
_spec = importlib.util.spec_from_file_location('i9100_log', Path(__file__).with_name('classify-log.py'))
_logs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_logs)


def require(ok, message):
    if not ok:
        raise ValueError(message)


class UncertainProcess(RuntimeError):
    """A child may still own USB/COM; do not open another recovery session."""


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write('\n')


def confined(path, parent):
    path, parent = Path(path).resolve(), Path(parent).resolve()
    require(path.is_relative_to(parent), f'Path must be inside {parent}: {path}')
    return path


def image_check(path):
    size = path.stat().st_size
    require(0x30 <= size < 8 * 1024 * 1024, 'KERNEL image size outside whitelist')
    with path.open('rb') as f:
        header = f.read(0x30)
    magic, begin, end = struct.unpack_from('<III', header, 0x24)
    require((magic, begin, end) == (0x016f2818, 0x40008000, 0x40008000 + size),
            'Expected raw i9100 zImage; tar/PIT/other images are not accepted')


def normalize_location(value):
    return value.upper().split('#USBMI(')[0]


def samsung(devices):
    return [d for d in devices if re.match(r'^USB\\VID_04E8&PID_[0-9A-F]{4}\\', d['instance'].upper())]


def cdc(devices):
    matches = [d for d in devices if d['instance'].upper() == CDC]
    require(len(matches) <= 1, 'Ambiguous CDC device')
    if not matches:
        return None
    d = matches[0]
    require(d['status'] == 'OK' and re.fullmatch(r'COM[0-9]+', d['port'] or ''),
            'CDC device is not a healthy COM port')
    return d


def make_profile(devices):
    candidates = samsung(devices)
    require(len(candidates) == 1, 'Need exactly one physical Samsung USB device')
    d = candidates[0]
    require(d['status'] == 'OK' and d['location'] and d['hardware'], 'Incomplete device evidence')
    return {'schema': 1, 'instance': d['instance'], 'hardware': d['hardware'],
            'service': d['service'], 'location': normalize_location(d['location'])}


def validate_profile(profile):
    require(set(profile) == {'schema', 'instance', 'hardware', 'service', 'location'}, 'Invalid profile fields')
    require(profile['schema'] == 1 and len(samsung([profile])) == 1, 'Not a Samsung USB profile')
    require(profile['service'].lower() in ('winusb', 'libusbk', 'libusb0'),
            'Download interface needs a separately approved Heimdall-compatible driver; no driver is changed here')
    require(bool(profile['location']) and bool(profile['hardware']), 'Missing device identity/topology')


def download(devices, profile):
    actual = make_profile(devices)
    require(actual == profile, f'Download identity/driver/topology changed: {actual}')
    require(cdc(devices) is None, 'CDC and download device are simultaneously present')
    return actual


class Host:
    def inventory(self):
        require(os.name == 'nt', 'Device access runs only on Windows')
        # PnP property enumeration only. Never query Win32_SerialPort.
        script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$rows=@(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB\\VID_(0525|04E8)&' } | ForEach-Object {
    $d=$_
    $p=@(Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_LocationPaths','DEVPKEY_Device_Service','DEVPKEY_Device_HardwareIds' -ErrorAction Stop)
    $loc=@(($p|Where-Object KeyName -eq 'DEVPKEY_Device_LocationPaths').Data)
    $hw=@(($p|Where-Object KeyName -eq 'DEVPKEY_Device_HardwareIds').Data)
    [pscustomobject]@{instance=$d.InstanceId;status=[string]$d.Status;name=$d.FriendlyName;
        port=[regex]::Match([string]$d.FriendlyName,'\bCOM[0-9]+\b').Value;
        service=[string](($p|Where-Object KeyName -eq 'DEVPKEY_Device_Service').Data);
        location=[string]($loc|Select-Object -First 1);hardware=[string]($hw|Select-Object -First 1)}
})
ConvertTo-Json -InputObject $rows -Compress -Depth 4
'''
        # Popen.wait timeout never kills a blocked child; no automatic re-query.
        proc = subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            raise UncertainProcess(f'PnP query blocked, PID {proc.pid}; STOP, no kill/retry')
        require(proc.returncode == 0, 'PnP query failed: ' + stderr.decode('utf-8', 'replace'))
        return json.loads(stdout.decode('utf-8-sig'))

    def run(self, argv, directory, timeout):
        with (directory / 'stdout.txt').open('xb') as stdout, (directory / 'stderr.txt').open('xb') as stderr:
            proc = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr, cwd=directory)
            save(directory / 'process.json', {'pid': proc.pid, 'argv': list(map(str, argv))})
            try:
                result = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                raise UncertainProcess(f'Process {proc.pid} exceeded deadline; state uncertain, NO kill/retry')
        require(result == 0, f'Process failed ({result}); see {directory}')

    def sleep(self):
        time.sleep(1)

    def settle(self, seconds):
        for _ in range(seconds):
            time.sleep(1)


class Journal:
    def __init__(self, directory):
        self.path = directory / 'timeline.jsonl'

    def event(self, phase, **extra):
        record = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **extra)
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
            f.flush()
            os.fsync(f.fileno())
        print(phase, extra, flush=True)


def wait_for(host, predicate, seconds, label):
    deadline = time.monotonic() + seconds
    while True:
        devices = host.inventory()
        value = predicate(devices)
        if value:
            return value
        require(time.monotonic() < deadline, f'Timeout: {label}; no retry')
        host.sleep()


def serial(host, plan, directory, device, verb, tag=None):
    directory.mkdir()
    args = [plan.parent / 'rawcom.exe', device['port'], str(plan.data['capture_seconds']), directory]
    if verb:
        args += ['-Send', verb]
    if tag:
        args += ['-Expect', tag]
    host.run(args, directory, plan.data['capture_seconds'] + 120)
    events = (directory / 'events.txt').read_text()
    if verb:
        require('PING_OK ' in events, 'Missing correlated kernel ping')
        require(verb == 'ping' or 'COMMAND_ACK ' in events, 'Missing reboot acknowledgement')
    require((directory / 'received.bin').stat().st_size > 0, 'Empty capture')
    save(directory / 'log-analysis.json', _logs.classify((directory / 'received.bin').read_bytes()))
    if verb == 'root-status':
        states = re.findall(r'^ROOT_STATE (BOOTING|WAIT_ROOT|NO_ROOT|MEDIA_FOUND)$', events, re.M)
        require(len(states) == 1, 'Missing or ambiguous root-state acknowledgement')
        return states[0]
    return None


class Plan:
    def __init__(self, path, digest):
        self.path = confined(path, OUT)
        require(self.path.name == 'plan.json', 'Expected a plan.json snapshot')
        self.parent = self.path.parent
        require(sha(self.path) == digest, 'Plan SHA256 was not approved or changed')
        self.data = json.loads(self.path.read_text())
        d = self.data
        require(set(d) == {'schema', 'partition', 'validation', 'root_status_protocol', 'capture_seconds', 'boot_settle_seconds', 'control_tag', 'profile', 'files'}, 'Unexpected plan fields')
        require(d['schema'] == 4 and d['partition'] == 'KERNEL', 'Only schema-4 KERNEL plans are permitted')
        require(d['validation'] in ('control', 'logs', 'maintenance'), 'Invalid validation mode')
        require(type(d['root_status_protocol']) == bool, 'Invalid root-status capability')
        require(d['validation'] != 'maintenance' or d['root_status_protocol'], 'Maintenance needs a root-status kernel')
        require(type(d['capture_seconds']) == int and 1 <= d['capture_seconds'] <= 900, 'Bad capture duration')
        require(type(d['boot_settle_seconds']) == int and 30 <= d['boot_settle_seconds'] <= 180, 'Bad boot settling duration')
        require(re.fullmatch('[0-9a-f]{16}', d['control_tag']) is not None, 'Missing kernel identity')
        require(set(d['files']) == {'zImage', 'rawcom.exe', 'heimdall.exe', *DLLS}, 'Unexpected snapshot files')
        if d['profile'] is not None:
            validate_profile(d['profile'])
        self.verify()

    def verify(self):
        for name, digest in self.data['files'].items():
            path = confined(self.parent / name, self.parent)
            require(sha(path) == digest, 'Snapshot SHA256 changed: ' + name)
        require(self.data['files']['heimdall.exe'] == HEIMDALL_SHA, 'Unreviewed Heimdall binary')
        image_check(self.parent / 'zImage')
        require(('i9100build=' + self.data['control_tag']).encode() in (self.parent / 'zImage').read_bytes(),
                'Build identity is not embedded in this loader image')


def create_plan(args):
    image = confined(args.image, REPO / 'out')
    image_check(image)
    manifest = json.loads(image.with_name('manifest.json').read_text())
    if not args.diagnostic:
        require(manifest.get('serial_control') is True, 'Use a control-enabled package or explicitly --diagnostic')
    else:
        require(manifest.get('diagnostic_control_bootargs_only') is True, 'Diagnostic package marker is missing')
    require(not args.maintenance or manifest.get('root_status_protocol') is True,
            'Maintenance needs an explicitly root-status-capable package')
    require(manifest['artifacts']['zImage']['sha256'] == sha(image), 'Package manifest does not match image')
    require(manifest['control_tag'] == manifest['artifacts']['mach_kernel']['sha256'][:16], 'Kernel tag mismatch')
    profile = json.loads(confined(args.profile, ROOT).read_text()) if args.profile else None
    if profile:
        validate_profile(profile)
    dest = OUT / ('plan-' + datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8])
    dest.mkdir(parents=True)
    sources = {'zImage': image, 'rawcom.exe': REPO / 'out/one-shot/host/rawcom.exe'}
    for name in ('heimdall.exe', *DLLS):
        sources[name] = ROOT / 'assets/heimdall-win64' / name
    for name, src in sources.items():
        shutil.copyfile(src, dest / name)
    data = {'schema': 4, 'partition': 'KERNEL',
            'validation': 'logs' if args.diagnostic else 'maintenance' if args.maintenance else 'control',
            'root_status_protocol': manifest.get('root_status_protocol') is True,
            'capture_seconds': args.seconds,
            'boot_settle_seconds': args.boot_settle_seconds,
            'control_tag': manifest['control_tag'], 'profile': profile,
            'files': {name: sha(dest / name) for name in sources}}
    save(dest / 'plan.json', data)
    digest = sha(dest / 'plan.json')
    Plan(dest / 'plan.json', digest)
    print(json.dumps({'plan': str(dest / 'plan.json'), 'approve_plan_sha256': digest,
                     'confirm_kernel_sha256': data['files']['zImage'], 'profile_present': bool(profile)}, indent=2))


@contextmanager
def host_lock():
    require(os.name == 'nt', 'Execution requires Windows')
    import msvcrt
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / 'host.lock').open('a+b') as lock:
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            yield
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def immutable_snapshots(plan):
    # Deny write/delete while Heimdall opens the same snapshot for reading.
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    with ExitStack() as stack:
        for name in ('plan.json', *plan.data['files']):
            h = kernel.CreateFileW(str(plan.parent / name), 0x80000000, 1, None, 3, 0, None)
            require(h != ctypes.c_void_p(-1).value, f'Cannot freeze {name}')
            stack.callback(kernel.CloseHandle, h)
        plan.verify()
        yield


def has_panic_recovery(plan):
    image = plan.parent / 'zImage'
    return image.is_file() and b'i9100panicrecovery=1' in image.read_bytes()


def panic_tools():
    spec = importlib.util.spec_from_file_location('i9100_boot_panic', Path(__file__).with_name('panic-recovery.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def check_boot_panic(host, plan, journal):
    """One independent state check after the previous serial child has exited.

    The outer execute already owns host.lock and the immutable snapshot lease.
    A timed-out child never reaches here. This never flashes or sends a reset.
    """
    if not has_panic_recovery(plan):
        return False
    p = panic_tools()
    profile = plan.data['profile']
    require(profile is not None, 'Panic state verification needs an approved Download profile')
    devices = host.inventory()
    if samsung(devices):
        journal.event('DOWNLOAD_DURING_BOOT_CHECK', profile=download(devices, profile))
        raise ValueError('Kernel is already in Download; boot was not verified')
    device = p.healthy_cdc(devices, profile)
    require(device is not None, 'No healthy kernel CDC for panic state check; no opener retry')
    output = plan.parent / 'panic-check'
    output.mkdir()
    with p.serial_session(output / 'serial', device, plan.data['control_tag'], journal.event) as session:
        answer, _ = session.command('panic-status')
        active, remaining = p.countdown(answer)
        journal.event('BOOT_PANIC_STATE', active=active, remaining_seconds=remaining)
        if not active:
            return False
        journal.event('BOOT_PANIC_DETECTED', meaning='Preserve evidence and wait for automatic Download; no flash retry')
        header, observed, digest, advanced = p.collect(session, output, journal.event)
    actual, duration = p.observe_download(host, profile, output, journal.event,
                                         observed - header['elapsed_seconds'])
    result = dict(build=plan.data['control_tag'], panic_log_sha256=digest,
                  header=header, countdown_advanced=advanced, download=actual,
                  seconds_since_panic=round(duration, 3), extra_flash_writes=0)
    save(output / 'result.json', result)
    journal.event('PANIC_RECOVERED_TO_DOWNLOAD', **result)
    return True


def verify_kernel(host, plan, device, journal, verify_only=False):
    journal.event('VERIFY_KERNEL', control_tag=plan.data['control_tag'])
    if plan.data['validation'] != 'logs':
        query = 'root-status' if plan.data['root_status_protocol'] else 'ping'
        try:
            root_state = serial(host, plan, plan.parent / 'after', device, query, plan.data['control_tag'])
            if plan.data['root_status_protocol']:
                expected = 'NO_ROOT' if plan.data['validation'] == 'maintenance' else 'MEDIA_FOUND'
                require(root_state == expected, f'Expected root state {expected}, observed {root_state}')
        except UncertainProcess:
            # The old child may still hold a blocked COM opener or PnP query.
            # Preserve it and stop; a recovery opener would violate ownership.
            raise
        except Exception:
            check_boot_panic(host, plan, journal)
            raise
        require(not check_boot_panic(host, plan, journal),
                'Kernel panicked; evidence saved and automatic Download observed; failed plan stays consumed')
        analysis = json.loads((plan.parent / 'after/log-analysis.json').read_text())
        require(not analysis['panic_lines'], 'Kernel panic appears in boot capture; boot was not verified')
        phase = 'DONE_VERIFY_ONLY' if verify_only else 'DONE_MAINTENANCE' if plan.data['validation'] == 'maintenance' else 'DONE'
        journal.event(phase, root_state=root_state,
                      meaning='Build/ping/capture verified; root state is media discovery, not filesystem integrity')
    else:
        serial(host, plan, plan.parent / 'after', device, None)
        data = (plan.parent / 'after/received.bin').read_bytes()
        require(any(marker in data for marker in (b'arm_init:', b'PE_init_iokit', b'launchd[1]', b'exec_activate_image')),
                'Diagnostic capture has no kernel log markers; stop without retry')
        journal.event('DONE_DIAGNOSTIC', bytes=len(data), meaning='Kernel logs observed; no command or build handshake attempted')


def cycle(host, plan, mode, journal):
    profile = plan.data['profile']
    require(plan.data['validation'] != 'logs' or mode == 'bootstrap',
            'A diagnostic kernel permits one bootstrap and read-only logs, never commands or a cycle')
    if mode == 'verify-only':
        device = cdc(host.inventory())
        require(device is not None, 'Expected a running kernel for verification')
        if profile:
            require(normalize_location(device['location']) == profile['location'], 'CDC moved to another USB port')
        plan.verify()
        verify_kernel(host, plan, device, journal, verify_only=True)
        return
    if mode != 'reboot-only':
        require(profile is not None, 'Measure and approve a download profile first')
    if mode != 'bootstrap':
        device = cdc(host.inventory())
        require(device is not None, 'Expected running command-enabled kernel')
        require(not samsung(host.inventory()), 'Disconnect other Samsung USB devices')
        if profile:
            require(normalize_location(device['location']) == profile['location'], 'CDC moved to another USB port')
        journal.event('CAPTURE_AND_REBOOT', device=device)
        serial(host, plan, plan.parent / 'before', device, 'reboot-download')
        journal.event('REBOOT_ACK')
        wait_for(host, lambda ds: not cdc(ds), 30, 'CDC disconnect')
        devices = wait_for(host, lambda ds: ds if samsung(ds) else None, 60, 'Samsung download enumeration')
        observed = make_profile(devices)
        require(observed['location'] == normalize_location(device['location']), 'New device is on a different USB port')
        save(plan.parent / 'observed-download.json', observed)
        journal.event('DOWNLOAD_OBSERVED', profile=observed)
        if mode == 'reboot-only':
            journal.event('DONE_REBOOT_ONLY')
            return
    download(host.inventory(), profile)
    plan.verify()
    journal.event('FLASH_KERNEL_BEGIN', sha256=plan.data['files']['zImage'])
    flashdir = plan.parent / 'flash'
    flashdir.mkdir()
    # Fixed argv. No user partition names, PIT writes, or arbitrary options.
    host.run([plan.parent / 'heimdall.exe', 'flash', '--KERNEL', plan.parent / 'zImage', '--stdout-errors'], flashdir, 180)
    journal.event('FLASH_TOOL_OK')
    wait_for(host, lambda ds: not samsung(ds), 60, 'download disconnect after flash')
    device = wait_for(host, cdc, 120, 'new CDC boot')
    require(normalize_location(device['location']) == profile['location'], 'Post-flash device topology changed')
    journal.event('WAIT_KERNEL_BOOT', seconds=plan.data['boot_settle_seconds'])
    host.settle(plan.data['boot_settle_seconds'])
    device = cdc(host.inventory())
    require(device is not None and normalize_location(device['location']) == profile['location'],
            'CDC changed during boot settling; no port opened')
    verify_kernel(host, plan, device, journal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('plan', help='Offline snapshot only; never opens USB')
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--profile', type=Path)
    checks = p.add_mutually_exclusive_group()
    checks.add_argument('--diagnostic', action='store_true', help='Explicit log-only baseline-kernel diagnostic; never send commands')
    checks.add_argument('--maintenance', action='store_true', help='Expect NO_ROOT with working USB commands; not normal system boot')
    p.add_argument('--seconds', type=int, choices=range(1, 901), default=30, metavar='1..900')
    p.add_argument('--boot-settle-seconds', type=int, choices=range(30, 181), default=90, metavar='30..180')
    p = sub.add_parser('observe-download', help='Real-device PnP observation; phone must already be in download mode')
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('execute', help='Use only after user approves this concrete plan and hardware operation')
    p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--approve-plan', required=True)
    p.add_argument('--mode', choices=('verify-only', 'reboot-only', 'bootstrap', 'cycle'), required=True)
    p.add_argument('--confirm-kernel', help='Second confirmation: exact zImage SHA256 (required for writes)')
    args = parser.parse_args()
    if args.command == 'plan':
        create_plan(args)
        return
    if args.command == 'observe-download':
        save(confined(args.output, OUT), make_profile(Host().inventory()))
        return
    plan = Plan(args.plan, args.approve_plan)
    if args.mode in ('bootstrap', 'cycle'):
        require(args.confirm_kernel == plan.data['files']['zImage'], 'KERNEL write needs a second SHA256 confirmation')
    with host_lock(), immutable_snapshots(plan):
        # A consumed plan is never retried, including after a crash/timeout.
        save(plan.parent / 'started.json', {'mode': args.mode, 'time': datetime.now(timezone.utc).isoformat()})
        journal = Journal(plan.parent)
        try:
            cycle(Host(), plan, args.mode, journal)
        except Exception as exc:
            journal.event('STOP', error=str(exc), retry=False)
            raise


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
