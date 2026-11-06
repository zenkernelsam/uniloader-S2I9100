#!/usr/bin/env python3
"""Offline fault injection. Retains evidence in out; never opens USB or deletes."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import uuid

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('odin', Path(__file__).with_name('odin-loop.py'))
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
BASE = o.OUT / ('tests-' + uuid.uuid4().hex[:8])
BASE.mkdir(parents=True)
CDC = dict(instance=o.CDC, status='OK', port='COM12', location='PCIROOT(0)#USBROOT(0)#USB(3)',
           service='usbser', hardware='USB\\VID_0525&PID_A4A7')
DL = dict(instance=r'USB\VID_04E8&PID_685D\TEST', status='OK', port='', location=CDC['location'],
          service='WinUSB', hardware=r'USB\VID_04E8&PID_685D&REV_0001')
PROFILE = o.make_profile([DL])


class FakePlan:
    def __init__(self):
        self.parent = BASE / uuid.uuid4().hex[:8]
        self.parent.mkdir()
        self.data = dict(profile=PROFILE, validation='control', capture_seconds=1, boot_settle_seconds=90,
                         control_tag='0123456789abcdef', files={'zImage':'0'*64})
        self.bad_hash = False

    def verify(self):
        o.require(not self.bad_hash, 'injected image change')


class FakeHost:
    def __init__(self, fault=None, initial='cdc'):
        self.state, self.fault, self.calls = initial, fault, []
        self.delays = []

    def inventory(self):
        if self.state == 'cdc':
            return [CDC, dict(CDC)] if self.fault == 'two-cdc' else [CDC]
        if self.state == 'dl':
            if self.fault == 'two-download': return [DL, dict(DL)]
            if self.fault == 'wrong-port': return [dict(DL, location='different-port')]
            if self.fault == 'wrong-driver': return [dict(DL, service='ssudbus')]
            return [DL]
        return [CDC]

    def run(self, args, directory, timeout):
        self.calls.append(list(map(str, args)))
        if args[1] == 'flash':
            if self.fault == 'flash-failure': raise RuntimeError('injected flash error')
            if self.fault == 'flash-timeout': raise RuntimeError('injected uncertain timeout')
            self.state = 'boot'
            return
        if self.fault == 'serial-open': raise RuntimeError('injected blocked opener; no kill')
        if self.state == 'boot' and self.fault == 'boot-identity': raise RuntimeError('wrong build tag')
        reboot = 'reboot-download' in args
        (directory/'events.txt').write_text('PING_OK tick_ms=10\n' + ('COMMAND_ACK tick_ms=20\n' if reboot and self.fault!='missing-ack' else ''))
        (directory/'received.bin').write_bytes(b'arm_init: fixture log bytes')
        if reboot: self.state = 'dl'

    def sleep(self):
        raise AssertionError('Unexpected wait in immediate-transition fixture')

    def settle(self, seconds):
        self.delays.append(seconds)


class Tests(unittest.TestCase):
    def run_case(self, fault=None, mode='cycle'):
        host, plan = FakeHost(fault, 'dl' if mode=='bootstrap' else 'cdc'), FakePlan()
        journal = o.Journal(plan.parent)
        if fault:
            with self.assertRaises((ValueError, RuntimeError)):
                o.cycle(host, plan, mode, journal)
        else:
            o.cycle(host, plan, mode, journal)
        return host, plan

    def test_success_cycle(self):
        host, plan = self.run_case()
        self.assertEqual(len(host.calls), 3)
        self.assertEqual(host.calls[1][1:], ['flash','--KERNEL',str(plan.parent/'zImage'),'--stdout-errors'])
        self.assertEqual(host.calls[2][-2:], ['-Expect', plan.data['control_tag']])
        self.assertEqual(host.delays, [90])

    def test_reboot_only_never_flashes(self):
        host, _ = self.run_case(mode='reboot-only')
        self.assertEqual(len(host.calls), 1)

    def test_bootstrap(self):
        host, _ = self.run_case(mode='bootstrap')
        self.assertEqual(len(host.calls), 2)

    def test_diagnostic_never_sends_commands(self):
        host, plan=FakeHost(initial='dl'), FakePlan()
        plan.data['validation']='logs'
        o.cycle(host,plan,'bootstrap',o.Journal(plan.parent))
        self.assertEqual(len(host.calls),2)
        self.assertNotIn('-Send',host.calls[1])
        with self.assertRaises(ValueError): o.cycle(host,plan,'cycle',o.Journal(plan.parent))
        self.assertEqual(len(host.calls),2)

    def test_fail_before_flash(self):
        for fault in ('two-cdc','serial-open','missing-ack','two-download','wrong-port','wrong-driver'):
            with self.subTest(fault=fault):
                host, _ = self.run_case(fault)
                self.assertFalse(any(c[1]=='flash' for c in host.calls))

    def test_failed_flash_is_not_retried(self):
        for fault in ('flash-failure','flash-timeout','boot-identity'):
            with self.subTest(fault=fault):
                host, _ = self.run_case(fault)
                self.assertEqual(sum(c[1]=='flash' for c in host.calls), 1)

    def test_hash_change_stops_flash(self):
        plan, host = FakePlan(), FakeHost(initial='dl')
        plan.bad_hash = True
        with self.assertRaises(ValueError): o.cycle(host,plan,'bootstrap',o.Journal(plan.parent))
        self.assertEqual(host.calls, [])

    def test_profile_must_be_measured(self):
        for ds in ([], [DL,DL], [dict(DL,location='')]):
            with self.assertRaises(ValueError): o.make_profile(ds)
        with self.assertRaises(ValueError): o.validate_profile(dict(PROFILE,service='ssudbus'))

    def test_zimage_boundaries(self):
        import struct
        path = BASE/'image'
        data = bytearray(128)
        struct.pack_into('<III', data, 0x24, 0x016f2818, 0x40008000, 0x40008080)
        path.write_bytes(data); o.image_check(path)
        data[0x24] ^= 1; path.write_bytes(data)
        with self.assertRaises(ValueError): o.image_check(path)

    def test_consumed_plan_cannot_restart(self):
        path = BASE/'started.json'
        o.save(path, {'fixture':True})
        with self.assertRaises(FileExistsError): o.save(path, {'fixture':True})

    def test_deadline_never_opens_or_flashes(self):
        from unittest.mock import patch
        host=FakeHost()
        with patch.object(o.time,'monotonic',side_effect=[0,61]):
            with self.assertRaisesRegex(ValueError,'Timeout'):
                o.wait_for(host,lambda ds:None,60,'download')
        self.assertEqual(host.calls,[])

    def test_confinement(self):
        with self.assertRaises(ValueError): o.confined(o.ROOT.parent/'elsewhere',o.ROOT)

    def test_real_plan_guards_and_freeze(self):
        # Real snapshot validation, still no process/device execution.
        plans = sorted(o.OUT.glob('plan-*/plan.json'))
        if not plans: self.skipTest('Build one offline plan for snapshot guards')
        src = plans[-1]
        dest = BASE/'guard-plan'; dest.mkdir()
        import shutil
        data = json.loads(src.read_text())
        data['schema'] = 3
        data['validation'] = 'control'
        data['boot_settle_seconds'] = 90
        for name in data['files']: shutil.copyfile(src.parent/name,dest/name)
        path = dest/'plan.json'
        o.save(path,data)
        plan = o.Plan(path,o.sha(path))
        with self.assertRaises(ValueError): o.Plan(path,'0'*64)
        if sys.platform == 'win32':
            with o.immutable_snapshots(plan):
                with self.assertRaises(PermissionError):
                    with (dest/'zImage').open('r+b'): pass
        data['partition']='PIT'; path.write_text(json.dumps(data))
        with self.assertRaises(ValueError): o.Plan(path,o.sha(path))
        data['partition']='KERNEL';path.write_text(json.dumps(data))
        with (dest/'zImage').open('r+b') as f: f.write(b'bad')
        with self.assertRaises(ValueError): o.Plan(path,o.sha(path))


if __name__ == '__main__':
    unittest.main()
