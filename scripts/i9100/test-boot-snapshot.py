#!/usr/bin/env python3
"""Exercise the one-handle collector with real fixture/frame bytes offline.

Windows transport, ARM page tables and process state are models. Production
Session/Receiver, Kernel/PageMap, observation decoder, stack and frame code
execute. No phone or PnP access. Test artifacts stay in loader out.
"""
import os
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
                         sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
import argparse
from contextlib import contextmanager,redirect_stdout,redirect_stderr
from datetime import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('test_boot_collector',HERE/'capture-boot-snapshot.py')
boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture',type=Path,required=True)
parser.add_argument('--kernel',type=Path,required=True)
parser.add_argument('--frame',type=Path,required=True)
args=parser.parse_args()
ROOT=HERE.parents[3];REPO=HERE.parents[1]
out=REPO/'out'/('boot-snapshot-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
raw_frame=args.frame.read_bytes()
assert len(raw_frame)==1536000 and args.frame.resolve().is_relative_to(REPO/'out')
TAG=boot.m.Symbols(args.kernel).tag
DEVICE=dict(instance=r'USB\VID_0525&PID_A4A7\S2I9100-OS6',status='OK',port='COM12',
            service='usbser',name='Modeled serial',location='PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)')
PIDS={'SpringBoard':57,'locationd':38,'lsd':67,'backboardd':7}


class Symbols:
    tag=TAG;base=0x80001000
    def __init__(self):
        self.values={'_gPhysBase':0x80001000,'_gVirtBase':0x80001004,'_kernel_pmap':0x80001008,
                     '_PE_state':0x80010000,'_i9100_fb_physical':0x80010040,
                     '_i9100_graphics_seq':0x80010048,'_i9100_panel_console_enabled':0x80010050,
                     '_i9100_ls_query_diag':0x80020000,'_i9100_ls_query_alloc_diag':0x80024000,
                     '_i9100_ls_query_alloc_failure_diag':0x80024800}
        self.values.update({'_i9100_power_'+name:0x80025000+n*4 for n,name in enumerate(
            ('valid','percent','mv','connected','charging','temp','reason','revision_value'))})
    def __getitem__(self,key):return self.values[key]


class Model:
    def __init__(self,case='normal'):
        self.case=case;self.now=0.;self.opens=self.closes=self.locks=self.unlocks=0
        self.writes=[];self.thread_reads={};self.tick=1000;self.segments={};self.commands=[]
        self.symbols=Symbols();self.store(0x40001000,struct.pack('<III',0x40000000,0x80000000,0x80002000))
        header=bytearray(0x34);struct.pack_into('<I',header,0,0x40004000);struct.pack_into('<I',header,0x30,0x4000)
        self.store(0x40002000,header)
        l1=bytearray(0x4000);struct.pack_into('<I',l1,0x800*4,0x40000002);self.store(0x40004000,l1)
        ul1=bytearray(0x1000);struct.pack_into('<I',ul1,0x200*4,0x43000002);struct.pack_into('<I',ul1,0x201*4,0x43100002)
        self.store(0x40008000,ul1)
        self.store(0x40010004,struct.pack('<5I',0xc0006000,1920,480,800,32))
        self.store(0x40010040,struct.pack('<I',0x43e00000));self.store(0x40010048,struct.pack('<Q',5));self.store(0x40010050,bytes(4))
        for name,file in [('_i9100_ls_query_diag','query.bin'),('_i9100_ls_query_alloc_diag','alloc.bin'),('_i9100_ls_query_alloc_failure_diag','failures.bin')]:
            self.store(self.symbols[name]-0x40000000,(args.fixture/file).read_bytes())
        self.store(0x40025000,struct.pack('<8I',1,12,3750,1,1,320,0,14))
        regs=[0]*17;regs[0]=0x20000180;regs[7]=0x20000120;regs[12]=0xffffffe1
        regs[13:17]=[0x20000100,0x3be1b04d,0x3be1aeb4,0x10]
        for n,name in enumerate(PIDS):
            base=0x80030000+n*0x10000;task=base+0x2000;vm=base+0x3000;pmap=base+0x4000;uss=base+0x5000
            self.store(base-0x40000000+0x22c,struct.pack('<I',uss));self.store(base-0x40000000+0x3a0,struct.pack('<I',task))
            self.store(task-0x40000000+0x18,struct.pack('<I',vm));self.store(vm-0x40000000+0x2c,struct.pack('<I',pmap))
            ph=bytearray(0x34);struct.pack_into('<I',ph,0,0x40008000);struct.pack_into('<I',ph,0x30,0x1000)
            self.store(pmap-0x40000000,ph);self.store(uss-0x40000000,struct.pack('<17I',*regs))
            self.store(task-0x40000000+0x210,struct.pack('<II',0x20100100,84))
        stack=bytearray(4096);struct.pack_into('<II',stack,0x120,0,0x3416385f);self.store(0x43000000,stack)
        dyld=[0]*21;dyld[0]=12;dyld[1]=1;dyld[20]=0x2b5e000;self.store(0x43100100,struct.pack('<21I',*dyld))
    def store(self,address,data):self.segments[address]=bytes(data)
    def read(self,address,count):
        if 0x43e00000<=address and address+count<=0x43e00000+len(raw_frame):return raw_frame[address-0x43e00000:address-0x43e00000+count]
        data=bytearray(count)
        for base,raw in self.segments.items():
            lo=max(address,base);hi=min(address+count,base+len(raw))
            if lo<hi:data[lo-address:hi-address]=raw[lo-base:hi-base]
        return bytes(data)
    def clock(self):return self.now
    def sleep(self,seconds):self.now+=seconds
    @contextmanager
    def lock(self):
        self.locks+=1
        try:yield
        finally:self.unlocks+=1


class Transport:
    def __init__(self,model,record):
        self.model=model;self.record=record;model.opens+=1
        record('OPEN_OK',port='COM12');record('DTR_OK')
        tag='0'*16 if model.case=='wrong-build' else TAG
        self.pending=[b'I9CTL1 READY control=1\nI9CTL1 BUILD '+tag.encode()+b'\n']
    def ticks(self):self.model.tick+=1;return self.model.tick
    def read(self):
        self.model.now+=.001 if self.pending else .5
        return self.pending.pop(0) if self.pending else b''
    def write(self,wire):
        self.model.writes.append(wire);fields=wire.decode().strip().split(' ',2);seq,verb=fields[1:]
        self.model.commands.append(verb);data=None
        if verb=='ping':reply='OK control=1'
        elif verb=='panic-status':
            late=self.model.case=='late-panic' and self.model.commands.count('panic-status')>1
            reply='OK panic=1 seconds=000000aa' if self.model.case in ('panic','bad-panic') or late else 'OK panic=0 seconds=00000000'
        elif verb=='root-status':reply='OK root=MEDIA_FOUND'
        elif verb=='panic-log':
            text=b'modeled retained panic\n';h=[0x39504c47,1,len(text),0,0,1,0,0,0,0,0,0,180,10,1,0]
            if self.model.case=='bad-panic':h[0]=0
            data=struct.pack('<16I',*h)+text;reply=f'OK DATA 00000000 {len(data):08x}'
        elif verb.startswith('threads '):
            name=verb.split()[1];pid=PIDS[name];n=list(PIDS).index(name);thr=0x80030000+n*0x10000
            seen=self.model.thread_reads.get(name,0);self.model.thread_reads[name]=seen+1
            if self.model.case=='respawn' and name=='SpringBoard' and seen:pid+=1
            data=f'proc {pid} {name} p=0x80090000 snapshot=raw-irq\n  uth=0x800a0000 thr=0x{thr:x} wchan=0\n    st=1 pc=3be1aeb4 r12=ffffffe1\n'.encode()
            reply=f'OK DATA 00000000 {len(data):08x}'
        elif verb.startswith('read-memory '):
            address,count=(int(x,16) for x in verb.split()[1:]);data=self.model.read(address,count)
            reply=f'OK DATA {address:08x} {count:08x}'
            if ((self.model.case=='truncated-table' and address==0x40020000) or
                (self.model.case=='partial-frame' and address==0x43e02000)):
                self.pending.append(f'I9CTL1 {seq} {reply}\n'.encode()+data[:31]);return
        else:raise AssertionError('Unexpected device action: '+verb)
        self.pending.append(f'I9CTL1 {seq} {reply}\n'.encode()+(data or b''))
    def close(self):self.model.closes+=1


class Tests(unittest.TestCase):
    def run_main(self,case='normal',with_frame=False,error=None):
        model=Model(case);directory=out/self._testMethodName;directory.mkdir()
        target=directory/'capture';log=io.StringIO();OriginalSession=boot.SnapshotSession
        def factory(*a,**kw):return OriginalSession(*a,**kw,clock=model.clock,sleep=model.sleep)
        class Host:
            def inventory(self):return [DEVICE]
        with (patch.object(boot.o,'Host',Host),patch.object(boot.o,'host_lock',model.lock),
                patch.object(boot.m,'Symbols',lambda _:model.symbols),
                patch.object(boot.f,'WinTransport',lambda port,record:Transport(model,record)),
                patch.object(boot,'SnapshotSession',factory),
                patch.object(sys,'argv',['capture','--kernel',str(args.kernel),'--output',str(target)]+(['--frame'] if with_frame else [])),
                redirect_stdout(log),redirect_stderr(log)):
            if error:
                with self.assertRaises(error):boot.main()
            else:boot.main()
        (directory/'test.log').write_text(log.getvalue(),encoding='utf-8')
        events=[json.loads(line)['phase'] for line in (target/'events.jsonl').read_text().splitlines()]
        self.assertEqual((model.opens,model.closes,model.locks,model.unlocks),(1,1,1,1))
        self.assertEqual(events[-1],'STOP' if error else 'DONE')
        self.assertEqual(events.count('CLOSED'),1);self.assertLess(events.index('CLOSED'),len(events)-1)
        return model,target,events
    def test_complete_one_handle(self):
        model,target,events=self.run_main(with_frame=True)
        result=json.loads((target/'results.json').read_text());self.assertEqual(result['mode'],'normal-evidence')
        self.assertEqual(len(result['processes']),4);self.assertEqual(result['ui_observations']['power']['percent'],12)
        self.assertEqual(result['ui_observations']['ls_query']['sequence'],8)
        self.assertFalse(result['springboard_interaction_verified']);self.assertTrue(result['frame']['coherent'])
        self.assertEqual((target/'frame/framebuffer.bin').read_bytes(),raw_frame)
        self.assertEqual(result['frame']['raw_sha256'],hashlib.sha256(raw_frame).hexdigest())
        original_png=args.frame.with_suffix('.png')
        if original_png.exists():self.assertEqual((target/'frame/framebuffer.png').read_bytes(),original_png.read_bytes())
        self.assertEqual(model.commands.count('ping'),1);self.assertNotIn('reboot-download',model.commands)
    def test_wrong_build_opens_once_no_write(self):
        model,target,_=self.run_main('wrong-build',error=boot.f.ProtocolError)
        self.assertFalse(model.writes);self.assertFalse((target/'results.json').exists())
    def test_table_truncation_preserves_partial(self):
        model,target,_=self.run_main('truncated-table',error=TimeoutError)
        self.assertEqual((target/'incomplete-data.partial').stat().st_size,31)
        self.assertFalse(any(cmd.startswith('threads') for cmd in model.commands))
        self.assertTrue(model.commands[-1].startswith('read-memory 40020000 '))
    def test_partial_frame_does_not_restart(self):
        model,target,_=self.run_main('partial-frame',True,error=TimeoutError)
        self.assertEqual((target/'frame/framebuffer.partial.bin').stat().st_size,8192)
        self.assertEqual((target/'incomplete-data.partial').stat().st_size,31)
        self.assertFalse((target/'frame/result.json').exists());self.assertFalse((target/'frame/framebuffer.png').exists())
        self.assertEqual(len(json.loads((target/'stacks.json').read_text())['processes']),4)
    def test_respawn_keeps_original_regs(self):
        model,target,_=self.run_main('respawn',error=RuntimeError)
        saved=json.loads((target/'stacks.json').read_text());self.assertEqual(saved['processes'][0]['pid'],57)
        self.assertIn('registers',saved['processes'][0]['threads'][0])
        self.assertNotIn('threads locationd',model.commands)
    def test_panic_only_preserves_snapshot(self):
        model,target,_=self.run_main('panic')
        result=json.loads((target/'results.json').read_text());self.assertEqual(result['mode'],'panic-retained')
        self.assertEqual(model.commands,['ping','panic-status','panic-log'])
        self.assertIn('modeled retained panic',(target/'panic-log.txt').read_text())
    def test_malformed_panic_saved_before_reject(self):
        model,target,_=self.run_main('bad-panic',error=ValueError)
        self.assertTrue((target/'panic-log.bin').exists());self.assertFalse((target/'panic-log.txt').exists())
        self.assertEqual(model.commands,['ping','panic-status','panic-log'])
    def test_panic_during_collection_is_retained(self):
        model,target,_=self.run_main('late-panic')
        saved=json.loads((target/'results.json').read_text())
        self.assertEqual(saved['mode'],'panic-retained')
        self.assertTrue(saved['panic_started_during_snapshot'])
        self.assertEqual(saved['panic_initial']['active'],0)
        self.assertEqual(saved['panic']['active'],1)
        self.assertEqual(model.commands[-2:],['panic-status','panic-log'])
        self.assertTrue((target/'panic-log.bin').exists())
        self.assertEqual(len(saved['processes']),4)
        report=target.parent/'panic-report'
        completed=subprocess.run([sys.executable,'-B',str(HERE/'analyze-ls-query.py'),
            '--capture',str(target),'--kernel',str(args.kernel),'--output',str(report)],capture_output=True,text=True)
        (target.parent/'panic-report-command.log').write_text(completed.stdout+completed.stderr)
        self.assertEqual(completed.returncode,0,completed.stderr)
        summary=json.loads((report/'report.json').read_text(encoding='utf-8'))
        self.assertEqual(summary['facts'][0]['code'],'retained_panic')
        self.assertTrue(summary['facts'][0]['started_during_snapshot'])
        self.assertEqual(summary['panic']['active'],1)
        self.assertFalse(summary['springboard_interaction_verified'])
        self.assertEqual(len(summary['recommendations']),1)
    def test_budget_and_command_scope(self):
        model=Model();received=io.BytesIO();transport=Transport(model,lambda *a,**k:None)
        session=boot.SnapshotSession(transport,TAG,lambda *a,**k:None,received,
            clock=model.clock,sleep=model.sleep,budget_seconds=1,command_limit=1)
        session.handshake();self.assertEqual(len(model.writes),1)
        with self.assertRaises(TimeoutError):session.command('panic-status')
        for command in ('reboot-download','hid-home c8','read-memory 3fffffff 4','threads x\nreboot'):
            with self.assertRaises(ValueError):session.command(command)
        self.assertEqual(len(model.writes),1)
        model2=Model();t2=Transport(model2,lambda *a,**k:None)
        s2=boot.SnapshotSession(t2,TAG,lambda *a,**k:None,io.BytesIO(),clock=model2.clock,
                               sleep=model2.sleep,budget_seconds=1)
        s2.handshake();model2.now=.95
        with self.assertRaises(TimeoutError):s2.command('panic-status')
        self.assertEqual(len(model2.writes),1)
    def test_device_scope_rejects_before_opener(self):
        directory=out/self._testMethodName;directory.mkdir()
        for label,devices in (('absent',[]),('wrong-port',[dict(DEVICE,location='PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)')]),
                              ('wrong-driver',[dict(DEVICE,service='WinUSB')])):
            model=Model();target=directory/label
            class Host:
                def inventory(self):return devices
            with (patch.object(boot.o,'Host',Host),patch.object(boot.o,'host_lock',model.lock),
                  patch.object(boot.m,'Symbols',lambda _:model.symbols),
                  patch.object(boot.f,'WinTransport',lambda port,record:Transport(model,record)),
                  patch.object(sys,'argv',['capture','--kernel',str(args.kernel),'--output',str(target)])):
                with self.assertRaises(ValueError):boot.main()
            self.assertEqual((model.opens,model.closes),(0,0))
            self.assertFalse(target.exists());self.assertEqual(model.unlocks,1)
    def test_snapshot_feeds_offline_report(self):
        model,target,_=self.run_main()
        report=target.parent/'report'
        completed=subprocess.run([sys.executable,'-B',str(HERE/'analyze-ls-query.py'),
            '--capture',str(target),'--kernel',str(args.kernel),'--output',str(report)],
            capture_output=True,text=True)
        (target.parent/'report-command.log').write_text(completed.stdout+completed.stderr)
        self.assertEqual(completed.returncode,0,completed.stderr)
        result=json.loads((report/'report.json').read_text(encoding='utf-8'))
        self.assertEqual(len(result['delivery_pairs']),2)
        self.assertFalse(result['springboard_interaction_verified'])
        self.assertEqual(result['phone_operations'],0)


result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
(out/'result.json').write_text(json.dumps(dict(passed=result.wasSuccessful(),tests=result.testsRun,
    scope='Production collector/session/page-map/decoder/stack/frame; Windows transport and paging state modeled; saved real framebuffer bytes replayed',
    source_frame_sha256=hashlib.sha256(raw_frame).hexdigest(),phone_operations=0),indent=2)+'\n')
print('EVIDENCE',out)
if not result.wasSuccessful():sys.exit(1)
