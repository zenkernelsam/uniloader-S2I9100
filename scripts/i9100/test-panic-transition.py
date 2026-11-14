#!/usr/bin/env python3
"""Run the real Session/Receiver through a completed panic refusal offline.

The transport models a kernel that switches to panic-readonly after handshake;
only the allowed status/log requests may follow, on the same live handle.
"""
from pathlib import Path
from datetime import datetime
import importlib.util
import io
import json
import struct

spec=importlib.util.spec_from_file_location('transition_boot',Path(__file__).with_name('capture-boot-snapshot.py'))
boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('panic-transition-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
TAG='1234567890abcdef'
class Transport:
    def __init__(self,answer='ERR panic-readonly'):
        self.pending=[f'I9CTL1 READY control=1\nI9CTL1 BUILD {TAG}\n'.encode()]
        self.answer=answer;self.writes=[];self.now=0;self.count=100
    def ticks(self):self.count+=1;return self.count
    def read(self):self.now+=.01;return self.pending.pop(0) if self.pending else b''
    def write(self,data):
        self.writes.append(data);_,seq,verb=data.decode().strip().split(' ',2)
        payload=b''
        if verb=='ping':reply='OK control=1'
        elif verb.startswith('read-memory'):reply=self.answer
        elif verb=='panic-status':reply='OK panic=1 seconds=000000a0'
        elif verb=='panic-log':
            text=b'original modeled panic\nI9100 PANIC_WAIT seconds=180 route=DOWNLOAD\n'
            payload=struct.pack('<16I',0x39504c47,1,len(text),0,0,1,0,0,0,0,0,0,180,20,1,0)+text
            reply=f'OK DATA 00000000 {len(payload):08x}'
        else:raise AssertionError('Unexpected command: '+verb)
        self.pending.append(f'I9CTL1 {seq} {reply}\n'.encode()+payload)
    def clock(self):return self.now
    def sleep(self,seconds):self.now+=seconds
for label,answer,expected in [('panic','ERR panic-readonly',4),('unrelated','ERR read-range',2)]:
    target=out/label;target.mkdir();events=[];transport=Transport(answer)
    def record(phase,**fields):events.append(dict(phase=phase,**fields))
    session=boot.SnapshotSession(transport,TAG,record,io.BytesIO(),timeout=2,clock=transport.clock,sleep=transport.sleep,budget_seconds=10)
    session.watch_panic(target,record);session.handshake()
    try:session.command('read-memory 40001000 4');raise AssertionError('Refused query returned success')
    except boot.f.ProtocolError as error:assert str(error)==answer
    assert len(transport.writes)==expected
    if label=='panic':
        assert [w.decode().strip().split(' ',2)[2] for w in transport.writes]==['ping','read-memory 40001000 4','panic-status','panic-log']
        assert session.panic_transition['active']==1 and (target/'panic-log.bin').exists()
        assert [e['phase'] for e in events].count('PANIC_TRANSITION_SAVED')==1
    else:assert not (target/'panic-log.bin').exists()
    (target/'events.json').write_text(json.dumps(events,indent=2))
print('PASS real Session/Receiver retains exact panic refusal on same handle; other errors do not trigger requests')
print('EVIDENCE',out)
