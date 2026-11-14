#!/usr/bin/env python3
"""Decode production first-wait fixtures; reject cross-task/object evidence."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--semaphore',type=Path,required=True);p.add_argument('--queue',type=Path,required=True);a=p.parse_args()
s=importlib.util.spec_from_file_location('sem_parser',Path(__file__).with_name('inspect-mdns.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('media-semaphore-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_media_semaphore_diag':0x1000,'_i9100_media_dispatch_wait':0x4000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,semaphore,queue):self.semaphore=semaphore;self.queue=queue
    def read(self,address,size):
        data=self.semaphore if address==0x1000 else self.queue
        assert address in (0x1000,0x4000) and size==len(data);return data
def decode(name,semaphore,queue):
    target=out/name;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(semaphore,queue),Symbols(),target)
raw=a.semaphore.read_bytes();queue=a.queue.read_bytes();r=decode('production',raw,queue)
sem=r['media_semaphore'];q=r['media_dispatch_wait']
assert sem['count']==4 and sem['finished_stage']==5 and [x['stage'] for x in sem['rows']]==[1,2,4,5]
assert sem['rows'][1]['count']==0xffffffff and sem['rows'][1]['count_known']==1
assert sem['rows'][2]['current_task']!=sem['task'] and sem['rows'][2]['owner_pid']==33
assert q['semaphore_name']==0xa203
assert q['semaphore']==sem['semaphore'] and q['matched_frames']==1 and q['pc']==0x393bcf04
assert b'AudioControl' in bytes.fromhex(q['raw_hex'])
for name,word,value in [('count',0,129),('version',1,2),('capacity',2,129),('stride',3,17),('finish',8,7),
                        ('row-sequence',12,2),('row-stage',13,7),('row-object',12+7,0),('known',12+10,2)]:
    data=bytearray(raw);struct.pack_into('<I',data,word*4,value)
    try:decode(name,bytes(data),queue);raise AssertionError('Bad semaphore schema accepted')
    except ValueError:pass
for name,word,value in [('queue-task',3,0xdead),('queue-object',11,0x1234),('queue-frames',13,7)]:
    data=bytearray(queue);struct.pack_into('<I',data,word*4,value)
    try:decode(name,raw,bytes(data));raise AssertionError('Unrelated queue accepted')
    except ValueError:pass
print('PASS production same-wait queue/sem identity, cross-task producer, signed count bits, continuation and corrupt schema rejection')
print('EVIDENCE',out)
