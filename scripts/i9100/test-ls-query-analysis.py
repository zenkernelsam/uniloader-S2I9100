#!/usr/bin/env python3
"""Exercise offline LS conclusions using actual C fixtures and explicit models."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture',type=Path,required=True)
p.add_argument('--kernel',type=Path,required=True)
a=p.parse_args()
out=REPO/'out'/('ls-query-analysis-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
analysis=module('query_analysis','analyze-ls-query.py');observer=module('query_decoder','inspect-mdns.py')
class Symbols:
    values={'_i9100_ls_query_diag':0x1000,'_i9100_ls_query_alloc_diag':0x2000,'_i9100_ls_query_alloc_failure_diag':0x3000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self):self.data={addr:(a.fixture/file).read_bytes() for addr,file in [(0x1000,'query.bin'),(0x2000,'alloc.bin'),(0x3000,'failures.bin')]}
    def read(self,address,size):assert len(self.data[address])==size;return self.data[address]
decoded=out/'decoded-fixture';decoded.mkdir()
with contextlib.redirect_stdout(io.StringIO()):observations=observer.capture_ui_observations(Memory(),Symbols(),decoded)
r=analysis.analyze(observations);codes=[f['code'] for f in r['facts']]
assert not r['springboard_interaction_verified']
assert codes.count('final_bytes_match')==1 and codes.count('final_bytes_differ')==1
assert all(code in codes for code in ('copyin_error','self_read_error','final_copyout_error','user_header_id_differs','allocation_failures'))
assert r['delivery_pairs'][1]['first_mismatch']==20
assert any('8条上限' in text for text in r['cautions'])
empty=analysis.analyze({});assert not empty['facts'] and not empty['springboard_interaction_verified']
missing=analysis.analyze({'ls_query':dict(sequence=7,rows=[observations['ls_query']['rows'][4]])})
assert not missing['delivery_pairs'] and any('没有完整匹配' in text for text in missing['cautions'])
read_error=analysis.analyze({'ls_query':dict(sequence=7,rows=[observations['ls_query']['rows'][5],observations['ls_query']['rows'][6]])})
assert not read_error['delivery_pairs'] and read_error['facts'][0]['code']=='self_read_error'
# A newer transfer on the same thread invalidates an older unpaired
# stage5, even when it changed the address/ID. Never pair stale buffer use.
original=observations['ls_query']['rows'][1]
actual=observations['ls_query']['rows'][2]
replacement=dict(original,sequence=3,address=original['address']+4096)
stale=analysis.analyze({'ls_query':dict(sequence=4,rows=[dict(original,sequence=1),replacement,dict(actual,sequence=4)])})
assert not stale['delivery_pairs'], 'same-thread buffer reuse paired a stale source'
def reply(retcode):
    raw=struct.pack('<6I',0x1200,36,0,0x707,0,14112)+bytes([0,0,0,0,1,0,0,0])+struct.pack('<I',retcode)
    common=dict(pid=38,thread=0x1234,address=0x12000,id=14112,captured=36,hex=raw.hex(),result=0)
    return dict(sequence=2,rows=[dict(common,sequence=1,stage=5,completion_seen=1,completion_result=0),
                                 dict(common,sequence=2,stage=6,completion_seen=0,completion_result=0)])
for retcode in (0,5,0xfffffecf):
    test=analysis.analyze({'ls_query':reply(retcode)})
    assert next(f['retcode'] for f in test['facts'] if f['code']=='native_reply_retcode')==retcode
    assert not test['springboard_interaction_verified']
invalid_rights=reply(5)
for row in invalid_rights['rows']:
    raw=bytearray.fromhex(row['hex']);struct.pack_into('<I',raw,0,0);row['hex']=raw.hex()
test=analysis.analyze({'ls_query':invalid_rights})
assert not any(f['code']=='native_reply_retcode' for f in test['facts']), 'invalid reply rights treated as native MIG'
tag=module('analysis_test_memory','live-memory.py').Symbols(a.kernel).tag
capture=out/'modeled-capture';capture.mkdir()
for source,target in [('query.bin','ls-query.bin'),('alloc.bin','ls_query_alloc.bin'),('failures.bin','ls_query_alloc_failure.bin')]:
    (capture/target).write_bytes((a.fixture/source).read_bytes())
(capture/'results.json').write_text(json.dumps(dict(tag=tag,ui_observations=observations,evidence='C production fixture; USB/copy backend modeled'))+'\n')
(capture/'events.jsonl').write_text(json.dumps(dict(phase='DONE',evidence='modeled test completion; no phone session'))+'\n')
def cli(label,expect_success=True):
    command=[sys.executable,'-B',str(HERE/'analyze-ls-query.py'),'--capture',str(capture),'--kernel',str(a.kernel),'--output',str(out/label)]
    result=subprocess.run(command,capture_output=True,text=True)
    (out/(label+'.log')).write_text(result.stdout+result.stderr)
    assert (result.returncode==0)==expect_success,label
    return result
cli('production-cli');actual=json.loads((out/'production-cli/report.json').read_text(encoding='utf-8'))
assert len(actual['delivery_pairs'])==2 and not actual['springboard_interaction_verified']
(capture/'events.jsonl').write_text(json.dumps(dict(phase='STOP'))+'\n');cli('reject-stopped',False)
(capture/'events.jsonl').write_text(json.dumps(dict(phase='DONE',evidence='modeled'))+'\n')
saved=json.loads((capture/'results.json').read_text());saved['tag']='0'*16
(capture/'results.json').write_text(json.dumps(saved));cli('reject-wrong-build',False)
(out/'result.json').write_text(json.dumps(dict(passed=True,source='production C observer fixture; transport and synthetic MIG replies modeled',
    checks=['matched and changed bytes','failed read not treated as user bytes','missing stage has no fabricated pair',
            'native reply errors remain errors','no inferred SpringBoard success','terminal and BUILD CLI checks'],phone_operations=0),indent=2)+'\n')
print('PASS evidence-supported LS conclusions, missing/error counterexamples and BUILD/terminal checks; no phone access')
print('EVIDENCE',out)
