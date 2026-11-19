#!/usr/bin/env python3
"""Compare retained same-BUILD WFI wall-clock observations without phone access.

Uses device MCT times, not file times. No CPU rate or milliamps inferred from
host receipt time, partial samples, a different boot or missing old schemas.
"""
import argparse,hashlib,importlib.util,json,re
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('idle_charge',here/'inspect-charge-health.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=here.parents[1]
def read_capture(path):
    path=path.resolve();root=repo/'out'
    if not path.is_relative_to(root) or not path.is_file():raise ValueError('Retained result.json under loader out required')
    raw=path.read_bytes();result=json.loads(raw)
    if not result.get('tag') or not isinstance(result.get('charge'),dict):raise ValueError('Expected an original owner charge result')
    expected=result['charge'].get('idle_paired')
    binary=path.parent/'idle-paired.bin'
    if not expected or not binary.is_file():raise ValueError('Current capture lacks paired WFI evidence; not inferred from CPU ticks')
    after=path.parent/'idle-paired-after.bin'
    if not after.is_file():raise ValueError('Publication recheck missing; no interval inferred')
    actual=m.decode_idle_paired(binary.read_bytes(),after.read_bytes())
    if actual!=expected:raise ValueError('Paired binary and charge JSON differ')
    owner=path.parent.parent
    if not re.fullmatch(r'task-[0-9]{4}',path.parent.name) or path.name!='result.json':
        raise ValueError('An original UI-owner task result is required')
    lease_raw=(owner/'owner.json').read_bytes();lease=json.loads(lease_raw)
    if lease.get('tag')!=result['tag'] or type(lease.get('process_created_100ns')) is not int:
        raise ValueError('Original owner BUILD/process identity missing')
    events_raw=(owner/'events.jsonl').read_bytes()
    if not events_raw.endswith(b'\n'):raise ValueError('Owner has a partial event; preserve it before summarizing')
    events=[json.loads(line) for line in events_raw.splitlines() if line.strip()]
    task=result.get('task',{});task_id=path.parent.name[5:]
    if task.get('id')!=task_id or task.get('action')!='charge':raise ValueError('Original charge task identity differs')
    ready=[row for row in events if row.get('phase')=='READY']
    if len(ready)!=1 or ready[0].get('tag')!=lease['tag'] or ready[0].get('pid')!=lease.get('pid'):
        raise ValueError('Original single-owner handshake missing')
    completed=[(n,row) for n,row in enumerate(events) if row.get('phase')=='TASK_DONE' and row.get('id')==task_id]
    if len(completed)!=1 or completed[0][1].get('action')!='charge':raise ValueError('Charge task has not completed once')
    completion=completed[0][0]
    if any(row.get('phase') in ('STOP','CLOSED','DONE') for row in events[:completion]):
        raise ValueError('Owner was terminal before this capture')
    return result,dict(path=str(path),owner=str(owner),task_index=completion,
        result_sha256=hashlib.sha256(raw).hexdigest(),owner_sha256=hashlib.sha256(lease_raw).hexdigest(),
        events_sha256=hashlib.sha256(events_raw).hexdigest(),
        paired_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        publication_header_sha256=hashlib.sha256(after.read_bytes()).hexdigest())
def compare(first,e1,last,e2):
    if first['tag']!=last['tag']:raise ValueError('Different kernels; no idle interval combined')
    if e1['owner']!=e2['owner'] or e1['owner_sha256']!=e2['owner_sha256']:
        raise ValueError('Different serial-owner lifetimes; separate boots cannot be combined')
    if e1['task_index']>=e2['task_index']:raise ValueError('Charge tasks are not in chronological order')
    return m.idle_interval(first['charge']['idle_paired'],last['charge']['idle_paired'])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--before',type=Path,required=True)
    p.add_argument('--after',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    first,e1=read_capture(a.before);last,e2=read_capture(a.after)
    summary=compare(first,e1,last,e2)
    out=a.output.resolve()
    if not out.is_relative_to(repo/'out') or out.exists():raise ValueError('Fresh output under loader out required')
    out.mkdir();report=dict(tag=first['tag'],before=e1,after=e2,idle=summary,
        limit='Completion-only WFI wall time modulo one 32-bit MCT wrap per individual wait; no voltage/current energy measurement')
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
