#!/usr/bin/env python3
"""Explain saved LS evidence offline without contacting or modifying the phone.

Individual original errors and paired self-buffer bytes are evidence. Missing
ring entries are not proof of missing operations. This tool never declares
SpringBoard interaction passed or invents query/allocator associations.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

ROOT=Path(__file__).resolve().parents[4]
REPO=ROOT/'neighbor/uniloader'
ERRORS={0:'SUCCESS',3:'KERN_NO_SPACE',14:'EFAULT',
        0x10000002:'MACH_SEND_INVALID_DATA',0x10000003:'MACH_SEND_INVALID_DEST',
        0x10000009:'MACH_SEND_INVALID_REPLY',0x1000000c:'MACH_SEND_INVALID_MEMORY',
        0x10000010:'MACH_SEND_INVALID_HEADER',0x10004003:'MACH_RCV_TIMED_OUT',
        0x10004008:'MACH_RCV_INVALID_DATA',0x1000400b:'MACH_RCV_HEADER_ERROR',
        0x1000400c:'MACH_RCV_BODY_ERROR',0x1000400f:'MACH_RCV_INVALID_TRAILER'}


def error_name(value):return f'{ERRORS.get(value,"原始错误码")} (0x{value:08x})'


def analyze(observations):
    facts=[];cautions=[];pairs=[];pending={};recommendations=[]
    def fact(code,detail,**evidence):facts.append(dict(code=code,detail=detail,**evidence))
    query=observations.get('ls_query')
    if query is None:
        cautions.append('此采集中没有独立查询表；A包及旧包本来没有该表，不能推断未发请求。')
        recommendations.append('若仍等待，按晚间清单部署B包并采集LS-only及当前线程。')
    else:
        seq=query['sequence'];rows=query['rows']
        if seq>32:cautions.append('查询表已滚动；仅有最新32槽，较早阶段可能被覆盖。')
        if not rows:cautions.append('独立查询表没有已发布记录；可能未命中、观察安全门或尚未执行，不能认定没有IPC。')
        # The decoder returns oldest-to-newest order, including UInt32 wrap.
        for r in rows:
            raw=bytes.fromhex(r['hex']);stage=r['stage'];identity=dict(sequence=r['sequence'],pid=r['pid'],thread=r['thread'],stage=stage,id=r['id'])
            if len(raw)!=r['captured'] or len(raw)<24:raise ValueError('Incomplete query bytes')
            if stage in (1,2) and r['completion_seen'] and r['completion_result']:
                phase='copyin' if stage==1 else 'send'
                fact(phase+'_error',f'观察到原{phase}失败：{error_name(r["completion_result"])}。',result=r['completion_result'],**identity)
            if stage in (3,4) and r['result']:
                fact('receive_conversion_error',f'接收阶段{stage}原结果为{error_name(r["result"])}。',result=r['result'],**identity)
            key=(r['pid'],r['thread'],r['address'],r['id'],r['captured'])
            if stage==5:
                pending[key]=r
                if r['completion_seen'] and r['completion_result']:
                    fact('final_copyout_error',f'最终copyoutmsg原结果失败：{error_name(r["completion_result"])}。',result=r['completion_result'],**identity)
            if stage!=6:continue
            if r['result']:
                fact('self_read_error',f'最终用户缓冲读回失败：{error_name(r["result"])}；本条bytes是原source，不当作用户数据。',result=r['result'],**identity)
                pending.pop(key,None);continue
            source=pending.pop(key,None)
            if source is None or not source['completion_seen'] or source['completion_result']:
                cautions.append(f'query#{r["sequence"]}有实际读回bytes，但没有完整匹配的stage5；不做源/目的相等断言。')
                continue
            before=bytes.fromhex(source['hex']);different=[i for i,(a,b) in enumerate(zip(before,raw)) if a!=b]
            pair=dict(source_sequence=source['sequence'],user_sequence=r['sequence'],pid=r['pid'],
                      thread=r['thread'],address=r['address'],id=r['id'],bytes=len(raw),
                      mismatch_bytes=len(different),first_mismatch=different[0] if different else None,
                      source_sha256=hashlib.sha256(before).hexdigest(),user_sha256=hashlib.sha256(raw).hexdigest())
            pairs.append(pair)
            if different:
                fact('final_bytes_differ',f'同PID/线程/地址的最终源与用户读回有{len(different)}B不同，首差异+0x{different[0]:x}。',**pair)
            else:
                fact('final_bytes_match',f'同PID/线程/地址的最终交付{len(raw)}B逐字节一致。',**pair)
            if struct.unpack_from('<I',raw,20)[0]!=r['id']:
                fact('user_header_id_differs','实际用户header ID与已验证原消息ID不同；保留了真实bytes。',**identity)
            elif r['id']==14112 and len(raw)>=36:
                # This simple MIG reply has no OOL descriptors. Require the
                # exact native little-endian NDR and authoritative wire size.
                bits,size=struct.unpack_from('<II',raw)
                if not bits&0x80000000 and size in (36,40) and size<=len(raw) and raw[24:32]==bytes([0,0,0,0,1,0,0,0]):
                    retcode=struct.unpack_from('<I',raw,32)[0]
                    fact('native_reply_retcode',f'真实14112用户回复RetCode=0x{retcode:08x}；RPC结果不等于UI验收。',retcode=retcode,**identity)
        failures=observations.get('ls_query_alloc_failure',{}).get('rows',[])
        if failures:
            fact('allocation_failures',f'独立保留了{len(failures)}笔LSD原回复缓冲分配失败；不与query自动关联。',records=failures)
            if len(failures)==8:cautions.append('分配失败保留表达到8条上限，不能推断失败仅发生8次。')
        allocations=observations.get('ls_query_alloc',{})
        if allocations.get('sequence',0)>32:cautions.append('分配结果表为最新32条，query/allocator之间没有唯一关联ID。')
        if not pairs:recommendations.append('保留当前内核，读取当前SB/locationd/lsd真实线程与端口；不要仅凭阶段缺失重刷。')
        if any(f['code'] in ('copyin_error','send_error','receive_conversion_error','final_copyout_error','self_read_error','final_bytes_differ') for f in facts):
            recommendations.append('优先按已观察的原错误或字节差异查相应IPC/VM边界，并保存原始bin。')
        elif pairs:recommendations.append('已核对的最终交付正常；继续查原服务处理/等待链和真实UI，勿把该局部结果称为系统通过。')
    budget=observations.get('ls_ui_budget',{}).get('rows',[])
    for r in budget:
        if r['phase']==3:fact('deadline_outcome',f'PID{r["pid"]}的5秒期限原结果：{error_name(r["result"])}。',pid=r['pid'],thread=r['thread'],sequence=r['sequence'],result=r['result'])
    cautions.append('连续读回不是原子系统快照；同线程/地址配对仍需结合原线程、sender和端口证据。')
    return dict(facts=facts,cautions=list(dict.fromkeys(cautions)),delivery_pairs=pairs,
                recommendations=list(dict.fromkeys(recommendations)),springboard_interaction_verified=False)


def markdown(report):
    lines=['# 离线LS查询证据摘要','',f'BUILD：`{report["tag"]}`。主屏交互尚未由此工具验证。','']
    for label,key in [('观察事实','facts'),('解释边界','cautions'),('下一步','recommendations')]:
        lines.extend(['## '+label,''])
        values=report[key]
        lines.extend('- '+(v['detail'] if isinstance(v,dict) else v) for v in values)
        if not values:lines.append('没有本类已核实记录。')
        lines.append('')
    return '\n'.join(lines)


def module(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    value=importlib.util.module_from_spec(s);s.loader.exec_module(value);return value


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();capture=a.capture.resolve();kernel=a.kernel.resolve();out=a.output.resolve()
    if not capture.is_relative_to(REPO/'out') or not kernel.is_relative_to(REPO/'out') or not out.is_relative_to(REPO/'out') or out.exists():
        p.error('Read loader out evidence/kernel and use a fresh output directory in loader out')
    saved=json.loads((capture/'results.json').read_text(encoding='utf-8'))
    tag=module('analysis_memory','live-memory.py').Symbols(kernel).tag
    if saved['tag']!=tag:raise ValueError('Saved evidence BUILD does not match the kernel')
    # Require terminal capture evidence; a results file alone is not proof
    # of a completed collection or permission to reopen the port.
    events=[json.loads(line) for line in (capture/'events.jsonl').read_text(encoding='utf-8').splitlines() if line]
    terminal=[e['phase'] for e in events if e.get('phase') in ('DONE','STOP')]
    if not terminal or terminal[-1]!='DONE':raise ValueError('Capture has no successful terminal DONE evidence')
    out.mkdir(parents=True)
    observations=dict(saved.get('ui_observations',{}))
    raw_tables={};symbol_values={}
    for n,(key,file,size) in enumerate((('_i9100_ls_query_diag','ls-query.bin',13316),
                                      ('_i9100_ls_query_alloc_diag','ls_query_alloc.bin',1540),
                                      ('_i9100_ls_query_alloc_failure_diag','ls_query_alloc_failure.bin',388))):
        if not (capture/file).exists():continue
        raw=(capture/file).read_bytes()
        if len(raw)!=size:raise ValueError('Raw observer size mismatch: '+file)
        address=0x1000*(n+1);symbol_values[key]=address;raw_tables[address]=raw
    if '_i9100_ls_query_diag' in symbol_values:
        class Symbols:
            values=symbol_values
            def __getitem__(self,key):return self.values[key]
        class Memory:
            def read(self,address,size):
                raw=raw_tables[address]
                if len(raw)!=size:raise ValueError('Raw table layout mismatch')
                return raw
        decoded=out/'decoded';decoded.mkdir()
        current=module('analysis_observer','inspect-mdns.py').capture_ui_observations(Memory(),Symbols(),decoded)
        observations.update(current)
    elif observations.get('ls_query'):
        raise ValueError('Decoded query JSON has no supporting raw table')
    report=analyze(observations)
    report.update(tag=tag,capture=str(capture),created=datetime.now(timezone.utc).isoformat(),
                  phone_operations=0,scope='Saved evidence only; no inferred UI success')
    (out/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (out/'report.md').write_text(markdown(report),encoding='utf-8')
    print(json.dumps(dict(output=str(out),facts=len(report['facts']),pairs=len(report['delivery_pairs']),
                         springboard_interaction_verified=False),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
