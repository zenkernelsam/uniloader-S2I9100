#!/usr/bin/env python3
"""Classify captured bytes; repeated exec events are not USB retransmission proof."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def classify(data):
    text = re.sub(r'\x1b\[[0-9;]*m', '', data.decode('utf-8', 'replace')).replace('\r', '')
    dumps = []
    pattern = r'([^\n ]+)\[(\d+)\]: usermode undefined instruction, EXC_BAD_INSTRUCTION at (0x[0-9a-f]+)(.*?cpsr:\s*(0x[0-9a-f]+))'
    for m in re.finditer(pattern, text, re.S):
        regs = dict(re.findall(r'\b(r\d+|sp|lr|pc|cpsr):\s*(0x[0-9a-f]+)',m[4]))
        dumps.append(dict(process=m[1],pid=int(m[2]),pc=m[3],registers=regs,
                          instruction_set='Thumb' if int(m[5],16)&32 else 'ARM'))
    groups = Counter((d['process'],d['pc'],d['instruction_set']) for d in dumps)
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                exec_events=len(re.findall(r'exec_check_permissions:',text)),
                register_dump_count=len(dumps),dumps=dumps,
                crash_groups=[dict(process=p,pc=pc,instruction_set=isa,count=n) for (p,pc,isa),n in groups.items()],
                panic_lines=[s for s in text.splitlines() if re.search(r'panic\(cpu|Kernel (?:prefetch|data|undefined)',s)],
                interpretation='Exec repetition records process launches; it does not establish transport retransmission. A handshake alone does not establish userspace stability.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    a=p.parse_args()
    print(json.dumps(classify(a.capture.read_bytes()),indent=2))
