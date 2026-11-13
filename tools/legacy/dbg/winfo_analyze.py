#!/usr/bin/env python3
"""Cross-reference threads+rnames with ports dumps.

Input files (from i9fetch capture dir):
  threads-*.txt   proc <pid> <comm> p=<ptr>
                  uth=.. thr=.. ..
                  st=.. wq=.. ist=<ith_state> iobj=.. rnam=<name> cont=.. pc=.. lr=..
  ports-*.txt     proc <pid> <comm> p=<ptr> task=<ptr>
                  space=.. tsize=..
                  pn=<name> rt=<rights> obj=<ptr> rsp=<recv-space> rtsk=<recv-task>

For every thread in MACH_MSG_RECEIVE (ist=0x10004001) resolves rnam via its
own task's port table -> object -> receiver task -> comm.
Usage: winfo_analyze.py <threads/ports files...>
"""
import re, sys, bisect, struct, os

IDX = "/root/i9100d/assets/ios6-extract/dyld6_syms.bin"
_tab = None
def load():
    global _tab
    if _tab: return _tab
    try: d = open(IDX, "rb").read()
    except OSError: _tab = ([], []); return _tab
    n = struct.unpack_from("<I", d, 0)[0]
    addrs = []
    for i in range(n):
        v, _ = struct.unpack_from("<II", d, 4 + i * 8)
        addrs.append(v)
    tags = [t.decode("utf8", "replace")
            for t in d[4 + n * 8:].split(b"\0")]
    _tab = (addrs, tags)
    return _tab

def sym(addr):
    addrs, tags = load()
    i = bisect.bisect_right(addrs, addr) - 1
    if i < 0 or addr - addrs[i] > 0x400: return None
    return "%s+0x%x" % (tags[i], addr - addrs[i]) if addr != addrs[i] else tags[i]

proc_by_ptr = {}    # int(proc ptr) -> (pid, comm)
task2pid    = {}    # int(task ptr) -> (pid, comm)
spaces      = {}    # int(task ptr) -> {name: (rt, obj, rtsk_int)}
threads     = []    # (comm, pid, thr, ist, iobj, rnam, cont, pc, r12, lr)

for path in sys.argv[1:]:
    base = os.path.basename(path)
    is_ports = base.startswith("ports") or 'ports' in base.split('-')
    pid = comm = None
    task_ptr = 0
    entries = {}
    last_uth = None
    for line in open(path, errors="replace"):
        m = re.match(r"proc\s+(\d+)\s+(\S+)\s+p=(0x[0-9a-f]+)(?:\s+task=(0x[0-9a-f]+))?", line)
        if m:
            pid, comm = int(m.group(1)), m.group(2)
            proc_by_ptr[int(m.group(3), 16)] = (pid, comm)
            if m.group(4):
                task_ptr = int(m.group(4), 16)
                task2pid[task_ptr] = (pid, comm)
                entries = {}
                spaces[task_ptr] = entries
            continue
        if not is_ports:
            m = re.match(r"uth=(0x[0-9a-f]+)\s+thr=(0x[0-9a-f]+)", line)
            if m:
                last_uth = (m.group(1), m.group(2), pid, comm)
                continue
            m = re.search(r"ist=([0-9a-f]+)\s+iobj=(0x[0-9a-f]+)\s+rnam=([0-9a-f]+)"
                          r"\s+cont=(0x[0-9a-f]+)\s+pc=([0-9a-f]+)\s+r12=([0-9a-f]+)"
                          r"\s+lr=([0-9a-f]+)", line)
            if m and last_uth:
                uth, thr, ppid, pcomm = last_uth
                threads.append((pcomm, ppid, thr,
                    int(m.group(1), 16), int(m.group(2), 16),
                    int(m.group(3), 16), int(m.group(4), 16),
                    int(m.group(5), 16), int(m.group(6), 16),
                    int(m.group(7), 16)))
            continue
        m = re.match(r"pn=([0-9a-f]+)\s+rt=(\w+)\s+obj=(0x[0-9a-f]+)"
                     r"(?:\s+rsp=(0x[0-9a-f]+)\s+rtsk=(0x[0-9a-f]+))?", line)
        if m and is_ports:
            name = int(m.group(1), 16)
            rtsk = int(m.group(5), 16) if m.group(5) else 0
            entries[name] = (m.group(2), m.group(3), rtsk)

for pcomm, ppid, thr, ist, iobj, rnam, cont, pc, r12, lr in threads:
    wait = ""
    if ist == 0x10004001:
        hit = None
        for tp, ents in spaces.items():
            if task2pid.get(tp, (None,))[0] == ppid and rnam in ents:
                hit = (ents[rnam], task2pid[tp]); break
        if hit:
            rt, obj, rtsk = hit[0]
            who = task2pid.get(rtsk)
            wait = " => RECV pn=%x (%s obj=%s) held by %s" % (
                rnam, rt, obj,
                ("%s[%d]" % (who[1], who[0])) if who else
                ("task 0x%x" % rtsk if rtsk else "?"))
        else:
            wait = " => RECV pn=%x (not in dumped space)" % rnam
    elif ist:
        wait = " => ist=%x" % ist
    print("%-16s[%d] thr=%s pc=%-42s lr=%s%s" % (
        pcomm, ppid, thr,
        sym(pc) or hex(pc), sym(lr) or hex(lr), wait))
