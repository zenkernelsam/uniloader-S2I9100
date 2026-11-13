"""watch9.py - overnight CDC watcher.

Polls PnP every 5s for the i9100 CDC composite. Whenever a usable COM
port for it materialises (cable replug, self-heal reconnect, fresh
boot), waits for the port to settle then runs a persistent i9sess
capture of the forensic verbs.  Safe: only read-only verbs are sent.

usage: py watch9.py
"""
import ctypes, re, subprocess, sys, time
from ctypes import wintypes as W
from pathlib import Path

cfg = ctypes.windll.cfgmgr32
k = ctypes.windll.kernel32
CR_SUCCESS = 0
HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / 'out' / 'forensic'

VERBS = [
    'ping', 'root-status',
    'threads backboardd', 'ports backboardd',
    'threads SpringBoard', 'ports SpringBoard',
    'threads launchd', 'ports launchd',
]


def devinst_id(dn):
    buf = ctypes.create_unicode_buffer(512)
    if cfg.CM_Get_Device_IDW(W.DWORD(dn), buf, 512, 0) != CR_SUCCESS:
        return ''
    return buf.value


def com_of_devinst(dn):
    """Return 'COMn' for a usbser devnode, else ''."""
    # COM port name lives in the device friendly name or PortName prop
    buf = ctypes.create_unicode_buffer(256)
    size = W.ULONG(512)
    t = W.ULONG(0)
    # CM_DRP_DEVICEDESC = 1
    if cfg.CM_Get_DevNode_Registry_PropertyW(
            W.DWORD(dn), 1, ctypes.byref(t), buf,
            ctypes.byref(size), 0) == CR_SUCCESS:
        m = re.search(r'\(COM(\d+)\)', buf.value)
        if m:
            return 'COM' + m.group(1)
    # CM_DRP_FRIENDLYNAME = 0x0c
    if cfg.CM_Get_DevNode_Registry_PropertyW(
            W.DWORD(dn), 0x0C, ctypes.byref(t), buf,
            ctypes.byref(size), 0) == CR_SUCCESS:
        m = re.search(r'\(COM(\d+)\)', buf.value)
        if m:
            return 'COM' + m.group(1)
    return ''


def find_coms():
    """Devnodes whose parent instance id is the i9100 composite."""
    root = W.DWORD()
    if cfg.CM_Locate_DevNodeW(ctypes.byref(root), None, 0) != CR_SUCCESS:
        return []
    targets, all_d = [], []
    stack = [root.value]
    seen = set()
    while stack:
        dn = stack.pop()
        if dn in seen:
            continue
        seen.add(dn)
        all_d.append(dn)
        iid = devinst_id(dn)
        if 'S2I9100' in iid or 'VID_0525&PID_A4A7' in iid:
            targets.append(dn)
        sib = W.DWORD()
        if cfg.CM_Get_Sibling(ctypes.byref(sib), W.DWORD(dn), 0) == CR_SUCCESS:
            stack.append(sib.value)
        ch = W.DWORD()
        if cfg.CM_Get_Child(ctypes.byref(ch), W.DWORD(dn), 0) == CR_SUCCESS:
            stack.append(ch.value)
    coms = []
    for t in targets:
        # walk children of composite for usbser nodes carrying (COMn)
        ch = W.DWORD()
        if cfg.CM_Get_Child(ctypes.byref(ch), W.DWORD(t), 0) == CR_SUCCESS:
            node = ch.value
            while node:
                c = com_of_devinst(node)
                if c:
                    coms.append(c)
                sib = W.DWORD()
                if cfg.CM_Get_Sibling(ctypes.byref(sib), W.DWORD(node),
                                      0) != CR_SUCCESS:
                    break
                node = sib.value
    return sorted(set(coms), key=lambda s: int(s[3:]))


def port_alive(port):
    h = k.CreateFileW('\\\\.\\' + port, 0xC0000000, 0, None, 3, 0, None)
    if h == ctypes.c_void_p(-1).value:
        return False
    k.CloseHandle(h)
    return True


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    seen = {}
    print('watching for i9100 CDC...', flush=True)
    while True:
        coms = find_coms()
        for com in coms:
            if seen.get(com) == 'captured':
                continue
            # new or re-appeared port -> settle then capture
            print('%s found %s, settling 4s' %
                  (time.strftime('%H:%M:%S'), com), flush=True)
            time.sleep(4)
            if not port_alive(com):
                print('  %s not openable yet, will retry' % com, flush=True)
                continue
            tag = time.strftime('%Y%m%d-%H%M%S')
            prefix = str(OUT / ('w9-%s-%s' % (tag, com)))
            print('  capturing on %s -> %s' % (com, prefix), flush=True)
            r = subprocess.run(
                [sys.executable, str(HERE / 'i9sess.py'), com, prefix]
                + VERBS, capture_output=True, text=True, timeout=900)
            (OUT / ('w9-%s-%s.log' % (tag, com))).write_text(
                (r.stdout or '') + (r.stderr or ''))
            seen[com] = 'captured'
            print('  done', flush=True)
        # forget ports that vanished so a replug re-captures
        for com in list(seen):
            if com not in coms:
                del seen[com]
        time.sleep(5)


if __name__ == '__main__':
    main()
