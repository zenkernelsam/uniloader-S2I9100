"""i9sess.py - persistent I9CTL session over the CDC serial port.

One handle stays open the whole run so Windows keeps an IN reader on the
pipe (device-side TX completes only while usbser holds read URBs).
Commands retry until a reply line arrives: retries use a fresh seq each
time because a dropped mid-line command is expected under console load.

usage: py i9sess.py COM12 <out-prefix> <cmd> [<cmd> ...]
  <cmd> is either a bare verb (threads backboardd) or secs:<n> to sleep.
"""
import ctypes, sys, time, re
from ctypes import wintypes as W

k = ctypes.windll.kernel32


def open_port(port):
    h = k.CreateFileW('\\\\.\\' + port, 0xC0000000, 0, None, 3, 0, None)
    if h == ctypes.c_void_p(-1).value:
        raise RuntimeError('CreateFile failed for ' + port)
    k.EscapeCommFunction(h, 5)  # SETDTR
    k.EscapeCommFunction(h, 3)  # SETRTS
    return h


class Sess(object):
    def __init__(self, h, log):
        self.h = h
        self.log = log          # file for all raw bytes
        self.buf = b''
        self.seq = (int(time.time()) & 0x3fffffff) + 1

    def pump(self, secs):
        n = W.DWORD()
        tmp = ctypes.create_string_buffer(65536)
        end = time.time() + secs
        while time.time() < end:
            if not k.ReadFile(self.h, tmp, 65536, ctypes.byref(n), None):
                break
            if n.value:
                chunk = tmp.raw[:n.value]
                self.buf += chunk
                self.log.write(chunk)
                self.log.flush()

    def send(self, verb):
        self.seq += 1
        line = 'I9CTL1 %08x %s\n' % (self.seq, verb)
        n = W.DWORD()
        b = line.encode()
        k.WriteFile(self.h, b, len(b), ctypes.byref(n), None)
        return self.seq

    def run_cmd(self, verb, timeout=120):
        """Send verb; retry every 4s until its reply line shows up.

        Reply format: '\\nI9CTL1 <seq> <answer...>\\n'.  DATA replies are
        'OK DATA <addr8> <len8>' followed by <len> payload bytes on the
        same stream.  We return (hdr_bytes, payload_bytes)."""
        want_seq = self.send(verb)
        hdr_re = re.compile(rb'I9CTL1 %08x ' % want_seq)
        t0 = time.time()
        last_send = t0
        mark = len(self.buf)
        payload = b''
        while time.time() - t0 < timeout:
            self.pump(1.0)
            # resend periodically - bytes can be swallowed mid-line
            if time.time() - last_send > 4:
                last_send = time.time()
                want_seq2 = self.send(verb)
                hdr_re = re.compile(rb'I9CTL1 %08x ' % want_seq2)
                want_seq = want_seq2
            m = hdr_re.search(self.buf, mark)
            if not m:
                continue
            tail = self.buf[m.end():]
            nl = tail.find(b'\n')
            if nl < 0:
                continue
            ans = tail[:nl].strip()
            sys.stderr.write('[%s] %r\n' % (verb, ans))
            dm = re.match(rb'OK DATA ([0-9a-f]{8}) ([0-9a-f]{8})', ans)
            if not dm:
                return ans, b''
            dlen = int(dm.group(2), 16)
            have = tail[nl + 1:]
            while len(have) < dlen and time.time() - t0 < timeout:
                self.pump(2.0)
                m2 = hdr_re.search(self.buf, mark)
                if m2 is None:
                    break
                tail = self.buf[m2.end():]
                nl2 = tail.find(b'\n')
                have = tail[nl2 + 1:] if nl2 >= 0 else b''
            return ans, have[:dlen]
        return None, b''


def main():
    port, prefix = sys.argv[1], sys.argv[2]
    cmds = sys.argv[3:]
    h = open_port(port)
    logf = open(prefix + '-console.bin', 'wb')
    s = Sess(h, logf)
    sys.stderr.write('session on %s, warm-up listen 3s\n' % port)
    s.pump(3)
    for i, c in enumerate(cmds):
        if c.startswith('secs:'):
            s.pump(float(c[5:]))
            continue
        ans, payload = s.run_cmd(c)
        tag = re.sub(r'[^A-Za-z0-9]+', '-', c).strip('-')
        open(prefix + '-' + tag + '.hdr', 'wb').write(ans or b'')
        open(prefix + '-' + tag + '.bin', 'wb').write(payload)
        sys.stderr.write('saved %s: hdr=%r payload=%d\n' %
                         (c, ans, len(payload)))
    s.pump(2)
    h and k.CloseHandle(h)
    logf.close()


if __name__ == '__main__':
    main()
