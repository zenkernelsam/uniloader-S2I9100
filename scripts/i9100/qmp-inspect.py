#!/usr/bin/env python3
"""Run a bounded QMP/HMP observation against a known local emulator."""
import argparse
import json
from pathlib import Path
import socket

p = argparse.ArgumentParser()
p.add_argument('--socket-file', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('commands', nargs='+')
a = p.parse_args()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(a.socket_file.read_text().strip())
f = s.makefile('rwb', buffering=0)
greeting = json.loads(f.readline())

def call(command, arguments=None):
    obj = {'execute': command}
    if arguments is not None:
        obj['arguments'] = arguments
    f.write((json.dumps(obj) + '\n').encode())
    while True:
        line = f.readline()
        if not line:
            raise ConnectionError('QMP connection closed before a response')
        msg = json.loads(line)
        if 'return' in msg or 'error' in msg:
            return msg

call('qmp_capabilities')
result = {'greeting': greeting, 'status': call('query-status'), 'commands': []}
a.output.write_text(json.dumps(result, indent=2) + '\n')
for command in a.commands:
    entry = {'command': command}
    result['commands'].append(entry)
    try:
        entry['result'] = call('human-monitor-command', {'command-line': command})
    except Exception as error:
        entry['error'] = str(error)
        a.output.write_text(json.dumps(result, indent=2) + '\n')
        raise
    a.output.write_text(json.dumps(result, indent=2) + '\n')
a.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
s.close()
