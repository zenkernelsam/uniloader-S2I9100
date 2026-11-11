#!/usr/bin/env python3
"""Decode an actual old abort snapshot and the versioned16-frame extension.

The memory transport is modeled; importing the production parser opens no COM.
Evidence stays in a new loader out directory without cleanup/deletion.
"""
from pathlib import Path
from datetime import datetime
import contextlib
import importlib.util
import io
import struct

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('abort_parser', Path(__file__).with_name('inspect-mdns.py'))
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)
legacy = (REPO / 'out/forensic/springboard-20261111-0843-query-proof/backboard_abort-observation.bin').read_bytes()
assert len(legacy) == 336
out = REPO / 'out' / ('abort-framing-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
out.mkdir()


class Symbols:
    def __init__(self, frames):
        self.values = {'_i9100_backboard_abort_observation': 0x1000}
        if frames is not None:
            self.values['_i9100_abort_frames'] = 0x2000

    def __getitem__(self, name):
        return self.values[name]


class Memory:
    def __init__(self, data, frames):
        self.data, self.frames, self.reads = data, frames, []

    def read(self, address, length):
        self.reads.append((address, length))
        assert address == 0x1000 and length == len(self.data)
        return self.data

    def u32(self, address):
        assert address == 0x2000
        return self.frames


def decode(label, raw, frames):
    destination = out / label
    destination.mkdir()
    memory = Memory(raw, frames)
    with contextlib.redirect_stdout(io.StringIO()):
        result = parser.capture_ui_observations(memory, Symbols(frames), destination)
    return result['backboard_abort'], memory


old, _ = decode('actual-legacy', legacy, None)
assert old['text'].startswith('Assertion failed: (slab->magic') and old['count'] == 8
extra = [0x31000101+4*n for n in range(8)]
extended = bytearray(legacy[:68]+struct.pack('<8I', *extra)+legacy[68:])
struct.pack_into('<I', extended, 28, 16)
new, _ = decode('versioned-16', bytes(extended), 16)
for key in ('pid', 'task', 'pc', 'lr', 'slab', 'slab_object', 'slab_expected', 'slab_actual', 'text_kind', 'text'):
    assert new[key] == old[key], key
assert new['count'] == 16
for n in range(8):
    assert new['frame'+str(n)] == old['frame'+str(n)]
    assert new['frame'+str(n+8)] == extra[n]
for frames in (0, 9, 32):
    try:
        decode('invalid-schema-'+str(frames), legacy, frames)
        raise AssertionError('Invalid abort schema was accepted')
    except ValueError as error:
        assert str(error) == 'Unknown retained abort frame layout'
bad_count = bytearray(extended)
struct.pack_into('<I', bad_count, 28, 17)
try:
    decode('invalid-count', bytes(bad_count), 16)
    raise AssertionError('Overflowing retained count was accepted')
except ValueError as error:
    assert str(error) == 'Retained abort count exceeds its schema'
print('PASS actual legacy/extended abort text and frame offsets; invalid schemas/count rejected; memory transport modeled')
print('EVIDENCE', out)
