#!/usr/bin/env python3
"""Capture the real S2 scanout through one BUILD-verified serial session."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def png_bgrx(raw, width, height, stride):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        row = raw[y * stride:y * stride + width * 4]
        for x in range(0, len(row), 4):
            rows.extend((row[x + 2], row[x + 1], row[x]))
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))


def main():
    f = module('frame_forensic', 'forensic-session.py')
    m = module('frame_memory', 'live-memory.py')
    o = module('frame_odin', 'odin-loop.py')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--chunk-bytes', type=int, choices=(4096,8192,16384,32768), default=32768,
                   help='Maximum bytes per DATA command; smaller blocks limit each transfer burst')
    a = p.parse_args()
    symbols = m.Symbols(a.kernel)
    out = o.confined(a.output, f.REPO / 'out')
    o.require(not out.exists(), 'Fresh output directory required')
    profile = json.loads((f.REPO / 'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device = o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location']) == profile['location'], 'No approved live CDC')
        out.mkdir(parents=True)
        transport = None
        captured = 0
        with (out / 'events.jsonl').open('x') as events, (out / 'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row) + '\n')
                events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'STOP', 'DONE'):
                    print(json.dumps(row), flush=True)
            try:
                transport = f.WinTransport(device['port'], record)
                session = f.Session(transport, symbols.tag, record, capture, timeout=20)
                session.handshake()
                kernel = m.Kernel(session, symbols)
                # PE_state.initialized is a 32-bit boolean; PE_Video follows
                # with five unsigned long fields in this ARM32 kernel.
                base, stride, width, height, depth = struct.unpack('<5I', kernel.read(symbols['_PE_state'] + 4, 20))
                o.require((width, height, depth, stride) == (480, 800, 32, 1920), 'Unexpected S2 scanout geometry')
                physical = kernel.u32(symbols['_i9100_fb_physical'])
                total = height * stride
                o.require(0x40000000 <= physical < physical + total <= 0x80000000, 'Scanout outside DRAM')
                before = kernel.read(symbols['_i9100_graphics_seq'], 8)
                console = kernel.u32(symbols['_i9100_panel_console_enabled'])
                raw = bytearray()
                with (out/'framebuffer.partial.bin').open('xb') as partial:
                    for offset in range(0, total, a.chunk_bytes):
                        block=kernel.read_phys(physical + offset,min(a.chunk_bytes,total-offset))
                        raw.extend(block)
                        partial.write(block);partial.flush()
                        captured+=len(block)
                after = kernel.read(symbols['_i9100_graphics_seq'], 8)
                png = png_bgrx(raw, width, height, stride)
                (out / 'framebuffer.bin').write_bytes(raw)
                (out / 'framebuffer.png').write_bytes(png)
                result = dict(tag=symbols.tag, device=device, physical=hex(physical), mapped_base=hex(base),
                              width=width, height=height, stride=stride, depth=depth, format='BGRX32',
                              console=console, sequence_before=struct.unpack('<Q', before)[0],
                              sequence_after=struct.unpack('<Q', after)[0], coherent=before == after,
                              bytes=len(raw), chunk_bytes=a.chunk_bytes, raw_sha256=hashlib.sha256(raw).hexdigest(),
                              png_sha256=hashlib.sha256(png).hexdigest())
                (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps(result, indent=2), flush=True)
                record('DONE', coherent=result['coherent'])
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False, partial_bytes=captured,
                       chunk_bytes=a.chunk_bytes)
                raise
            finally:
                if transport is not None:
                    transport.close()


if __name__ == '__main__':
    main()
