#!/usr/bin/env python3
"""Audit project-local original MFCv5.1 firmware; no device contact or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from datetime import datetime

ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT / "uniloader-S2I9100"


def cap():
    if os.name != "posix":
        raise RuntimeError("Run under the project's WSL CPU envelope")
    if os.environ.get("I9100_CPU_CAPPED") != "1":
        os.execvpe("taskset", ["taskset", "-c", "0-13", "nice", "-n10", "ionice", "-c2", "-n7",
                              sys.executable, "-B", *sys.argv], dict(os.environ, I9100_CPU_CAPPED="1"))
    if set(os.sched_getaffinity(0)) - set(range(14)) or os.getpriority(os.PRIO_PROCESS, 0) < 10:
        raise RuntimeError("CPU envelope missing")


def source(path, limit):
    path = path.resolve()
    if not path.is_relative_to(ROOT) or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Use a bounded source file inside the project")
    data = path.read_bytes()
    if len(data) > limit:
        raise ValueError("Source grew while reading")
    return data, {"path": str(path.relative_to(ROOT)), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def plan(system, stream_bytes):
    # The C driver owns this exact layout; equality is checked by its model.
    context = system
    shared = (context + 0x96000 + 4095) & ~4095
    descriptor = (shared + 4096 + 2047) & ~2047
    stream = (descriptor + 0x20000 + 2047) & ~2047
    return dict(system_bytes=system, context_offset=context, context_bytes=0x96000,
                shared_offset=shared, shared_bytes=4096, descriptor_offset=descriptor,
                descriptor_bytes=0x20000, stream_offset=stream, stream_capacity=0x400000,
                stream_bytes=stream_bytes, end_offset=stream + 0x400000)


def prepare(a):
    if not a.source_note.strip():
        raise ValueError("Original firmware and controller provenance note required")
    firmware, fm = source(a.firmware, 0x80000)
    raw, pm = source(a.controller_proof, 65536)
    proof = json.loads(raw)
    model = proof.get("model_fixture") is True
    system = proof.get("system_bytes")
    version = proof.get("firmware_version")
    required = {"soc", "mfc_revision", "system_bytes", "firmware_version", "firmware_sha256", "source_note", "model_fixture"}
    if set(proof) != required or proof["soc"] != "exynos4210" or proof["mfc_revision"] != "0x51":
        raise ValueError("Require the exact Exynos4210 MFCv5.1 proof schema")
    if type(system) is not int or system not in (0x60000, 0x80000) or len(firmware) > system:
        raise ValueError("Reviewed system reservation must be 384 or 512KiB, independently of file length")
    if type(version) is not int or not 0 < version < 0xffffffff or proof["firmware_sha256"] != fm["sha256"]:
        raise ValueError("Version must be actual recorded firmware identity, with matching original SHA256")
    if type(proof["model_fixture"]) is not bool or not isinstance(proof["source_note"], str) or not proof["source_note"].strip():
        raise ValueError("Explicit source attribution and model marker required")
    if a.mark_reviewed and model:
        raise ValueError("Model firmware/controller data cannot become hardware reviewed")
    if not 10 <= a.timeout_ms <= 5000:
        raise ValueError("Protocol deadline outside the supported range")
    bitstream = None
    bitstream_manifest = None
    if a.annexb_stream:
        bitstream, bitstream_manifest = source(a.annexb_stream, 0x400000)
        if len(bitstream) < 5 or not bitstream.startswith((b"\0\0\1", b"\0\0\0\1")):
            raise ValueError("Header input must start with a bounded Annex-B start code")
    output = a.output.resolve() if a.output else REPO / "out" / ("mfc-firmware-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not output.is_relative_to(REPO / "out") or output.exists():
        raise ValueError("Use a fresh retained loader out directory")
    profile = dict(board_data_reviewed=int(a.mark_reviewed), system_bytes=system, firmware_bytes=len(firmware),
                   expected_version=version, timeout_ms=a.timeout_ms, sha256=fm["sha256"])
    layout = plan(system, len(bitstream)) if bitstream else None
    if layout and layout["end_offset"] > 8388608:
        raise ValueError("Header layout exceeds the private 8MiB bankA")
    result = dict(schema=1, kind="i9100-mfcv51-firmware-header", hardware_tested=False, device_contacted=False,
                  board_data_reviewed=bool(a.mark_reviewed), model_fixture=model, source_note=a.source_note,
                  profile=profile, inputs=dict(firmware=fm, controller_proof=pm, annexb_stream=bitstream_manifest),
                  header_plan=layout, native_bank_bytes=[8388608, 1048576], native_alignment=131072,
                  preparer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  requirements="Real owned MFC supply/clock/identity and both SYSMMUs, matching actual version/profile; no production activation by this tool")
    output.mkdir(parents=True)
    (output / "mfc_fw.bin").write_bytes(firmware)
    (output / "controller-proof.source.json").write_bytes(raw)
    if bitstream:
        (output / "header.annexb").write_bytes(bitstream)
    (output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    if hashlib.sha256((output / "mfc_fw.bin").read_bytes()).hexdigest() != fm["sha256"]:
        raise RuntimeError("Retained firmware copy changed")
    return output, result


def main():
    cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firmware", type=Path, required=True)
    p.add_argument("--controller-proof", type=Path, required=True)
    p.add_argument("--annexb-stream", type=Path)
    p.add_argument("--source-note", required=True)
    p.add_argument("--timeout-ms", type=int, default=500)
    p.add_argument("--mark-reviewed", action="store_true")
    p.add_argument("--output", type=Path)
    output, result = prepare(p.parse_args())
    print(json.dumps(dict(output=str(output), profile=result["profile"], hardware_tested=False,
                          device_contacted=False, model_fixture=result["model_fixture"]), indent=2))


if __name__ == "__main__":
    main()
