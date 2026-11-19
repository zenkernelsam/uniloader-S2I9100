#!/usr/bin/env python3
"""Verify retained MFC asset preparation and compare its layout to actual C-core evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from datetime import datetime

SCRIPT = Path(__file__).resolve().with_name("prepare-mfc-firmware.py")
spec = importlib.util.spec_from_file_location("mfc_prepare", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def main():
    module.cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core-model", type=Path, required=True)
    a = p.parse_args()
    core = a.core_model.resolve()
    xnu = module.ROOT / "xnu-S2I9100"
    if not core.is_relative_to(xnu / "out"):
        raise RuntimeError("Require retained XNU core-model evidence")
    cm = json.loads((core / "manifest.json").read_text())
    if cm.get("result") != "PASS" or cm.get("hardware_tested") is not False or cm.get("models") != "i9100_camera_mfc_test.c":
        raise RuntimeError("Require actual current MFC model success")
    for name, expected in cm["sources"].items():
        if hashlib.sha256((xnu / "iokit/Drivers/KernelBuiltIn/ARM/AppleARMPlatform" / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Core evidence source changed")
    if hashlib.sha256((xnu / "port-tests" / cm["models"]).read_bytes()).hexdigest() != cm["models_sha256"]:
        raise RuntimeError("Core model fixture changed")
    raw_core = (core / "mfc-core.json").read_bytes()
    layout = json.loads(raw_core)
    if layout.get("model_fixture") is not True:
        raise RuntimeError("Core output must retain its model provenance")
    out = module.REPO / "out" / ("mfc-firmware-check-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    out.mkdir()
    firmware = bytes((k * 13 + 7) & 255 for k in range(262144))
    image = out / "fixture.bin"
    image.write_bytes(firmware)
    stream = out / "fixture.annexb"
    stream.write_bytes(bytes.fromhex("000000016742001ef40501ec80"))
    proof = dict(soc="exynos4210", mfc_revision="0x51", system_bytes=0x80000, firmware_version=0x211116,
                 firmware_sha256=hashlib.sha256(firmware).hexdigest(), model_fixture=True,
                 source_note="Explicit offline random-byte fixture and modeled controller; not original hardware firmware")
    proof_path = out / "proof.json"
    proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    args = argparse.Namespace(firmware=image, controller_proof=proof_path, annexb_stream=stream,
                              source_note=proof["source_note"], timeout_ms=500, mark_reviewed=False, output=out / "prepared")
    prepared, manifest = module.prepare(args)
    if manifest["header_plan"] != layout["plan"] or manifest["profile"]["sha256"] != layout["firmware_sha256"]:
        raise RuntimeError("Actual C plan/staged firmware differs from host preparation")
    if manifest["board_data_reviewed"] or not manifest["model_fixture"] or manifest["profile"]["board_data_reviewed"]:
        raise RuntimeError("Fixture became production reviewed")
    failures = []
    args.output = out / "must-not-exist"
    args.mark_reviewed = True
    try:
        module.prepare(args)
    except ValueError:
        failures.append("model-cannot-be-reviewed")
    else:
        raise RuntimeError("Model review was allowed")
    args.mark_reviewed = False
    proof["system_bytes"] = 262144
    proof_path.write_text(json.dumps(proof))
    try:
        module.prepare(args)
    except ValueError:
        failures.append("file-length-is-not-system-reservation")
    else:
        raise RuntimeError("File length became system reservation")
    if args.output.exists():
        raise RuntimeError("Rejected proof created an output")
    result = dict(result="PASS", hardware_tested=False, device_contacted=False, failures=failures,
                  core_model=str(core.relative_to(module.ROOT)), core_manifest_sha256=hashlib.sha256((core / "manifest.json").read_bytes()).hexdigest(),
                  core_output_sha256=hashlib.sha256(raw_core).hexdigest(),
                  preparer_sha256=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), prepared=str(prepared.relative_to(module.ROOT)))
    (out / "test-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS default-unreviewed/model rejection + actual C layout/SHA;", out)


if __name__ == "__main__":
    main()
