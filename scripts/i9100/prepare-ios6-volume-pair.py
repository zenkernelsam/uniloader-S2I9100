#!/usr/bin/env python3
"""Bind verified raw HFS root/data candidates to historical slice roles; no deployment."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from datetime import datetime

SCRIPT = Path(__file__).resolve().with_name("audit-ios6-volume-split.py")
spec = importlib.util.spec_from_file_location("volume_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
ROOT, REPO = audit.ROOT, audit.REPO


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def image(folder, role, filename, capacity):
    folder = folder.resolve()
    if not folder.is_relative_to(REPO / "out"):
        raise ValueError("Volume candidate escaped retained loader out")
    preparation = json.loads((folder / "preparation.json").read_text())
    if preparation.get("result") != "PASS" or preparation.get("hardware_tested") is not False or preparation.get("device_contacted") is not False:
        raise ValueError("Require actual successful offline raw-volume preparation")
    source_tool = "build-ios6-system-volume.py" if role == "system" else "build-ios6-data-volume.py"
    if sha(Path(__file__).with_name(source_tool)) != preparation["builder_sha256"]:
        raise ValueError("Volume preparation source changed; do not wash an older PASS")
    verify_bytes = (folder / "metadata-verification.json").read_bytes()
    if hashlib.sha256(verify_bytes).hexdigest() != preparation["metadata_verification_sha256"]:
        raise ValueError("Metadata verification evidence changed")
    verified = json.loads(verify_bytes)
    verify_tool = "verify-ios6-system-volume.py" if role == "system" else "verify-ios6-data-volume.py"
    if verified.get("result") != "PASS" or sha(Path(__file__).with_name(verify_tool)) != verified["verifier_sha256"]:
        raise ValueError("Verifier source/result changed")
    path = folder / filename
    hfs = audit.HFS(path)
    try:
        if hfs.bytes != capacity or path.stat().st_size != capacity:
            raise ValueError("Raw HFS does not exactly fit its historical target slice")
        journaled = bool(struct.unpack_from(">I", hfs.header, 4)[0] & 0x2000)
        if role == "data" and not journaled:
            raise ValueError("Data candidate is not journaled")
        full = hashlib.sha256()
        chunks = []
        with path.open("rb") as file:
            offset = 0
            while offset < capacity:
                raw = file.read(min(16 * 1024 * 1024, capacity - offset))
                if not raw:
                    raise ValueError("Short raw volume read")
                full.update(raw)
                chunks.append(dict(offset=offset, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
                offset += len(raw)
        return dict(role=role, path=str(path.relative_to(ROOT)), bytes=capacity, sha256=full.hexdigest(),
                    hfsx=hfs.signature == 0x4858, journaled=journaled,
                    mount_path="/" if role == "system" else "/private/var", read_only=role == "system",
                    preparation_sha256=sha(folder / "preparation.json"), metadata_verification_sha256=hashlib.sha256(verify_bytes).hexdigest(),
                    chunk_bytes=16 * 1024 * 1024, chunks=chunks)
    finally:
        hfs.close()


def main():
    audit.cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--system", type=Path, required=True)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    out = a.output.resolve() if a.output else REPO / "out" / ("ios6-volume-pair-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not out.is_relative_to(REPO / "out") or out.exists():
        raise ValueError("Use fresh retained pair evidence")
    partitions = ROOT / "research/I9100-INTERNAL-PARTITION-AUDIT-20261106.json"
    report = json.loads(partitions.read_text())
    selected = {p["name"]: p for p in report["partitions"] if p["name"] in ("FACTORYFS", "DATAFS")}
    if report["source_sha256"] != "879334a928bbffffc67d57b584906c03bee10f1310a88a0f1362fc6dfb3724ef" or selected["FACTORYFS"]["start_lba"] != 344064 or selected["DATAFS"]["start_lba"] != 3489792:
        raise ValueError("Historical handset partition facts differ")
    system = image(a.system, "system", "FACTORYFS.HFS", selected["FACTORYFS"]["bytes"])
    data = image(a.data, "data", "DATAFS.HFS", selected["DATAFS"]["bytes"])
    for name, volume in (("FACTORYFS", system), ("DATAFS", data)):
        volume["historical_target"] = selected[name]
    result = dict(schema=1, result="PASS", hardware_tested=False, device_contacted=False, deployment_authorized=False,
                  historical_partition_evidence=dict(path=str(partitions.relative_to(ROOT)), sha256=sha(partitions)),
                  system=system, data=data, source_rootfs_sha256=json.loads((a.system / "preparation.json").read_text())["source_volume_sha256"],
                  preparer_sha256=sha(Path(__file__)), boot_ready=False,
                  requires=["Current actual CID/EXT_CSD/both GPTs/PIT and complete rollback backups",
                            "Real readonly root and writable data slice publication, current-media stable aliases",
                            "Mandatory data mount before launchd writes; no fallback to root directory",
                            "HFS journal/card-cache synchronization and orderly reboot worker",
                            "Separate explicit raw-volume deployment approval; existing Odin loop stays KERNEL-only"])
    out.mkdir(parents=True)
    (out / "pair-manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(result="PASS", output=str(out), system_sha256=system["sha256"], data_sha256=data["sha256"],
                          boot_ready=False, deployment_authorized=False), indent=2))


if __name__ == "__main__":
    main()
