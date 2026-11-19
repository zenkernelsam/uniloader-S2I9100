#!/usr/bin/env python3
"""Verify the rebuilt system keeps all retained metadata/forks and mandates the data mount."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib
from datetime import datetime

VERIFY_DATA = Path(__file__).resolve().with_name("verify-ios6-data-volume.py")
spec = importlib.util.spec_from_file_location("verify_data", VERIFY_DATA)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
audit = verifier.audit
ROOT, REPO = verifier.ROOT, verifier.REPO
FSTAB = (b"/dev/i9100-system / hfs ro 0 1\n"
         b"/dev/i9100-data /private/var hfs rw,nosuid,nodev 0 2\n")


def verify(source, system):
    checked = audit.audit(source, ROOT / "research/I9100-INTERNAL-PARTITION-AUDIT-20261106.json")
    original, original_threads = verifier.entries(source)
    target, target_threads = verifier.entries(system)
    excluded = {e["cnid"] for e in checked["catalog"] if e["path"].startswith("/private/var/")}
    mount = next(e for e in checked["catalog"] if e["path"] == "/private/var")
    fstab = next(e for e in checked["catalog"] if e["path"] == "/private/etc/fstab")
    if set(target) != set(original) - excluded or set(target_threads) != set(original_threads) - excluded:
        raise ValueError("Missing/extra system CNIDs or data subdirectory survived the split")
    fork_hashes = hashlib.sha256()
    metadata_hashes = hashlib.sha256()
    files = 0
    for fid, before in original.items():
        if fid in excluded:
            continue
        after = target[fid]
        if before["name"] != after["name"] or before["parent"] != after["parent"] or before["kind"] != after["kind"]:
            raise ValueError("System name/parent/kind mismatch")
        body = bytearray(before["body"])
        if fid == mount["cnid"]:
            struct.pack_into(">I", body, 4, 0)
            struct.pack_into(">I", body, 84, 0)
        if bytes(body) != after["body"] or original_threads[fid] != target_threads[fid]:
            raise ValueError("System catalog metadata/thread changed outside the allowed empty mount")
        metadata_hashes.update(body)
        if before["kind"] == 2:
            for kind, field in ((0, 88), (255, 168)):
                left = verifier.digest_fork(source, before["body"][field:field + 80], fid, kind)
                right = verifier.digest_fork(system, after["body"][field:field + 80], fid, kind)
                if left != right:
                    raise ValueError("System data/resource fork differs")
                fork_hashes.update(struct.pack("<IIQ", fid, kind, left[0]) + bytes.fromhex(left[1]))
            files += 1
        if fid != fstab["cnid"]:
            if sorted(before["attributes"]) != sorted(after["attributes"]):
                raise ValueError("System attribute record changed")
        else:
            attrs = after["attributes"]
            if len(attrs) != 1:
                raise ValueError("Unexpected system fstab attributes")
            raw = attrs[0]
            end = struct.unpack_from(">H", raw)[0] + 2
            length = struct.unpack_from(">I", raw, end + 12)[0]
            value = raw[end + 16:end + 16 + length]
            if value[:4] != b"fpmc" or struct.unpack_from("<IQ", value, 4) != (3, len(FSTAB)) or zlib.decompress(value[16:]) != FSTAB:
                raise ValueError("System fstab does not exactly mandate the paired data volume")
    if system.bytes != 1610612736 or source.bytes != system.bytes:
        raise ValueError("System candidate does not fit the actual FACTORYFS slice")
    return dict(result="PASS", hardware_tested=False, device_contacted=False, deployed=False,
                retained_objects=len(target), removed_data_objects=len(excluded), retained_files_verified=files,
                system_catalog_bytes_preserved=True, system_attributes_preserved_except_exact_fstab=True,
                raw_data_and_resource_forks_verified=True, fork_digest= fork_hashes.hexdigest(),
                metadata_digest=metadata_hashes.hexdigest(), fstab_new=FSTAB.decode(), data_mount_empty=True,
                source_header_sha256=hashlib.sha256(source.header).hexdigest(),
                target_header_sha256=hashlib.sha256(system.header).hexdigest(),
                device_aliases_implemented=False, boot_ready=False)


def main():
    audit.cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, default=ROOT / "assets/releases/ios6-sd-20261106/ROOTFS.HFS")
    p.add_argument("--system-volume", type=Path, required=True)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    out = a.output.resolve() if a.output else REPO / "out" / ("ios6-system-verify-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not out.is_relative_to(REPO / "out") or out.exists():
        raise ValueError("Use fresh retained output")
    source, system = audit.HFS(a.source), audit.HFS(a.system_volume)
    try:
        result = verify(source, system)
    finally:
        source.close()
        system.close()
    result["verifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["data_verifier_sha256"] = hashlib.sha256(VERIFY_DATA.read_bytes()).hexdigest()
    result["system_volume"] = str(a.system_volume.resolve().relative_to(ROOT))
    out.mkdir(parents=True)
    (out / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS all retained system catalog/threads/attributes/raw forks; exact paired fstab;", out)


if __name__ == "__main__":
    main()
