#!/usr/bin/env python3
"""Independently compare rebuilt data-volume metadata and fork bytes to the source HFS."""
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


def entries(image):
    found, threads = {}, {}
    for _, _, record in image.leaves(272):
        end = struct.unpack_from(">H", record)[0] + 2
        parent, units = struct.unpack_from(">IH", record, 2)
        body = record[end:]
        kind = struct.unpack_from(">H", body)[0]
        if kind in (3, 4):
            if parent in threads:
                raise ValueError("Duplicate data-volume thread")
            threads[parent] = body
        elif kind in (1, 2):
            fid = struct.unpack_from(">I", body, 8)[0]
            if fid in found:
                raise ValueError("Duplicate data-volume CNID")
            found[fid] = dict(cnid=fid, parent=parent, name=record[8:end].decode("utf-16be"),
                              body=body, kind=kind, attributes=[])
        else:
            raise ValueError("Unsupported rebuilt catalog record")
    for _, _, record in image.leaves(352):
        fid = struct.unpack_from(">I", record, 4)[0]
        if fid not in found:
            raise ValueError("Rebuilt attribute references absent CNID")
        found[fid]["attributes"].append(record)
    return found, threads


def digest_fork(image, raw, fid, kind):
    f = image.fork(raw, fid, kind)
    h = hashlib.sha256()
    remaining = f["logical_bytes"]
    for extent in f["extents"]:
        span = min(remaining, extent["blocks"] * image.bs)
        offset = extent["block"] * image.bs
        while span:
            amount = min(span, 1024 * 1024)
            data = image.read(offset, amount)
            h.update(data)
            offset += amount
            span -= amount
            remaining -= amount
    if remaining:
        raise ValueError("Fork digest stopped early")
    return f["logical_bytes"], h.hexdigest()


def verify(source, data):
    original = audit.audit(source, ROOT / "research/I9100-INTERNAL-PARTITION-AUDIT-20261106.json")
    selected = [e for e in original["catalog"] if e["path"] == "/private/var" or e["path"].startswith("/private/var/")]
    root = next(e for e in selected if e["path"] == "/private/var")
    data_rows, data_threads = entries(data)
    source_attributes = {}
    for _, _, raw in source.leaves(352):
        fid = struct.unpack_from(">I", raw, 4)[0]
        if fid in {e["cnid"] for e in selected}:
            source_attributes.setdefault(fid, []).append(raw)
    journal = [e for e in data_rows.values() if e["parent"] == 2 and e["name"] in (".journal", ".journal_info_block")]
    if len(journal) != 2 or data.bytes != 6442450944 or not (struct.unpack_from(">I", data.header, 4)[0] & 0x2000):
        raise ValueError("Expected journaled6GiB data volume")
    if len(data_rows) != len(selected) + 2 or len(data_threads) != len(data_rows):
        raise ValueError("Unexpected/missing rebuilt data objects/threads")
    payloads = []
    for src in selected:
        fid = 2 if src["cnid"] == root["cnid"] else src["cnid"]
        dst = data_rows.get(fid)
        if not dst:
            raise ValueError("Missing relocated data CNID")
        parent = 1 if fid == 2 else 2 if src["parent"] == root["cnid"] else src["parent"]
        if dst["parent"] != parent or (fid != 2 and dst["name"] != src["name"]):
            raise ValueError("Data prefix/CNID parent relocation differs")
        original_body = bytearray.fromhex(src["catalog_body_hex"])
        new_body = bytearray(dst["body"])
        # Compare every non-geometric byte, including all dates/BSD flags/
        # permissions/Finder info. Only identity/root counters/fork geometry
        # are allowed to differ; special file data is never normalized away.
        expected = bytearray(original_body)
        struct.pack_into(">I", expected, 8, fid)
        if dst["kind"] == 2:
            struct.pack_into(">H", expected, 2, struct.unpack_from(">H", expected, 2)[0] | 2)
            for kind, field in ((0, 88), (255, 168)):
                old_fork = digest_fork(source, original_body[field:field + 80], src["cnid"], kind)
                new_fork = digest_fork(data, new_body[field:field + 80], fid, kind)
                if old_fork != new_fork:
                    raise ValueError("Data/resource fork differs: " + src["path"])
                payloads.append(dict(path=src["path"], kind=kind, bytes=old_fork[0], sha256=old_fork[1]))
            expected[88:248] = new_body[88:248]
        else:
            struct.pack_into(">I", expected, 4, sum(e["parent"] == src["cnid"] for e in selected) + (2 if fid == 2 else 0))
            struct.pack_into(">I", expected, 84, sum(e["parent"] == src["cnid"] and e["type"] == "directory" for e in selected))
        if new_body != expected:
            raise ValueError("Metadata byte mismatch for " + src["path"])
        thread = data_threads.get(fid)
        if not thread or struct.unpack_from(">I", thread, 4)[0] != parent:
            raise ValueError("Thread parent relocation differs")
        units = struct.unpack_from(">H", thread, 8)[0]
        if thread[10:10 + units * 2].decode("utf-16be") != dst["name"]:
            raise ValueError("Thread name differs")
        original_attrs = []
        for raw in source_attributes.get(src["cnid"], []):
            raw = bytearray(raw)
            struct.pack_into(">I", raw, 4, fid)
            original_attrs.append(bytes(raw))
        if sorted(original_attrs) != sorted(dst["attributes"]):
            raise ValueError("Full original attribute record differs: " + src["path"])
    return dict(result="PASS", hardware_tested=False, device_contacted=False, objects=len(selected),
                original_metadata_bytes_preserved=True, original_attribute_records_preserved=True,
                source_data_root_cnid=root["cnid"], target_data_root_cnid=2,
                target_data_mount="/private/var", raw_forks=payloads, journal_files=2,
                source_header_sha256=hashlib.sha256(source.header).hexdigest(),
                target_header_sha256=hashlib.sha256(data.header).hexdigest())


def main():
    audit.cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, default=ROOT / "assets/releases/ios6-sd-20261106/ROOTFS.HFS")
    p.add_argument("--data-volume", type=Path, required=True)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    out = a.output.resolve() if a.output else REPO / "out" / ("ios6-data-verify-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not out.is_relative_to(REPO / "out") or out.exists():
        raise ValueError("Use fresh retained verifier output")
    source, data = audit.HFS(a.source), audit.HFS(a.data_volume)
    try:
        result = verify(source, data)
    finally:
        source.close()
        data.close()
    result.update(verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  auditor_sha256=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                  data_volume=str(a.data_volume.resolve().relative_to(ROOT)))
    out.mkdir(parents=True)
    (out / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS original metadata bytes/full attributes/raw forks after CNID root relocation;", out)


if __name__ == "__main__":
    main()
