#!/usr/bin/env python3
"""Build a fresh journaled /private/var raw HFSX image, preserving audited metadata."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from datetime import datetime

SCRIPT = Path(__file__).resolve().with_name("audit-ios6-volume-split.py")
spec = importlib.util.spec_from_file_location("volume_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
ROOT, REPO = audit.ROOT, audit.REPO


def key(parent, name):
    text = name.encode("utf-16be")
    units = len(text) // 2
    if units > 255:
        raise ValueError("Unbounded catalog name")
    return struct.pack(">HIH", 6 + len(text), parent, units) + text


def thread(fid, parent, name, folder):
    text = name.encode("utf-16be")
    return key(fid, "") + struct.pack(">HHIH", 3 if folder else 4, 0, parent, len(text) // 2) + text


def node(records, size, kind, height, forward=0, backward=0):
    out = bytearray(size)
    struct.pack_into(">IIbBHH", out, 0, forward, backward, kind, height, len(records), 0)
    at = 14
    for i, record in enumerate(records):
        if at + len(record) + 2 * (len(records) + 1) > size:
            raise ValueError("B-tree node overflow")
        struct.pack_into(">H", out, size - 2 * (i + 1), at)
        out[at:at + len(record)] = record
        at += len(record)
    struct.pack_into(">H", out, size - 2 * (len(records) + 1), at)
    return bytes(out)


def pages(rows, node_size):
    page = []
    used = 14
    for record in rows:
        if used + len(record) + 2 * (len(page) + 2) > node_size:
            if not page:
                raise ValueError("Single B-tree record too large")
            yield page
            page = []
            used = 14
        page.append(record)
        used += len(record)
    if page:
        yield page


def build_tree(raw_template, fork_bytes, rows, row_key):
    ns = struct.unpack_from(">H", raw_template, 32)[0]
    total = fork_bytes // ns
    head = bytearray(raw_template[:ns])
    hcount = struct.unpack_from(">H", head, 10)[0]
    positions = [struct.unpack_from(">H", head, ns - 2 * (i + 1))[0] for i in range(hcount + 1)]
    if hcount != 3 or positions[0] != 14:
        raise ValueError("Unsupported fresh mkfs header-map layout")
    headers = [bytearray(head[positions[i]:positions[i + 1]]) for i in range(3)]
    if len(headers[2]) * 8 < total:
        raise ValueError("New tree requires unsupported map nodes")
    result = {}
    number = 1
    leaf_groups = list(pages(rows, ns))
    level = []
    for i, group in enumerate(leaf_groups):
        ident = number
        number += 1
        result[ident] = node(group, ns, -1, 1, ident + 1 if i + 1 < len(leaf_groups) else 0, ident - 1 if i else 0)
        level.append((row_key(group[0]), ident))
    height = 1 if level else 0
    while len(level) > 1:
        height += 1
        index_rows = [k + struct.pack(">I", ident) for k, ident in level]
        next_level = []
        groups = list(pages(index_rows, ns))
        for index, group in enumerate(groups):
            ident = number
            number += 1
            result[ident] = node(group, ns, 0, height,
                                ident + 1 if index + 1 < len(groups) else 0, ident - 1 if index else 0)
            next_level.append((row_key(group[0]), ident))
        level = next_level
    if number > total:
        raise ValueError("Fresh metadata fork too small")
    h = headers[0]
    struct.pack_into(">HIIII", h, 0, height, level[0][1] if level else 0, len(rows), 1 if leaf_groups else 0, len(leaf_groups))
    struct.pack_into(">II", h, 22, total, total - number)
    # Preserve compareType/attributes and header/user records produced by
    # mkfs; only valid newly built nodes become allocated in the map.
    bitmap = bytearray(len(headers[2]))
    for i in range(number):
        bitmap[i // 8] |= 1 << (7 - (i & 7))
    headers[2] = bitmap
    result[0] = node([bytes(x) for x in headers], ns, 1, 0)
    return result, dict(node_size=ns, nodes_used=number, total_nodes=total, depth=height, leaf_records=len(rows))


def fork_raw(logical, start, blocks):
    data = bytearray(80)
    struct.pack_into(">QIIII", data, 0, logical, 0, blocks, start if blocks else 0, blocks)
    return data


def metadata_write(file, image, field, logical, data):
    mapping = image.fork(image.header[field:field + 80], {112: 6, 192: 3, 272: 4, 352: 8}.get(field, 0))
    for extent in mapping["extents"]:
        size = extent["blocks"] * image.bs
        if logical >= size:
            logical -= size
            continue
        take = min(len(data), size - logical)
        file.seek(extent["block"] * image.bs + logical)
        file.write(data[:take])
        data = data[take:]
        logical = 0
        if not data:
            return
    raise ValueError("New metadata escaped fresh fork")


def verify_payload(source, target, image, kind, destination):
    original = bytes.fromhex(source["catalog_body_hex"])[88:168] if kind == 0 else bytes.fromhex(source["catalog_body_hex"])[168:248]
    old = image.fork(original, source["cnid"], kind)
    h_old, h_new = hashlib.sha256(), hashlib.sha256()
    remaining = old["logical_bytes"]
    at = destination
    for extent in old["extents"]:
        span = min(remaining, extent["blocks"] * image.bs)
        offset = extent["block"] * image.bs
        while span:
            amount = min(span, 1024 * 1024)
            raw = image.read(offset, amount)
            target.seek(at)
            target.write(raw)
            h_old.update(raw)
            offset += amount
            at += amount
            span -= amount
            remaining -= amount
    if remaining:
        raise ValueError("Source fork incomplete")
    target.flush()
    target.seek(destination)
    remaining = old["logical_bytes"]
    while remaining:
        raw = target.read(min(remaining, 1024 * 1024))
        if not raw:
            raise ValueError("Output fork truncated")
        h_new.update(raw)
        remaining -= len(raw)
    if h_old.digest() != h_new.digest():
        raise RuntimeError("Landed raw fork differs from original")
    return dict(path=source["path"], kind=kind, logical_bytes=old["logical_bytes"], sha256=h_old.hexdigest())


def build(a):
    source_path = a.image.resolve()
    out = a.output.resolve() if a.output else REPO / "out" / ("ios6-data-volume-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not out.is_relative_to(REPO / "out") or out.exists():
        raise ValueError("Use a fresh project-local output")
    image = audit.HFS(source_path)
    try:
        checked = audit.audit(image, ROOT / "research/I9100-INTERNAL-PARTITION-AUDIT-20261106.json")
        if checked["cross_volume_hardlink_groups"]:
            raise ValueError("Hardlink chains crossing the split require a separate reviewed relocation")
        entries = [e for e in checked["catalog"] if e["path"] == "/private/var" or e["path"].startswith("/private/var/")]
        root = next(e for e in entries if e["path"] == "/private/var")
        if any(e.get("hardlink") for e in entries):
            raise ValueError("Do not silently rebuild hardlink backing inodes")
        attrs = {}
        for _, _, raw in image.leaves(352):
            fid = struct.unpack_from(">I", raw, 4)[0]
            if fid in {e["cnid"] for e in entries}:
                kl = struct.unpack_from(">H", raw)[0] + 2
                if struct.unpack_from(">I", raw, kl)[0] != 0x10:
                    raise ValueError("Extent-based attributes require an additional relocation implementation")
                attrs.setdefault(fid, []).append(raw)
        out.mkdir(parents=True)
        target_path = out / "DATAFS.HFS"
        with target_path.open("xb") as file:
            file.truncate(6442450944)
        run = subprocess.run(["mkfs.hfsplus", "-s", "-J", "-b", "8192", "-v", "I9100DATA", "-U", "0", "-G", "0", "-M", "0755", str(target_path)],
                             capture_output=True, text=True)
        (out / "mkfs.log").write_text(run.stdout + run.stderr)
        if run.returncode:
            raise RuntimeError("Fresh HFS creation failed; source unchanged")
        fresh = audit.HFS(target_path)
        try:
            journal_rows = [r for _, _, r in fresh.leaves(272)]
            root_row = next(r for r in journal_rows if struct.unpack_from(">I", r, 2)[0] == 1)
            root_name = root_row[8:struct.unpack_from(">H", root_row)[0] + 2].decode("utf-16be")
            # Keep only newly created journal files and their threads; the
            # data root keeps its original BSD/Finder metadata, remapped to2.
            journal_rows = [r for r in journal_rows if struct.unpack_from(">I", r, 2)[0] not in (1, 2) or
                            struct.unpack_from(">H", r, struct.unpack_from(">H", r)[0] + 2)[0] == 2]
            catalog_rows = list(journal_rows)
            attribute_rows = []
            bitmap = bytearray(fresh.fork_read(112, 0, fresh.fork(fresh.header[112:192], 6)["logical_bytes"]))
            used = sum((bitmap[i // 8] >> (7 - (i & 7))) & 1 for i in range(fresh.total))
            cursor = 1
            allocated = 0
            payloads = []
            data_paths = []
            with target_path.open("r+b") as target:
                for entry in entries:
                    fid = 2 if entry["cnid"] == root["cnid"] else entry["cnid"]
                    parent = 1 if fid == 2 else 2 if entry["parent"] == root["cnid"] else entry["parent"]
                    name = root_name if fid == 2 else entry["name"]
                    body = bytearray.fromhex(entry["catalog_body_hex"])
                    struct.pack_into(">I", body, 8, fid)
                    flags = struct.unpack_from(">H", body, 2)[0]
                    if entry["type"] == "file":
                        flags |= 2
                    struct.pack_into(">H", body, 2, flags)
                    if entry["type"] == "file":
                        for kind, field in ((0, 88), (255, 168)):
                            old = image.fork(body[field:field + 80], entry["cnid"], kind)
                            blocks = (old["logical_bytes"] + fresh.bs - 1) // fresh.bs
                            start = 0
                            if blocks:
                                candidate = cursor
                                run_length = 0
                                for i in range(cursor, fresh.total - 1):
                                    occupied = bitmap[i // 8] & (1 << (7 - (i & 7)))
                                    if occupied:
                                        candidate, run_length = i + 1, 0
                                    else:
                                        run_length += 1
                                    if run_length == blocks:
                                        start = candidate
                                        cursor = i + 1
                                        break
                                if not start:
                                    raise ValueError("No bounded contiguous extent for audited data fork")
                                for i in range(start, start + blocks):
                                    bitmap[i // 8] |= 1 << (7 - (i & 7))
                                allocated += blocks
                                payloads.append(verify_payload(entry, target, image, kind, start * fresh.bs))
                            body[field:field + 80] = fork_raw(old["logical_bytes"], start, blocks)
                    else:
                        valence = sum(e["parent"] == entry["cnid"] for e in entries) + (2 if fid == 2 else 0)
                        folders = sum(e["parent"] == entry["cnid"] and e["type"] == "directory" for e in entries)
                        struct.pack_into(">I", body, 4, valence)
                        struct.pack_into(">I", body, 84, folders)
                    catalog_rows.append(key(parent, name) + body)
                    catalog_rows.append(thread(fid, parent, name, entry["type"] == "directory"))
                    for raw in attrs.get(entry["cnid"], []):
                        raw = bytearray(raw)
                        struct.pack_into(">I", raw, 4, fid)
                        attribute_rows.append(bytes(raw))
                    data_paths.append(dict(source=entry["path"], target="/" if fid == 2 else entry["path"][len("/private/var"):],
                                           source_cnid=entry["cnid"], target_cnid=fid,
                                           source_record_sha256=entry["catalog_record_sha256"], body_sha256=hashlib.sha256(body).hexdigest()))
                def csort(row):
                    parent, units = struct.unpack_from(">IH", row, 2)
                    return parent, tuple(struct.unpack_from(">" + "H" * units, row, 8))
                def asort(row):
                    fid, start, units = struct.unpack_from(">IIH", row, 4)
                    return fid, tuple(struct.unpack_from(">" + "H" * units, row, 14)), start
                catalog_rows.sort(key=csort)
                attribute_rows.sort(key=asort)
                summaries = {}
                for field, rows in ((272, catalog_rows), (352, attribute_rows)):
                    source_head = fresh.fork_read(field, 0, fresh.fork(fresh.header[field:field + 80], 4 if field == 272 else 8)["logical_bytes"])
                    nodes, summary = build_tree(source_head, len(source_head), rows, lambda r: r[:struct.unpack_from(">H", r)[0] + 2])
                    summaries[str(field)] = summary
                    for number, raw in nodes.items():
                        metadata_write(target, fresh, field, number * summary["node_size"], raw)
                metadata_write(target, fresh, 112, 0, bitmap)
                vh = bytearray(fresh.header)
                struct.pack_into(">I", vh, 32, sum(e["type"] == "file" for e in entries) + 2)
                struct.pack_into(">I", vh, 36, sum(e["type"] == "directory" for e in entries) - 1)
                struct.pack_into(">I", vh, 48, fresh.total - used - allocated)
                struct.pack_into(">I", vh, 64, max(e["cnid"] for e in entries) + 1)
                struct.pack_into(">I", vh, 68, struct.unpack_from(">I", vh, 68)[0] + 1)
                # HFSX journal created by mkfs remains intact; offline edits
                # leave a clean unmounted volume, then independent fsck -n.
                target.seek(1024)
                target.write(vh)
                target.seek(fresh.bytes - 1024)
                target.write(vh)
                target.flush()
            result = dict(result="PREPARED", hardware_tested=False, device_contacted=False,
                          source=checked["source"], target=dict(path=str(target_path.relative_to(ROOT)), bytes=fresh.bytes,
                          journaled=True, hfsx=True, data_mount="/private/var", migrated_objects=len(entries),
                          raw_forks=payloads, catalog_map=data_paths, btrees=summaries,
                          attributes_preserved=len(attribute_rows), migration_verified=False),
                          source_auditor_sha256=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                          builder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            (out / "preparation.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        finally:
            fresh.close()
        check = subprocess.run(["fsck.hfsplus", "-f", "-n", str(target_path)], capture_output=True, text=True)
        (out / "fsck.log").write_text(check.stdout + check.stderr)
        if check.returncode:
            raise RuntimeError("HFS consistency validation failed; keep candidate for inspection, source untouched")
        verifier_path = Path(__file__).resolve().with_name("verify-ios6-data-volume.py")
        verifier_spec = importlib.util.spec_from_file_location("data_verify", verifier_path)
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        verify_target = audit.HFS(target_path)
        try:
            verified = verifier.verify(image, verify_target)
        finally:
            verify_target.close()
        verified["verifier_sha256"] = hashlib.sha256(verifier_path.read_bytes()).hexdigest()
        (out / "metadata-verification.json").write_text(json.dumps(verified, indent=2) + "\n")
        result["result"] = "PASS"
        result["target"]["migration_verified"] = True
        result["metadata_verification_sha256"] = hashlib.sha256((out / "metadata-verification.json").read_bytes()).hexdigest()
        (out / "preparation.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps(dict(result="PASS", output=str(out), bytes=fresh.bytes, objects=len(entries), forks=len(payloads),
                              attributes=len(attribute_rows), hardware_tested=False, deployed=False), indent=2))
        return out
    finally:
        image.close()


def main():
    audit.cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, default=ROOT / "assets/releases/ios6-sd-20261106/ROOTFS.HFS")
    p.add_argument("--output", type=Path)
    build(p.parse_args())


if __name__ == "__main__":
    main()
