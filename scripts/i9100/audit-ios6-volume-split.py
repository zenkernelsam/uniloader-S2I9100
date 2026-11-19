#!/usr/bin/env python3
"""Audit original HFS catalog/attributes for /private/var relocation; read-only."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from datetime import datetime

ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT / "uniloader-S2I9100"


def cap():
    if os.name != "posix":
        raise RuntimeError("Use WSL under the project CPU envelope")
    if os.environ.get("I9100_CPU_CAPPED") != "1":
        os.execvpe("taskset", ["taskset", "-c", "0-13", "nice", "-n10", "ionice", "-c2", "-n7",
                              sys.executable, "-B", *sys.argv], dict(os.environ, I9100_CPU_CAPPED="1"))
    if set(os.sched_getaffinity(0)) - set(range(14)) or os.getpriority(os.PRIO_PROCESS, 0) < 10:
        raise RuntimeError("Missing CPU envelope")


class HFS:
    def __init__(self, path):
        self.path = Path(path).resolve()
        if not self.path.is_relative_to(ROOT) or not self.path.is_file():
            raise ValueError("HFS source must be a project-local regular file")
        self.file = self.path.open("rb")
        self.header = self.read(1024, 512)
        self.signature, self.version = struct.unpack_from(">HH", self.header)
        if (self.signature, self.version) not in ((0x482b, 4), (0x4858, 5)):
            raise ValueError("Expected a naked HFS+/HFSX volume")
        self.bs, self.total, self.free = struct.unpack_from(">III", self.header, 40)
        if not 512 <= self.bs <= 1048576 or self.bs & (self.bs - 1) or not self.total or self.free > self.total:
            raise ValueError("Invalid HFS geometry")
        self.bytes = self.bs * self.total
        if self.bytes > self.path.stat().st_size or self.bytes < 4096:
            raise ValueError("HFS geometry exceeds the image")
        self.backup = self.read(self.bytes - 1024, 512)
        if self.backup[:4] != self.header[:4] or self.backup[40:48] != self.header[40:48]:
            raise ValueError("Alternate HFS header geometry differs")
        self.overflow = {}
        # System extents file must bootstrap from its inline descriptors;
        # no filesystem mount, external repair or raw device access.
        for node, _, record in self.leaves(192):
            key_bytes = struct.unpack_from(">H", record)[0] + 2
            if key_bytes != 12 or len(record) < key_bytes + 64:
                raise ValueError("Invalid HFS extent key/body")
            kind, _, fid, start = struct.unpack_from(">BBII", record, 2)
            key = (fid, kind, start)
            if key in self.overflow:
                raise ValueError("Duplicate overflow extent")
            self.overflow[key] = tuple(struct.unpack_from(">II", record, key_bytes + 8 * k) for k in range(8))

    def close(self):
        self.file.close()

    def read(self, offset, count):
        if offset < 0 or count < 0 or offset + count > self.path.stat().st_size:
            raise ValueError("Read escaped HFS image")
        self.file.seek(offset)
        raw = self.file.read(count)
        if len(raw) != count:
            raise ValueError("Short HFS read")
        return raw

    def fork(self, raw, fid=0, kind=0):
        logical, clump, total = struct.unpack_from(">QII", raw)
        extents = list(struct.unpack_from(">II", raw, 16 + 8 * k) for k in range(8))
        used = sum(n for _, n in extents)
        seen = set()
        while used < total:
            key = (fid, kind, used)
            if key in seen or key not in self.overflow:
                raise ValueError("Missing or cyclic overflow extent")
            seen.add(key)
            more = self.overflow[key]
            amount = sum(n for _, n in more)
            if not amount or len(extents) > 65536:
                raise ValueError("Unbounded extent chain")
            extents += more
            used += amount
        if used != total or logical > total * self.bs:
            raise ValueError("Fork geometry inconsistent")
        for block, span in extents:
            if span and (block >= self.total or span > self.total - block):
                raise ValueError("Extent outside volume")
        return dict(logical_bytes=logical, clump_bytes=clump, blocks=total,
                    extents=[dict(block=b, blocks=n) for b, n in extents if n])

    def fork_read(self, field, logical, count):
        mapping = self.fork(self.header[field:field + 80], {192: 3, 272: 4, 352: 8}.get(field, 0))
        if logical < 0 or logical + count > mapping["logical_bytes"]:
            raise ValueError("Read exceeds metadata fork")
        raw = bytearray()
        for extent in mapping["extents"]:
            size = extent["blocks"] * self.bs
            if logical >= size:
                logical -= size
                continue
            take = min(count, size - logical)
            raw += self.read(extent["block"] * self.bs + logical, take)
            count -= take
            logical = 0
            if not count:
                return bytes(raw)
        raise ValueError("Incomplete metadata fork")

    def leaves(self, field):
        head = self.fork_read(field, 0, 512)
        node_size = struct.unpack_from(">H", head, 32)[0]
        first = struct.unpack_from(">I", head, 24)[0]
        last = struct.unpack_from(">I", head, 28)[0]
        total = struct.unpack_from(">I", head, 36)[0]
        if node_size < 512 or node_size > 32768 or node_size & (node_size - 1) or total > 1048576:
            raise ValueError("Invalid B-tree header")
        seen = set()
        prior = 0
        number = first
        while number:
            if number in seen or number >= total or len(seen) >= total:
                raise ValueError("Cyclic/out-of-range B-tree leaf")
            seen.add(number)
            node = self.fork_read(field, number * node_size, node_size)
            following, backward, kind, height, records = struct.unpack_from(">IIbBH", node)
            if kind != -1 or height != 1 or backward != prior or records > (node_size - 14) // 2:
                raise ValueError("Invalid B-tree leaf chain")
            positions = [struct.unpack_from(">H", node, node_size - 2 * (k + 1))[0] for k in range(records + 1)]
            if positions and (positions[0] < 14 or positions[-1] > node_size - 2 * (records + 1)):
                raise ValueError("B-tree records overlap offset table")
            for k in range(records):
                if positions[k] >= positions[k + 1]:
                    raise ValueError("Unordered B-tree record offsets")
                record = node[positions[k]:positions[k + 1]]
                if len(record) < 2 or struct.unpack_from(">H", record)[0] + 2 > len(record):
                    raise ValueError("Invalid B-tree key length")
                yield number, k, record
            prior, number = number, following
        if prior != last:
            raise ValueError("B-tree last leaf mismatch")


def audit(image, partition_report):
    with image.path.open("rb") as f:
        f.seek(1024)
        initial = f.read(512)
    entries = []
    by_id = {}
    threads = {}
    for node, index, raw in image.leaves(272):
        key_end = struct.unpack_from(">H", raw)[0] + 2
        parent, length = struct.unpack_from(">IH", raw, 2)
        if key_end != 8 + length * 2 or length > 255:
            raise ValueError("Invalid catalog Unicode key")
        name = raw[8:key_end].decode("utf-16be")
        body = raw[key_end:]
        kind = struct.unpack_from(">H", body)[0]
        if kind in (3, 4):
            if parent in threads:
                raise ValueError("Duplicate catalog thread")
            threads[parent] = dict(type=kind, record_sha256=hashlib.sha256(raw).hexdigest())
            continue
        if kind not in (1, 2) or len(body) < (88 if kind == 1 else 248):
            raise ValueError("Unsupported catalog record")
        fid = struct.unpack_from(">I", body, 8)[0]
        if fid in by_id:
            raise ValueError("Duplicate catalog CNID")
        uid, gid, admin, owner, mode, special = struct.unpack_from(">IIBBHI", body, 32)
        flags = struct.unpack_from(">H", body, 2)[0]
        entry = dict(cnid=fid, parent=parent, name=name, type="directory" if kind == 1 else "file",
                     flags=flags, uid=uid, gid=gid, admin_flags=admin, owner_flags=owner, mode=mode,
                     special=special, finder_info_hex=body[48:80].hex(), node=node, record=index,
                     catalog_record_sha256=hashlib.sha256(raw).hexdigest(), catalog_body_hex=body.hex())
        if kind == 2:
            entry["data_fork"] = image.fork(body[88:168], fid, 0)
            entry["resource_fork"] = image.fork(body[168:248], fid, 255)
            entry["hardlink"] = bool(flags & 0x20 or body[48:56] == b"hlnkhfs+")
            entry["symlink"] = mode & 0xf000 == 0xa000
        by_id[fid] = entry
        entries.append(entry)
    if 2 not in by_id:
        raise ValueError("No HFS root folder")
    children = defaultdict(list)
    for entry in entries:
        children[entry["parent"]].append(entry)

    def path(fid):
        parts = []
        seen = set()
        while fid != 2:
            if fid in seen or fid not in by_id or len(seen) >= 256:
                raise ValueError("Orphan/cyclic catalog path")
            seen.add(fid)
            e = by_id[fid]
            parts.append(e["name"])
            fid = e["parent"]
        return "/" + "/".join(reversed(parts))

    selected = set()
    for entry in entries:
        entry["path"] = path(entry["cnid"])
        if entry["path"] == "/private/var" or entry["path"].startswith("/private/var/"):
            selected.add(entry["cnid"])
        entry["thread_present"] = entry["cnid"] in threads
        entry["attributes"] = []
    attr_records = 0
    selected_attribute_bytes = 0
    for node, index, raw in image.leaves(352):
        key_end = struct.unpack_from(">H", raw)[0] + 2
        if key_end < 14 or len(raw) < key_end + 4:
            raise ValueError("Invalid attribute record")
        fid, start, name_length = struct.unpack_from(">IIH", raw, 4)
        if key_end != 14 + name_length * 2:
            raise ValueError("Invalid Unicode attribute key")
        name = raw[14:key_end].decode("utf-16be")
        record_type = struct.unpack_from(">I", raw, key_end)[0]
        attr = dict(name=name, start_block=start, record_type=record_type, node=node, record=index,
                    record_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        if record_type == 0x10:
            size = struct.unpack_from(">I", raw, key_end + 12)[0]
            if key_end + 16 + size > len(raw):
                raise ValueError("Inline attribute length exceeds record")
            data = raw[key_end + 16:key_end + 16 + size]
            attr.update(bytes=size, value_sha256=hashlib.sha256(data).hexdigest())
            if name == "com.apple.decmpfs":
                if len(data) < 16 or data[:4] != b"fpmc":
                    raise ValueError("Invalid compression attribute")
                attr["compression_type"], attr["uncompressed_bytes"] = struct.unpack_from("<IQ", data, 4)
        elif record_type not in (0x20, 0x30):
            raise ValueError("Unknown attribute type")
        if fid in by_id:
            by_id[fid]["attributes"].append(attr)
        elif fid >= 16:
            raise ValueError("Attribute refers to absent catalog entry")
        if fid in selected:
            selected_attribute_bytes += len(raw)
        attr_records += 1
    data_entries = [e for e in entries if e["cnid"] in selected]
    data_root = [e for e in data_entries if e["path"] == "/private/var"]
    if len(data_root) != 1 or data_root[0]["type"] != "directory":
        raise ValueError("Missing unique /private/var directory")
    hardlinks = [e for e in entries if e.get("hardlink")]
    groups = defaultdict(list)
    for e in hardlinks:
        groups[e["special"]].append(e)
    crossing = [dict(inode=n, paths=[e["path"] for e in group]) for n, group in groups.items()
                if any(e["cnid"] in selected for e in group) and any(e["cnid"] not in selected for e in group)]
    data_blocks = sum(e.get("data_fork", {}).get("blocks", 0) + e.get("resource_fork", {}).get("blocks", 0) for e in data_entries)
    filesystem_types = Counter(e["mode"] & 0xf000 for e in data_entries)
    extattrs = Counter(a["name"] for e in data_entries for a in e["attributes"])
    partitions = json.loads(partition_report.read_text())
    if partitions["source_sha256"] != "879334a928bbffffc67d57b584906c03bee10f1310a88a0f1362fc6dfb3724ef":
        raise ValueError("Unexpected historical partition evidence")
    chosen = {p["name"]: p for p in partitions["partitions"] if p["name"] in ("FACTORYFS", "DATAFS")}
    if chosen["FACTORYFS"]["bytes"] != 1610612736 or chosen["DATAFS"]["bytes"] != 6442450944:
        raise ValueError("Historical two-volume capacities changed")
    before = hashlib.sha256(initial).hexdigest()
    if hashlib.sha256(image.read(1024, 512)).hexdigest() != before:
        raise RuntimeError("Source header changed while auditing")
    result = dict(schema=1, result="PASS", device_contacted=False, hardware_tested=False,
                  source=dict(path=str(image.path.relative_to(ROOT)), file_bytes=image.path.stat().st_size,
                              volume_bytes=image.bytes, signature=hex(image.signature), version=image.version,
                              allocation_block=image.bs, total_blocks=image.total, free_blocks=image.free,
                              attributes=struct.unpack_from(">I", image.header, 4)[0],
                              primary_header_sha256=before, alternate_header_sha256=hashlib.sha256(image.backup).hexdigest()),
                  historical_partitions=dict(path=str(partition_report.relative_to(ROOT)),
                                             sha256=hashlib.sha256(partition_report.read_bytes()).hexdigest(), selected=chosen),
                  counts=dict(catalog_objects=len(entries), catalog_threads=len(threads), attribute_records=attr_records,
                              data_objects=len(data_entries), data_files=sum(e["type"] == "file" for e in data_entries),
                              data_directories=sum(e["type"] == "directory" for e in data_entries),
                              data_fork_allocated_bytes=data_blocks * image.bs, data_attribute_record_bytes=selected_attribute_bytes,
                              data_symlinks=sum(bool(e.get("symlink")) for e in data_entries),
                              data_hardlinks=sum(bool(e.get("hardlink")) for e in data_entries)),
                  data_root_cnid=data_root[0]["cnid"], data_mode_counts={oct(k): v for k, v in filesystem_types.items()},
                  data_attribute_counts=dict(extattrs), cross_volume_hardlink_groups=crossing,
                  plan=dict(system_mount="/", data_mount="/private/var", data_contents="Remove /private/var prefix, remap only its root CNID to2",
                            source_system_fits=image.bytes <= chosen["FACTORYFS"]["bytes"],
                            source_data_content_fits=data_blocks * image.bs + selected_attribute_bytes < chosen["DATAFS"]["bytes"],
                            migration_pending=True, metadata_roundtrip_required=True,
                            blockers=["Rebuild catalogue/thread/attribute/overflow indexes on separate raw HFS volume",
                                      "Preserve CNID-linked hardlink backing inodes and split crossing chains explicitly",
                                      "Retain uid/gid/mode/flags/ACL/xattrs/resourcefork/decmpfs, don't use raw-only file copy",
                                      "Journaled data, current-media backup, writable slice/flush, pre-launchd mandatory mount and safe reboot still required"]),
                  catalog=entries)
    return result


def main():
    cap()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, default=ROOT / "assets/releases/ios6-sd-20261106/ROOTFS.HFS")
    p.add_argument("--partition-report", type=Path, default=ROOT / "research/I9100-INTERNAL-PARTITION-AUDIT-20261106.json")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    output = a.output.resolve() if a.output else REPO / "out" / ("ios6-volume-split-audit-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    report = a.partition_report.resolve()
    if not output.is_relative_to(REPO / "out") or output.exists() or not report.is_relative_to(ROOT / "research"):
        raise ValueError("Use fresh project loader out and retained partition research")
    image = HFS(a.image)
    try:
        result = audit(image, report)
    finally:
        image.close()
    result["auditor_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output.mkdir(parents=True)
    (output / "split-audit.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    summary = {key: value for key, value in result.items() if key != "catalog"}
    (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(dict(output=str(output), counts=result["counts"], cross_volume_links=len(result["cross_volume_hardlink_groups"]),
                          fits=result["plan"]["source_system_fits"], hardware_tested=False, migration_pending=True), indent=2))


if __name__ == "__main__":
    main()
