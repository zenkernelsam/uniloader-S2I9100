#!/usr/bin/env python3
"""Create an immutable-source HFSX system candidate with an empty mandatory data mount."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import zlib
from datetime import datetime

BUILDER = Path(__file__).resolve().with_name("build-ios6-data-volume.py")
spec = importlib.util.spec_from_file_location("data_builder", BUILDER)
data_builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(data_builder)
audit = data_builder.audit
ROOT, REPO = audit.ROOT, audit.REPO
FSTAB = (b"/dev/i9100-system / hfs ro 0 1\n"
         b"/dev/i9100-data /private/var hfs rw,nosuid,nodev 0 2\n")


def records(image):
    rows = {}
    for _, _, raw in image.leaves(272):
        key_end = struct.unpack_from(">H", raw)[0] + 2
        kind = struct.unpack_from(">H", raw, key_end)[0]
        fid = struct.unpack_from(">I", raw, key_end + 8)[0] if kind in (1, 2) else struct.unpack_from(">I", raw, 2)[0]
        key = (kind, fid)
        if key in rows:
            raise ValueError("Duplicate source catalog record")
        rows[key] = raw
    return rows


def build(a):
    out = a.output.resolve() if a.output else REPO / "out" / ("ios6-system-volume-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    if not out.is_relative_to(REPO / "out") or out.exists():
        raise ValueError("Use fresh retained output")
    image = audit.HFS(a.image)
    try:
        checked = audit.audit(image, ROOT / "research/I9100-INTERNAL-PARTITION-AUDIT-20261106.json")
        removed = {e["cnid"] for e in checked["catalog"] if e["path"].startswith("/private/var/")}
        mount = next(e for e in checked["catalog"] if e["path"] == "/private/var")
        fstab = next(e for e in checked["catalog"] if e["path"] == "/private/etc/fstab")
        if checked["cross_volume_hardlink_groups"] or not checked["plan"]["source_system_fits"]:
            raise ValueError("Source system requires a different reviewed split")
        expected = records(image)
        catalog = []
        for (kind, fid), raw in expected.items():
            if fid in removed:
                continue
            if kind == 1 and fid == mount["cnid"]:
                raw = bytearray(raw)
                start = struct.unpack_from(">H", raw)[0] + 2
                struct.pack_into(">I", raw, start + 4, 0)
                struct.pack_into(">I", raw, start + 84, 0)
                raw = bytes(raw)
            catalog.append(raw)
        attributes = []
        old_fstab = None
        for _, _, raw in image.leaves(352):
            fid = struct.unpack_from(">I", raw, 4)[0]
            if fid in removed:
                continue
            end = struct.unpack_from(">H", raw)[0] + 2
            name = raw[14:end].decode("utf-16be")
            if fid == fstab["cnid"] and name == "com.apple.decmpfs":
                if old_fstab is not None or struct.unpack_from(">I", raw, end)[0] != 0x10:
                    raise ValueError("Need exactly one source inline fstab compression record")
                size = struct.unpack_from(">I", raw, end + 12)[0]
                value = raw[end + 16:end + 16 + size]
                if value[:4] != b"fpmc" or struct.unpack_from("<I", value, 4)[0] != 3:
                    raise ValueError("Unsupported source fstab compression")
                old_fstab = zlib.decompress(value[16:])
                new_value = struct.pack("<4sIQ", b"fpmc", 3, len(FSTAB)) + zlib.compress(FSTAB, 9)
                attr_body = struct.pack(">IIII", 0x10, 0, 0, len(new_value)) + new_value
                if len(attr_body) & 1:
                    attr_body += b"\0"
                raw = raw[:end] + attr_body
            attributes.append(raw)
        if old_fstab is None:
            raise ValueError("Source fstab not located")
        removed_blocks = set()
        protected = set()
        for field, fid in ((112, 6), (192, 3), (272, 4), (352, 8), (432, 7)):
            for ex in image.fork(image.header[field:field + 80], fid)["extents"]:
                protected.update(range(ex["block"], ex["block"] + ex["blocks"]))
        for entry in checked["catalog"]:
            for field in ("data_fork", "resource_fork"):
                for ex in entry.get(field, {}).get("extents", []):
                    chosen = removed_blocks if entry["cnid"] in removed else protected
                    chosen.update(range(ex["block"], ex["block"] + ex["blocks"]))
        if removed_blocks & protected:
            raise ValueError("Removal would free an extent referenced by retained system metadata/file")
        overflow = []
        for _, _, raw in image.leaves(192):
            fid = struct.unpack_from(">I", raw, 4)[0]
            if fid not in removed:
                overflow.append(raw)
        out.mkdir(parents=True)
        target_path = out / "FACTORYFS.HFS"
        source_hash = hashlib.sha256()
        with target_path.open("xb") as target:
            remaining = image.bytes
            offset = 0
            while remaining:
                amount = min(remaining, 4 * 1024 * 1024)
                raw = image.read(offset, amount)
                source_hash.update(raw)
                target.write(raw)
                remaining -= amount
                offset += amount
        bitmap_size = image.fork(image.header[112:192], 6)["logical_bytes"]
        bitmap = bytearray(image.fork_read(112, 0, bitmap_size))
        for n in removed_blocks:
            if not bitmap[n // 8] & (1 << (7 - (n & 7))):
                raise ValueError("Removed extent was not allocated in source bitmap")
            bitmap[n // 8] &= ~(1 << (7 - (n & 7)))
        used = sum((bitmap[n // 8] >> (7 - (n & 7))) & 1 for n in range(image.total))
        def sort_catalog(raw):
            fid, units = struct.unpack_from(">IH", raw, 2)
            return fid, tuple(struct.unpack_from(">" + "H" * units, raw, 8))
        def sort_attributes(raw):
            fid, start, units = struct.unpack_from(">IIH", raw, 4)
            return fid, tuple(struct.unpack_from(">" + "H" * units, raw, 14)), start
        def sort_extent(raw):
            kind, _, fid, start = struct.unpack_from(">BBII", raw, 2)
            return fid, kind, start
        catalog.sort(key=sort_catalog)
        attributes.sort(key=sort_attributes)
        overflow.sort(key=sort_extent)
        summaries = {}
        with target_path.open("r+b") as target:
            for field, rows, fid in ((192, overflow, 3), (272, catalog, 4), (352, attributes, 8)):
                amount = image.fork(image.header[field:field + 80], fid)["logical_bytes"]
                template = image.fork_read(field, 0, amount)
                tree, summary = data_builder.build_tree(template, amount, rows, lambda raw: raw[:struct.unpack_from(">H", raw)[0] + 2])
                summaries[str(field)] = summary
                # A smaller rebuilt tree must not leave old nodes marked
                # free but nonzero; independent fsck checks those nodes.
                for offset in range(0, amount, 1024 * 1024):
                    data_builder.metadata_write(target, image, field, offset, bytes(min(1024 * 1024, amount - offset)))
                for n, raw in tree.items():
                    data_builder.metadata_write(target, image, field, n * summary["node_size"], raw)
            data_builder.metadata_write(target, image, 112, 0, bitmap)
            header = bytearray(image.header)
            old_files, old_folders = struct.unpack_from(">II", header, 32)
            struct.pack_into(">I", header, 32, old_files - sum(e["cnid"] in removed and e["type"] == "file" for e in checked["catalog"]))
            struct.pack_into(">I", header, 36, old_folders - sum(e["cnid"] in removed and e["type"] == "directory" for e in checked["catalog"]))
            struct.pack_into(">I", header, 48, image.total - used)
            struct.pack_into(">I", header, 68, struct.unpack_from(">I", header, 68)[0] + 1)
            target.seek(1024)
            target.write(header)
            target.seek(image.bytes - 1024)
            target.write(header)
            target.flush()
        result = dict(result="PREPARED", hardware_tested=False, device_contacted=False, deployed=False,
                      source=checked["source"], source_volume_sha256=source_hash.hexdigest(),
                      target=dict(path=str(target_path.relative_to(ROOT)), bytes=image.bytes,
                                  system_mount="/", read_only_required=True, empty_data_mount_cnid=mount["cnid"],
                                  data_mount="/private/var", removed_objects=len(removed), freed_allocation_blocks=len(removed_blocks),
                                  fstab_old=old_fstab.decode(), fstab_new=FSTAB.decode(),
                                  device_alias_provider_implemented=False, boot_ready=False), btrees=summaries,
                      builder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      auditor_sha256=hashlib.sha256(Path(__file__).resolve().with_name("audit-ios6-volume-split.py").read_bytes()).hexdigest(),
                      pending="Real CID/media-bound aliases, mandatory early data mount and writer/journal/flush-before-reboot integration")
        (out / "preparation.json").write_text(json.dumps(result, indent=2) + "\n")
        run = subprocess.run(["fsck.hfsplus", "-f", "-n", str(target_path)], capture_output=True, text=True)
        (out / "fsck.log").write_text(run.stdout + run.stderr)
        if run.returncode:
            raise RuntimeError("System candidate fsck failed; source unchanged, keep output for inspection")
        verify_path = Path(__file__).resolve().with_name("verify-ios6-system-volume.py")
        verify_spec = importlib.util.spec_from_file_location("system_verify", verify_path)
        verifier = importlib.util.module_from_spec(verify_spec)
        verify_spec.loader.exec_module(verifier)
        verify_image = audit.HFS(target_path)
        try:
            compared = verifier.verify(image, verify_image)
        finally:
            verify_image.close()
        compared["verifier_sha256"] = hashlib.sha256(verify_path.read_bytes()).hexdigest()
        (out / "metadata-verification.json").write_text(json.dumps(compared, indent=2) + "\n")
        result["metadata_verification_sha256"] = hashlib.sha256((out / "metadata-verification.json").read_bytes()).hexdigest()
        result["result"] = "PASS"
        (out / "preparation.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(dict(result="PASS", output=str(out), removed=len(removed), freed_bytes=len(removed_blocks) * image.bs,
                              hardware_tested=False, boot_ready=False), indent=2))
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
