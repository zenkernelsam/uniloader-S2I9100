#!/usr/bin/env python3
"""Check real HFS parser/tree construction and rejection without devices or deletion."""
import importlib.util
import json
from pathlib import Path
import struct
from unittest.mock import patch
from datetime import datetime

SCRIPT = Path(__file__).resolve().with_name("build-ios6-data-volume.py")
spec = importlib.util.spec_from_file_location("data_builder", SCRIPT)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
audit = builder.audit


def main():
    audit.cap()
    out = builder.REPO / "out" / ("ios6-volume-tools-check-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    out.mkdir()
    image = audit.HFS(builder.ROOT / "assets/releases/ios6-sd-20261106/ROOTFS.HFS")
    try:
        template = image.fork_read(272, 0, 8192)
        rows = [builder.key(2, "item" + str(k).zfill(5)) + struct.pack(">H", 2) + bytes(246) for k in range(10000)]
        tree, report = builder.build_tree(template, 8192 * 1024, rows,
                                           lambda raw: raw[:struct.unpack_from(">H", raw)[0] + 2])
        assert report["depth"] >= 3 and report["leaf_records"] == len(rows)
        leaves = [k for k, v in tree.items() if struct.unpack_from(">b", v, 8)[0] == -1]
        seen = []
        count = 0
        cursor = leaves[0]
        while cursor:
            assert cursor not in seen
            seen.append(cursor)
            node = tree[cursor]
            count += struct.unpack_from(">H", node, 10)[0]
            cursor = struct.unpack_from(">I", node)[0]
        assert count == len(rows) and seen == leaves
        failures = []
        try:
            builder.build_tree(template, 8192 * 2, rows, lambda raw: raw[:struct.unpack_from(">H", raw)[0] + 2])
        except ValueError:
            failures.append("tree-capacity")
        else:
            raise AssertionError("Too-small metadata fork accepted")
        original = image.fork_read
        first = struct.unpack_from(">I", template, 24)[0]

        def corrupt(field, offset, count):
            raw = bytearray(original(field, offset, count))
            if field == 272 and offset == first * 8192:
                struct.pack_into(">I", raw, 0, first)
            return bytes(raw)

        with patch.object(image, "fork_read", corrupt):
            try:
                list(image.leaves(272))
            except ValueError:
                failures.append("cyclic-catalog")
            else:
                raise AssertionError("Cyclic catalog accepted")
        try:
            image.fork(bytes(16) + struct.pack(">II", image.total, 1) + bytes(56))
        except ValueError:
            failures.append("extent-beyond-volume")
        else:
            raise AssertionError("Invalid extent accepted")
        try:
            image.fork_read(272, image.bytes, 4096)
        except ValueError:
            failures.append("metadata-out-of-range")
        else:
            raise AssertionError("Out of metadata range accepted")
        (out / "test-result.json").write_text(json.dumps(dict(result="PASS", hardware_tested=False,
            device_contacted=False, nodes=report, failures=failures,
            scope="Actual source reader, three-level tree packing, node bounds and malformed-input rejection; no mount, generated deployment or phone"), indent=2) + "\n")
    finally:
        image.close()
    print("PASS actual parser/tree/rejection;", out)


if __name__ == "__main__":
    main()
