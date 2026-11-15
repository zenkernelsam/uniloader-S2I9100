#!/usr/bin/env python3
"""Prepare an opt-in object-list integration patch; never edit the live builder."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
source = repo / "scripts/i9100/prepare-automation.py"
xnu = repo.parent / "xnu-S2I9100"
inventory = ast.parse((xnu / "port-tests/check_i9100_peripheral_all.py").read_text())
groups = {}
for node in inventory.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        if node.targets[0].id in ("C_SOURCES", "CPP_SOURCES"):
            groups[node.targets[0].id] = ast.literal_eval(node.value)
names = groups["C_SOURCES"] + groups["CPP_SOURCES"]
objects = ["iokit/" + Path(name).stem + (".cpo" if name.endswith(".cpp") else ".o") for name in names]
original_bytes = source.read_bytes()
original = original_bytes.decode().replace("\r\n", "\n")
flag = "parser.add_argument('--offline-peripheral-objects', action='store_true',\n" \
       "                    help='Compile opt-in peripheral objects; no peripheral hardware is enabled')\n"
if "--offline-peripheral-objects" in original:
    raise RuntimeError("Builder already contains this integration; refusing to generate a duplicate")
anchor = "args = parser.parse_args()\n"
if original.count(anchor) != 1:
    raise RuntimeError("Builder parser changed; inspect instead of guessing an insertion point")
modified = original.replace(anchor, flag + anchor, 1)
tree = ast.parse(modified)
assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "objects" for target in node.targets))
lines = modified.splitlines(keepends=True)
block = "if args.offline_peripheral_objects:\n" + "    peripheral_objects = " + repr(objects) + "\n" \
        + "    objects.extend(name for name in peripheral_objects if name not in objects)\n"
lines.insert(assignment.end_lineno, block)
modified = "".join(lines)
ast.parse(modified)
if source.read_bytes() != original_bytes:
    raise RuntimeError("Live builder changed while preparing patch; result discarded")
patch = repo / "scripts/i9100/peripheral-offline-objects-integration.patch"
patch.write_text("".join(difflib.unified_diff(original.splitlines(True), modified.splitlines(True),
                 fromfile="a/scripts/i9100/prepare-automation.py", tofile="b/scripts/i9100/prepare-automation.py")))
manifest = dict(source_sha256=hashlib.sha256(original_bytes).hexdigest(), new_objects=objects,
                patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),
                applied=False, hardware_enabled=False,
                prerequisite="Apply both XNU files.arm patches and regenerate iokit rules/full filelist first")
(repo / "scripts/i9100/peripheral-offline-objects-integration.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("PREPARED (not applied)", patch)
