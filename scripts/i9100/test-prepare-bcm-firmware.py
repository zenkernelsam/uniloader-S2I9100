#!/usr/bin/env python3
"""Retained synthetic tests for local assets/geometry, no hardware access."""
import argparse
import hashlib
import importlib.util
import json
from datetime import datetime
from pathlib import Path

path=Path(__file__).with_name("prepare-bcm-firmware.py")
spec=importlib.util.spec_from_file_location("bcm_prepare",path)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.cap()
out=mod.REPO/"out"/("bcm-firmware-plan-tests-"+datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
out.mkdir()
image=bytes((n*7)%256 for n in range(32769))
raw=b"# SYNTHETIC TEST ONLY\r\nmacaddr=02:11:22:33:44:66\r\nboardtype=0x053e\nccode=US\nregrev=0 # retained value space\n"
(out/"fake-firmware.bin").write_bytes(image)
(out/"fake-nvram.txt").write_bytes(raw)
(out/"fake-mac.txt").write_bytes(b"02:11:22:33:44:66\n")
args=argparse.Namespace(firmware=out/"fake-firmware.bin",nvram=out/"fake-nvram.txt",factory_mac_file=out/"fake-mac.txt",
                       chip_revision=3,sdio_revision=12,ram_bytes=393216,source_note="SYNTHETIC TEST DATA, NEVER FOR HARDWARE",mark_reviewed=False,output=out/"prepared")
folder,m=mod.prepare(args)
assert not m["board_data_reviewed"] and not m["hardware_tested"] and not m["radio_started"]
assert (folder/"firmware.bin").read_bytes()==image
assert m["files"]["firmware.bin"]["sha256"]==hashlib.sha256(image).hexdigest()
packed=(folder/"nvram.packed.bin").read_bytes()
assert b"regrev=0 \0" in packed and b"#" not in packed and packed.endswith(b"\0\0")
assert m["files"]["nvram.packed.bin"]["sha256"]==hashlib.sha256(packed).hexdigest()
assert mod.layout(393216,7,32768,64)["token"]==0xffee0011
assert mod.layout(393216,7,32768,64)["nvram_address"]==393144
try:
    mod.prepare(args)
    raise AssertionError("Existing folder overwritten")
except ValueError:
    pass
for bad in (b"",b"macaddr=00:00:00:00:00:00\n",b"macaddr=03:11:22:33:44:66\n",
            b"macaddr=02:11:22:33:44:66\nccode=US\nccode=JP\n",b"boardtype=0x053e\n",b"\0"*5):
    try:
        mod.pack_nvram(bad,bytes.fromhex("021122334466"))
        raise AssertionError("Bad NVRAM accepted")
    except ValueError:
        pass
for geometry in ((393216,12,393216,100),(8192,12,8,100),(393216,12,8,4097)):
    try:
        mod.layout(*geometry)
        raise AssertionError("Invalid geometry accepted")
    except ValueError:
        pass
sources={str(p.relative_to(mod.REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (path,Path(__file__))}
(out/"test-result.json").write_text(json.dumps(dict(result="PASS",synthetic_only=True,hardware_tested=False,
    sources=sources,coverage="stock byte preservation/real SHA256/MAC rejection/duplicate keys/new-folder refusal/RAM overlap/PR85623"),indent=2)+"\n")
print("PASS local firmware manifest/assets geometry, synthetic evidence retained",out)
