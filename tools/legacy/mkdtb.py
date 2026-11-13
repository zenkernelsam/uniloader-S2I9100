#!/usr/bin/env python3
# Emit a minimal Apple "flattened device tree" (iBoot ADT binary) that the
# XNU pexpert/IOKit DT walker can parse.
#
# On-disk layout (pexpert/pexpert/device_tree.h):
#   DeviceTreeNode          { u32 nProperties; u32 nChildren; props[]; children[]; }
#   DeviceTreeNodeProperty  { char name[32]; u32 length; u8 value[round4(length)]; }
#
# A node with nProperties==0 ends the sibling walk, so every node we emit
# carries at least a "name" property.
import struct
import sys

def _pad4(b):
    return b + b"\0" * ((4 - (len(b) & 3)) & 3)

def prop(name, value):
    if isinstance(value, str):
        value = value.encode() + b"\0"
    elif isinstance(value, int):
        value = struct.pack("<I", value)
    return name.encode()[:31].ljust(32, b"\0") + struct.pack("<I", len(value)) + _pad4(value)

def prop_bin(name, *u32s):
    return prop(name, b"".join(struct.pack("<I", u) for u in u32s))

def node(name, props, children=()):
    plist = [prop("name", name)] + props
    out = struct.pack("<2I", len(plist), len(children))
    for p in plist:
        out += p
    for c in children:
        out += c
    return out

def build(bootargs, ba_pa, ba_len, dt_pa, dt_len, ram_pa, ram_len, rd_pa, rd_len, model):
    # /chosen/memory-map: DO NOT declare BootArgs/DeviceTree/RAMDisk/RAM
    # regions here — the kernel unmaps every declared page after reclaim,
    # and our boot_args (0x41735448) shares the DeviceTree page, so the
    # next PE_parse_boot_argn CommandLine read takes an L2 translation
    # fault (observed: L2[0x34,0x35] zeroed at PA 0x41c0dcd0).
    memmap = node("memory-map", [])
    udid = bytes.fromhex("7c5f8a2e94d1b3f6085a3c7e9f2b4d6a8c0e1f35")
    chosen = node("chosen", [
        prop("boot-args", bootargs),
        prop("machine-name", model),
        prop_bin("unique-chip-id", 0x0000DEAD, 0x0BADCAFE),
        prop("unique-device-id", udid),
        prop_bin("ecid", 0, 0x0BADCAFE),
        prop("device-imei", "012345678901234"),
        prop("serial-number", "C39GH00E0069"),
        prop("mlb-serial-number", "C3LJT0DSDT9Y"),
        prop("osversion", "10B329"),
        prop("firmware-version", "iBoot-1537.9.55"),
        prop_bin("die-id", 0x10000000),
        prop_bin("device-id", 4),
        prop_bin("board-id", 0),
        prop_bin("chip-id", 0x8940),
        prop_bin("amc-version", 0),
    ], [memmap])
    defaults = node("defaults", [
        prop("content-adlock", 0),
    ])
    aliases = node("aliases", [])
    cpus = node("cpus", [
        prop_bin("#address-cells", 1),
        prop_bin("#size-cells", 0),
    ])
    facetime = node("facetime", [
        prop_bin("bitrate-wifi", 3000000),
        prop_bin("bitrate-lte", 2000000),
        prop_bin("bitrate-3g", 1000000),
        prop_bin("bitrate-2g", 0),
    ])
    maps = node("maps", [
        prop_bin("no-simplistic-road-mesh", 0),
        prop_bin("navigation", 1),
    ])
    product = node("product", [
        prop_bin("udid-version", 1),
        prop("region-info", "LL/A"),
        prop("model-number", "MC918LL"),
        prop("mlb-serial-number", "C3LJT0DSDT9Y"),
        prop("serial-number", "C39GH00E0069"),
        prop_bin("unique-chip-id", 0x0BADCAFE),
        prop("unique-device-id", "7c5f8a2e94d1b3f6085a3c7e9f2b4d6a8c0e1f35"),
        prop_bin("device-id", 4),
        prop_bin("board-id", 0),
        prop_bin("chip-id", 0x8940),
        prop_bin("die-id", 0x10000000),
        prop_bin("soc-id", 0),
        prop_bin("development-cert", 0),
        prop("product-description", "iPhone4,1"),
        prop("product-version", "10B329"),
        prop_bin("product-id", 0x0c00),
        prop_bin("lockdown-certtype", 0),
        prop("marketing-name", "iPhone 4S"),
    ], [facetime, maps])
    options = node("options", [])
    armio = node("arm-io", [
        prop("compatible", "arm-io,i9100"),
        prop_bin("chip-id", 0x4210),
        prop_bin("board-id", 0),
        prop_bin("amc-version", 0),
        prop_bin("chip-revision", 0x10),
        prop("device_type", "arm-io"),
    ])
    root = node("device-tree", [
        prop("compatible", b"samsung,i9100\0samsung,exynos4210\0AppleARM\0"),
        prop("model", model),
        prop_bin("#address-cells", 1),
        prop_bin("#size-cells", 1),
        prop_bin("secure-root-prefix", 0),
        prop("serial-number", "C39GH00E0069"),
        prop_bin("target-type", 0),
    ], [chosen, defaults, aliases, cpus, product, options, armio])
    return root

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--bootargs", default="-v keepsyms=1 kprintf=1")
    ap.add_argument("--ba",   default="0x41735000,0x1000")
    ap.add_argument("--dt",   default="0x41734000,0x2000")
    ap.add_argument("--ram",  default="0x40000000,0x30000000")
    ap.add_argument("--rd",   default="0x41736000,0x1")
    ap.add_argument("--model", default="iPhone4,1")
    a = ap.parse_args()
    def pv(s):
        pa, sz = s.split(",")
        return int(pa, 0), int(sz, 0)
    ba_pa, ba_len = pv(a.ba)
    dt_pa, dt_len = pv(a.dt)
    ram_pa, ram_len = pv(a.ram)
    rd_pa, rd_len = pv(a.rd)
    blob = build(a.bootargs, ba_pa, ba_len, dt_pa, dt_len,
                 ram_pa, ram_len, rd_pa, rd_len, a.model)
    open(a.out, "wb").write(blob)
    print("wrote %s (%d bytes)" % (a.out, len(blob)))
