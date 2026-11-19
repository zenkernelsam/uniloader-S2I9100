#!/usr/bin/env python3
"""Retain pinned Samsung U1 camera facts, without contacting a phone or downloading."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

if os.environ.get("I9100_CPU_CAPPED") != "1":
    os.execvpe("taskset", ["taskset", "-c", "0-13", "nice", "-n10", "ionice", "-c2", "-n7",
                          sys.executable, "-B", __file__, *sys.argv[1:]],
               dict(os.environ, I9100_CPU_CAPPED="1"))

ROOT = Path(__file__).resolve().parents[3]
PIN = "a0346556698e62405a04b010c4f4197bdc9fec06"
BASE = ROOT / ("research/vendor-linux-u1-a0346556/android_kernel_samsung_smdk4210-" + PIN)
FILES = (
    "arch/arm/mach-exynos/mach-u1.c",
    "arch/arm/mach-exynos/include/mach/map-exynos4.h",
    "arch/arm/mach-exynos/include/mach/irqs-exynos4.h",
    "arch/arm/mach-exynos/include/mach/regs-clock.h",
    "arch/arm/mach-exynos/include/mach/regs-pmu.h",
    "arch/arm/mach-exynos/clock-exynos4.c",
    "arch/arm/plat-s5p/setup-mipiphy.c",
    "arch/arm/plat-s5p/include/plat/regs-fimc.h",
    "arch/arm/plat-s5p/include/plat/regs-csis.h",
    "drivers/media/video/samsung/fimc/csis.c",
    "drivers/media/video/samsung/fimc/fimc_regs.c",
    "drivers/media/video/samsung/fimc/fimc_dev.c",
    "drivers/media/video/s5p-fimc/regs-fimc.h",
    "drivers/media/video/s5p-fimc/fimc-reg.c",
    "drivers/media/video/s5p-fimc/fimc-core.h",
    "drivers/media/video/s5p-fimc/fimc-core.c",
)
MFC_FILES = (
    "drivers/media/video/s5p-mfc/regs-mfc-v5.h",
    "drivers/media/video/s5p-mfc/s5p_mfc.c",
    "drivers/media/video/s5p-mfc/s5p_mfc_cmd_v5.c",
    "drivers/media/video/s5p-mfc/s5p_mfc_ctrl.c",
    "drivers/media/video/s5p-mfc/s5p_mfc_opr_v5.c",
    "drivers/media/video/s5p-mfc/s5p_mfc_shm.c",
    "drivers/media/video/s5p-mfc/s5p_mfc_shm.h",
    "drivers/media/video/samsung/mfc5x/mfc_buf.h",
    "drivers/media/video/samsung/mfc5x/mfc_cmd.c",
    "arch/arm/mach-exynos/dev-pd-exynos4.c",
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--include-mfc", action="store_true")
    a = p.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT / "research") or out.exists():
        raise RuntimeError("Use a fresh directory inside project research")
    pin_path = ROOT / "research/peripheral-reference-20261115/source-pin.json"
    pin = json.loads(pin_path.read_text())
    if pin != {"repository": "CyanogenMod/android_kernel_samsung_smdk4210", "branch": "cm-10.1", "commit": PIN}:
        raise RuntimeError("Pinned Samsung source changed")
    tree_path = pin_path.with_name("source-tree.json")
    tree = json.loads(tree_path.read_text())
    if tree.get("truncated"):
        raise RuntimeError("Source inventory was truncated")
    indexed = {x["path"]: x for x in tree["tree"] if x.get("type") == "blob"}
    sources = {}
    for name in FILES + (MFC_FILES if a.include_mfc else ()):
        path = BASE / name
        raw = path.read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        entry = indexed.get(name)
        if not entry or entry["sha"] != git_blob or entry["size"] != len(raw):
            raise RuntimeError("Original Git blob does not match local source: " + name)
        sources[name] = dict(path=str(path.relative_to(ROOT)), bytes=len(raw), git_blob=git_blob,
                             sha256=hashlib.sha256(raw).hexdigest())
    facts = {
        "controller": "Exynos4210 FIMCv5.1 / two CSIS receivers; not Exynos4412 FIMC-LITE/IS",
        "fimc0": {"physical": "0x11800000", "gic_intid": 116, "gate_cam_bit": 0,
                  "sysmmu_physical": "0x11a20000", "sysmmu_gate_cam_bit": 7},
        "csis": [{"physical": "0x11880000", "gic_intid": 110, "gate_cam_bit": 4},
                 {"physical": "0x11890000", "gic_intid": 112, "gate_cam_bit": 5}],
        "rear_source_candidate": {"config": "CONFIG_VIDEO_M5MO", "sensor": "M5MO", "i2c": "0x1f",
                                  "csis": 0, "lanes": 2, "hs_settle": 12, "alignment": 32, "mclk": 24000000},
        "front_source_candidate": {"config": "CONFIG_VIDEO_S5K5BAFX", "sensor": "S5K5BAFX", "i2c": "0x2d",
                                   "csis": 1, "lanes": 1, "hs_settle": 6, "alignment": 32, "mclk": 24000000},
        "fimc_output": {"slot0_y_cb_cr": ["0x18", "0x28", "0x38"], "sequence_bitmap": "0x1fc",
                        "present_slot": "CISTATUS2[5:0], one-based", "before_slot": "CISTATUS2[12:7], one-based",
                        "status": "0x64; FRAMEEND bit17 / LASTCAPTUREEND bit16",
                        "idle": "CIIMGCPT[31:30]=0, scaler[15]=0, MSCTRL[0]=0, status[26,22,21]=0",
                        "format": "CITRGFMT 2<<29 = packed 422; CIOCTRL 3 = YCBYCR/YUYV",
                        "linear_dma": "CIDMAPARAM[14:13]=0; CIEXTEN ratio extension separately owned"},
        "shared_phy": {"pmu": "0x10020000 + 0x710 + 4*index", "enable": 0,
                       "csis_reset_n": 1, "display_dsim_reset_n": 2,
                       "rule": "Do not power off PHY while the other display/CSI owner still holds its reset_n"},
        "limitations": ["Board CONFIG/revision candidates are not this handset's chip identity",
                        "No supply provider, sensor initialization, clocks, waveform or image verified on hardware",
                        "A CSIS non-image interrupt cannot prove a FIMC frame or DMA completion",
                        "Polled single slot freezes a completed buffer; not guaranteed exactly one exposure"],
    }
    if a.include_mfc:
        facts["mfcv51"] = dict(physical="0x13400000", sysmmu=["0x13620000", "0x13630000"],
            gic_intid=126, cmu_gate="0xc928 bits0/1/2 = MFC/left-MMU/right-MMU", pmu_configuration="0x3c40/status+4",
            bank_base_alignment=131072, register_address_shift=11, host_shared_address_unit="bytes",
            system_reservation_candidates=[0x60000, 0x80000], reservation_rule="Profile follows original matching firmware; not file length",
            h264_context=0x96000, cpb=0x400000, descriptor=0x20000, shared=0x1000,
            header_command="0x2040=(1<<16)|instance", sequence_reply=4,
            picture_readback="width0x2008,height0x2004,dpb0x200c,consumed0x2018,channel0x2000",
            banks="Luma and H264 MV in bankB; chroma/neighbor scratch in bankA",
            hardware_tested=False, original_firmware_available=False)
    result = dict(result="PASS", hardware_tested=False, device_contacted=False, source_reference_only=True,
                  repository=pin["repository"], commit=PIN, sources=sources, facts=facts,
                  verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  pin_sha256=hashlib.sha256(pin_path.read_bytes()).hexdigest(),
                  tree_sha256=hashlib.sha256(tree_path.read_bytes()).hexdigest())
    out.mkdir()
    (out / "source-facts.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS", len(sources), "original Git blobs; source facts only;", out)


if __name__ == "__main__":
    main()
