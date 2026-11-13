#!/bin/sh
# Build the stub launchd and inject it into an existing rootfs.hfs + sd image.
# Usage: build.sh <rootfs.hfs> <sd-image>   (both paths, /tmp or repo)
set -e
export PATH=/root/i9100-toolchain/bin:$PATH
HERE=$(dirname "$0")
ROOTFS=${1:-/tmp/rootfs.hfs}
SDIMG=${2:-/tmp/sd-ios.img}
clang -target armv7-apple-darwin11 -c "$HERE/launchd.s" -o /tmp/launchd.o
ld64 -static -arch armv7 -e _start -o /tmp/launchd.out /tmp/launchd.o
mkdir -p /mnt/hfs-inject
mount -o loop -t hfsplus "$ROOTFS" /mnt/hfs-inject
mkdir -p /mnt/hfs-inject/sbin
cp /tmp/launchd.out /mnt/hfs-inject/sbin/launchd
umount /mnt/hfs-inject
# hfs_header() gate: journalInfoBlock (VH+12) must be 0 after Linux mount
python3 - "$ROOTFS" <<PY
import sys
f=open(sys.argv[1],"r+b"); f.seek(1024+12); f.write(b"\x00\x00\x00\x00"); f.close()
PY
if [ -n "$SDIMG" ] && [ -f "$SDIMG" ]; then
  mdel -i "$SDIMG@@$((2048*512))" ::IOS7/ROOTFS.HFS 2>/dev/null || true
  mcopy -i "$SDIMG@@$((2048*512))" -o "$ROOTFS" ::IOS7/ROOTFS.HFS
fi
echo "launchd injected into $ROOTFS${SDIMG:+ and $SDIMG}"
