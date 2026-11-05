#!/bin/bash
# One bounded emulation at a time; all artifacts stay in the project.
set -euo pipefail
if [[ ${1-} != --cpu-capped ]]; then
    exec taskset -c 0-13 nice -n10 ionice -c2 -n7 bash "$0" --cpu-capped "$@"
fi
shift
image=$(realpath -- "$1")
prefix=$2
seconds=${3:-30}
case "$image" in /mnt/d/Desktop/Git/ios-samsung-i9100/*) ;; *) exit 2 ;; esac
case "$prefix" in /mnt/d/Desktop/Git/ios-samsung-i9100/*) ;; *) exit 2 ;; esac
[[ "$seconds" =~ ^[0-9]+$ ]] && ((seconds > 0 && seconds <= 900))
mkdir -p -- "$(dirname -- "$prefix")"
extra=()
if [[ -n ${4-} ]]; then
    sd=$(realpath -- "$4")
    case "$sd" in /mnt/d/Desktop/Git/ios-samsung-i9100/*) ;; *) exit 2 ;; esac
    # Snapshot mode leaves the validated SD image unchanged.
    # smdkc210's default index 0 is SDHCI0 (0x12510000); the i9100
    # external slot is SDHCI2 (0x12530000).
    extra=(-drive "file=$sd,if=sd,index=2,format=raw,snapshot=on")
fi
set +e
timeout --signal=TERM --kill-after=5s "${seconds}s" qemu-system-arm \
    -M smdkc210 -m 1024M -smp 2 -display none \
    -serial "file:$prefix-uart0.log" -serial null \
    -serial "file:$prefix-uart2.log" -serial null -monitor none \
    -device "loader,file=$image,addr=0x40008000,cpu-num=0" \
    -no-reboot "${extra[@]}" >"$prefix-qemu.log" 2>&1
result=$?
set -e
printf 'QEMU exit: %s; logs: %s\n' "$result" "$prefix"
tail -40 -- "$prefix-uart0.log"
if [[ "$result" != 124 && "$result" != 0 ]]; then
    cat -- "$prefix-qemu.log"
    exit "$result"
fi
