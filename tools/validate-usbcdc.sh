#!/bin/bash
# Offline validation only. No hardware access, cleanup, make, or firmware writes.
set -euo pipefail
if [[ ${1-} != --cpu-capped ]]; then
    exec taskset -c 0-13 nice -n10 ionice -c2 -n7 bash "$0" --cpu-capped
fi
repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd -- "$repo"
case "$repo" in
    /root/i9100d/uniloader-S2I9100|/mnt/d/Desktop/Git/ios-samsung-i9100/uniloader-S2I9100) ;;
    *) printf '%s\n' 'Refusing output outside the documented project paths' >&2; exit 1 ;;
esac
output="$repo/out/usbcdc-check-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p -- "$output"
printf 'Validation output: %s\n' "$output"
gcc -std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -Iinclude tools/usbcdc_sim.c -o "$output/sim"
"$output/sim" 2>&1 | tee "$output/sim.log"
arm-none-eabi-gcc -fsyntax-only -Wall -Wextra -Werror=implicit-function-declaration \
    -fno-builtin -nostdinc -Ilib/unic -Iinclude \
    -include include/generated/autoconf.h -D__KERNEL__ \
    -march=armv7-a -mfloat-abi=soft -mtune=cortex-a9 \
    drivers/samsung/dwc2cdc4210.c 2>&1 | tee "$output/arm-syntax.log"
printf '%s\n' 'PASS: host simulation and ARM syntax (not a hardware USB test)'
