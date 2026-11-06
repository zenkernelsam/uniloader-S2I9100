#!/bin/bash
set -euo pipefail
if [[ ${1-} != --cpu-capped ]]; then
    exec taskset -c 0-13 nice -n10 ionice -c2 -n7 bash "$0" --cpu-capped
fi
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
out="$repo/out/one-shot/host"
mkdir -p -- "$out"
llvm-dlltool-14 -m i386:x86-64 -d "$repo/scripts/i9100/kernel32.def" -l "$out/kernel32.lib"
clang-14 --target=x86_64-pc-windows-msvc -O1 -ffreestanding -fno-builtin \
    -fno-stack-protector -c "$repo/scripts/i9100/rawcom.c" -o "$out/rawcom.obj"
lld-link /entry:entry /subsystem:console /nodefaultlib /machine:x64 \
    "/out:$out/rawcom.exe" "$out/rawcom.obj" "$out/kernel32.lib"
llvm-readobj-14 --coff-imports "$out/rawcom.exe" >"$out/imports.txt"
printf 'Built %s\n' "$out/rawcom.exe"
