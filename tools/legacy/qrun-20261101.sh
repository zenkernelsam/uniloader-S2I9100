#!/bin/bash
cd /root/i9100d
exec taskset -c 0-13 nice -n10 ionice -c2 -n7 qemu-system-arm -M smdkc210 -kernel uniloader-S2I9100/uniLoader -m 1024 -display none -serial null -serial null -serial file:out/uart2-sz.log -drive if=sd,format=raw,file=/root/sd-fast.img -monitor unix:/tmp/qmon12,server,nowait -gdb tcp::1234
