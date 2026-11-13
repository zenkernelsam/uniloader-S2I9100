#!/usr/bin/env python3
# Add mqueue-pointer probes to ipc_mqueue_send/receive for send<->receive
# correlation across task namespaces.
import sys

F = "/mnt/d/Desktop/Git/ios-samsung-i9100/xnu-S2I9100/xnu/osfmk/ipc/ipc_mqueue.c"
d = open(F, "rb").read()
NL = bytes([92, 110])

a = b"""{
	int wresult;

	/*
	 *  Don't block if:"""
i = d.find(a)
assert i > 0, "send anchor"
send_probe = (
    b"{\n"
    b"#if defined(BOARD_CONFIG_EXYNOS4210_I9100)\n"
    b"\t{ int j1p=proc_selfpid(); if (j1p>=17)\n"
    b"\t    kprintf(\"J1MQS pid=%d mq=%x id=%d" + NL + b"\", j1p, (unsigned)mqueue,\n"
    b"\t        kmsg && kmsg->ikm_header ? kmsg->ikm_header->msgh_id : -1); }\n"
    b"#endif\n"
    b"\tint wresult;\n\n\t/*\n\t *  Don" + bytes([39]) + b"t block if:"
)
d = d[:i] + send_probe + d[i + len(a):]

a = b"""{
	wait_result_t           wresult;
        thread_t                self = current_thread();"""
i = d.find(a)
assert i > 0, "rcv anchor"
rcv_probe = (
    b"{\n"
    b"#if defined(BOARD_CONFIG_EXYNOS4210_I9100)\n"
    b"\t{ int j1p=proc_selfpid(); if (j1p>=17)\n"
    b"\t    kprintf(\"J1MQR pid=%d mq=%x" + NL + b"\", j1p, (unsigned)mqueue); }\n"
    b"#endif\n"
    b"\twait_result_t           wresult;\n        thread_t                self = current_thread();"
)
d = d[:i] + rcv_probe + d[i + len(a):]
open(F, "wb").write(d)
print("mq probes added")
