/* exit(0) stub for bring-up: replaces tools launchd must "run"
 * successfully but that cannot work in our env (fsck on a
 * file-backed root, nvram on hardware that lacks NVRAM). */
.text
.align 2
.globl _start
_start:
    mov     r0, #0
    mov     r12, #1         /* exit */
    svc     #0x80
spin:
    b       spin
