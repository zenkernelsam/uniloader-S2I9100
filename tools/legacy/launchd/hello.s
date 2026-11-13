/* Minimal static armv7 job stub: open /dev/console, banner, exit(0).
 * Launched BY real launchd as a plist job — proving the job system works.
 * Exit 0 (clean) so launchd does not throttle-respawn us. */
.text
.align 2
.globl _start
_start:
    adr     r0, path
    mov     r1, #2          /* O_RDWR */
    mov     r12, #5         /* open */
    svc     #0x80
    mov     r4, r0
    cmp     r0, #0
    blt     nowrite
    mov     r0, r4
    adr     r1, msg
    mov     r2, #29
    mov     r12, #4         /* write */
    svc     #0x80
nowrite:
    mov     r0, #0
    mov     r12, #1         /* exit */
    svc     #0x80
spin:
    b       spin
path:
    .asciz  "/dev/console"
msg:
    .ascii  "HELLO-JOB: spawned by launchd\n"
