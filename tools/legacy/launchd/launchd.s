/* Minimal static armv7 PID1 stub: open /dev/console, banner, exit(42).
 * The exit code is the canary — the kernel "launchd died" panic reports
 * it, proving userland executed to the end of our svc sequence. */
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
    mov     r2, #15
    mov     r12, #4         /* write */
    svc     #0x80
nowrite:
    mov     r0, #42
    mov     r12, #1         /* exit */
    svc     #0x80
spin:
    b       spin
path:
    .asciz  "/dev/console"
msg:
    .ascii  "LAUNCHD-ALIVE!\n"
