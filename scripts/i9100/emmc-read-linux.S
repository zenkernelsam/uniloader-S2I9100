/* SPDX-License-Identifier: BSD-2-Clause; Linux ARM EABI, no bionic/glibc. */
.syntax unified
.arm
.text
.global _start
.type _start,%function
_start:
 ldr r0,[sp]
 add r1,sp,#4
 bl i9ro_linux_main
 mov r7,#248
 svc #0
1: b 1b
.size _start,.-_start
.global i9ro_syscall6
.type i9ro_syscall6,%function
i9ro_syscall6:
 push {r4,r5,r7,lr}
 mov r7,r0
 mov r0,r1
 mov r1,r2
 mov r2,r3
 ldr r3,[sp,#16]
 ldr r4,[sp,#20]
 ldr r5,[sp,#24]
 svc #0
 pop {r4,r5,r7,pc}
.size i9ro_syscall6,.-i9ro_syscall6
.section .note.GNU-stack,"",%progbits
