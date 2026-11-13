import io
notes = u"""
## 里程碑 19（2026-10-30）：launchd/libxpc 死锁破案 + iOS6 daemon 生态全活

### 根因链（实测定案，非猜测）

1. launchd[1] 的 EXC_BAD_INSTRUCTION 风暴 = libxpc _xpc_domain_create
   的第三断言故意 udf #254（Could not set context on Mach port!）。
2. TRHIST 环形缓冲（mach_syscall_trace 钩子）证明所有 mach trap 全 ret=0，
   最后调用是 -31 mach_msg_trap → 失败在 MIG RPC 内部。
3. MMTRAP 抓 msgh_id：id=3229 = mach_port_set_context，发向 task port
   (rport=103)，kr=0 但 _X stub 从未执行（MPSC 探针静默）。
4. 真正元凶：内核 MIG server 的 Request 结构 context 字段为 32 位
   （期望 msgh_size=40），而 iOS6 用户态发 44 字节（8 字节 context 槽）。
   项目自带的 ios7lab_context_request wire shim 正是干这个的
   （44B+高位零 → 改写 msgh_size=40）——但被
   ios7_compat_vmabi_enabled() 门控，iOS6 启动标记
   ios7lab_vmabi=0 把它误伤了。

### 修复

- osfmk/kern/ipc_kobject.c：3228/3229/4811/4813/2865 四个
  wire-format shim 的门控从 ios7_compat_vmabi_enabled() 解开
  （线格式适配是用户态 ABI，与 vmabi 策略无关）。
- bsd/vfs/vfs_lookup.c：namei 对 */cc_fips_test 返回 ENOENT——
  卷头 freeBlocks=0（镜像塞满），FIPS POST 控制文件 F_PREALLOCATE
  必 ENOSPC，launchctl 会 reboot(RB_HALT)；隐藏二进制让
  path_check() 直接跳过 POST。
- 取证仪表：model_dep.c TRHIST 32 槽环形（pid+trap+ret+msgid）、
  mach_port.c MPSC 探针、mach_msg.c MMTRAP（已门控到
  i9100mmtrap=1 boot-arg，默认关）、unix_syscalls.c SYSC
  （cc_fips_test 全量 + pid<=8 错误调用，上限 140 行）。

### QEMU 实测（out/uart2-clean.log）

- MPSC ok + IOS7LAB port_context64 operation=set result=0 —
  set_context 真正进内核并返回成功。
- 零 EXC_BAD_INSTRUCTION，零 panic。
- daemon 全家桶活：UserEventAgent、wifid、DumpPanic、lskdd、
  wifiFirmwareLoad、CrashHousekeeping、mtmergeprops、daily、hpfd、
  atwakeup、FinishRestore — launchd 主循环稳态收发。
- 2493 行干净日志（MMTRAP 关闭后）。

### 遗留

- freeBlocks=0 的根问题还在：任何需新分配块的写入都会 ENOSPC。
  真机 ASR 恢复把卷铺满分区所以有空；我们的镜像按卷头大小。
  后续需要：给卷造空闲块（位图尾段未引用块释放？）或挂数据分区。
- SpringBoard 未观察到拉起——需确认是缺 UI 服务条件还是没到那步。
"""
with io.open(u"../NOTES.md", "a", encoding="utf-8") as f:
    f.write(notes)
msg = u"""i9100: unblock iOS6 launchd by lifting wire-ABI shim gating

The packed iOS6 rootfs now reaches a steady daemon ecosystem in QEMU.
Root cause of the launchd EXC_BAD_INSTRUCTION storm: libxpc's
_xpc_domain_create asserted on mach_port_set_context(3229) because the
ios7lab wire-format compat shims were gated by ios7lab_vmabi, which the
iOS6 marker sets to 0. The shims translate the 44-byte userland request
to the kernel's 40-byte MIG struct; ungate them since wire format is a
userland ABI independent of the vmabi policy toggle.

Also hide /usr/libexec/cc_fips_test in namei: the packed volume has
freeBlocks=0 so the FIPS POST control-file prealloc always ENOSPCs and
launchctl would reboot(RB_HALT). TRHIST/MMTRAP/SYSC/MPSC forensics
added; MMTRAP is now behind i9100mmtrap boot-arg.
"""
with io.open(u"commitmsg.txt", "w", encoding="utf-8") as f:
    f.write(msg)
