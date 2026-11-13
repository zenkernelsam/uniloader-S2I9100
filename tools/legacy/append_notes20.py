import io
note = u"""
## 里程碑 20（2026-10-31）— iOS6 spawn 风暴根因定案 + SpringBoard 真实跑起来

### 根因（层层取证）

- pid 风暴（pid 冲到 1371+）= launchd 反复 fork 子进程，子进程
  posix_spawn(244) 返回 EINVAL(22) 后 exit(22)，KeepAlive 立即重试。
- J1PACT 端口动作转储：iOS6/7 libSystem 给每个 spawn 附
  port_type=3（PSPA_IMP_WATCHPORTS 重要性捐赠提示）。
  exec_handle_port_actions 里 type-3 的跳过逻辑被
  ios7_compat_vmabi_enabled() 门控——ios7lab_vmabi=0 时落进
  default: EINVAL，整个 spawn 失败。与 mach_port_set_context
  线格式 shim 完全同病：wire-format 兼容不应挂在 VM ABI 策略开关上。
- 修复：去掉 type-3 bypass 的 vmabi 门控（kern_exec.c）。
  flags=0x40=POSIX_SPAWN_SETEXEC（iOS6 launchd 用 setexec 模式，
  跳过 fork1 直接在自己 proc 上跑 port/file actions）。

### 验证（uart2-spawn7.log）

- spawn 风暴归零：J1SPAWN err 从每轮 ~150 降到 1（仅 /sbin/mount_nfs
  ENOENT 良性）。J1FORK kind=0 不再刷屏。
- **backboardd activate=0、SpringBoard pid=53 activate=0 SRCHK err=0
  单次拉起不重生**——iOS6 SpringBoard 真实存活。
- IOSurface 被真实调用：surface open/method16(caps)/method6/lookup id=1
  480x800 BGRA——合成器链路开始走了。
- 52 个 activate=0（kbd/deleted/fseventsd/passd/MobileStorageMounter/
  mstreamd/atc/keybagd/notifyd...）。

### 新障碍（已在修）

- ReportCrash 对崩溃 daemon 做 stack_snapshot → 函数里
  TRAP_DEBUGGER 执行 bkpt#0 → KDP 未接线 → prefetch abort panic。
  修：i9100 下 stack_snapshot2 提前返回 ENOTSUP（stackshot 是
  诊断路径，不影响功能）。待验证。
- 崩溃 daemon（ReportCrash 服务对象）：imagent/securityd sig=0xc
  （SIGSEGV?）、powerd sig=4——个别 daemon 有真实崩溃，后续逐个查。

### 遗留诊断（仍待查）

- J1EXIT rv=0x1600 退出码 22 的 fork 子进程已消失（同根因）。
- mDNSResponder rv=0x4700 退出码 71 三次——可能正常重启策略。
"""
with io.open("NOTES.md","a",encoding="utf-8") as f: f.write(note)
print("appended")
