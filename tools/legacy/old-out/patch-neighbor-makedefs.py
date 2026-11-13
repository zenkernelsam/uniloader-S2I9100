#!/usr/bin/env python3
"""Apply the Linux-host build adaptations our tree already proved out to a
neighbour-baseline XNU makedefs/MakeInc.def (LF checkout)."""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'makedefs/MakeInc.def'
s = open(path, encoding='utf-8', newline='').read()
changed = []

if 'TARGET_OS_EMBEDDED' not in s:
    anchor = ('export DEFINES = -DAPPLE -DKERNEL -DKERNEL_PRIVATE '
              '-DXNU_KERNEL_PRIVATE \\\n'
              '       -DPRIVATE -D__MACHO__=1 -Dvolatile=__volatile $(IDENT) '
              '-DBOARD_CONFIG_$(MACHINE_CONFIG)')
    if anchor not in s:
        m = re.search(r'export DEFINES = .*?-DBOARD_CONFIG_\$\(MACHINE_CONFIG\)',
                      s, re.S)
        if not m:
            sys.exit('DEFINES anchor not found')
        anchor = m.group(0)
    add = ('\n\n'
           '# Linux/embedded hosts: TargetConditionals.h comes from the SDK\n'
           '# on macOS; this tree builds -nostdinc.\n'
           'ifeq ($(ARCH_CONFIG),ARM)\n'
           'export DEFINES += -DTARGET_OS_EMBEDDED=1\n'
           'endif')
    s = s.replace(anchor, anchor + add, 1)
    changed.append('TARGET_OS_EMBEDDED')

if 'CFLAGS_RELEASEARM = -O1' not in s:
    old = ('export CFLAGS_RELEASEARM = -O0\n'
           'export CFLAGS_DEVELOPMENTARM = -O0\n'
           'export CFLAGS_DEBUGARM = -O0\n'
           'export CFLAGS_PROFILEARM = -O0')
    if old not in s:
        sys.exit('CFLAGS_*ARM anchor not found')
    new = ('# Linux hosts: llvm-14 -mkernel/-fapple-kext at -O0 emits an extra\n'
           '# ldr for every extern global; -O1 is the first correct level.\n'
           'ifeq ($(UNAME_S),Linux)\n'
           'export CFLAGS_RELEASEARM = -O1\n'
           'export CFLAGS_DEVELOPMENTARM = -O1\n'
           'export CFLAGS_DEBUGARM = -O1\n'
           'export CFLAGS_PROFILEARM = -O1\n'
           'else\n' + old + '\nendif')
    s = s.replace(old, new, 1)
    changed.append('CFLAGS_*ARM=-O1')

if not changed:
    print('already patched')
else:
    open(path, 'w', encoding='utf-8', newline='').write(s)
    print('patched: ' + ', '.join(changed))
