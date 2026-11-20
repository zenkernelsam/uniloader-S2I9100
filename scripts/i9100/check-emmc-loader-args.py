#!/usr/bin/env python3
"""Actual boot-arg helper guards and ARM loader compile; no QEMU or device."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from datetime import datetime
REPO=Path(__file__).resolve().parents[2];XNU=REPO.parent/'xnu-S2I9100'
sys.path.insert(0,str(XNU/'port-tests'))
from i9100_offline_build import Evidence
e=Evidence('emmc-loader-args');e.wait_idle_seconds=60
fixture=e.out/'test-loader-args.c'
fixture.write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <main/i9100-emmc-root.h>
int main(void){
 char args[2056],saved[2056];memset(args,0xa5,sizeof(args));
 const char *valid="-v keepsyms=1 i9100control=1 init=/sbin/launchd";
 strcpy(args+4,valid);assert(i9100_emmc_root_append(args+4,2048));
 assert(!strcmp(args+4,"-v keepsyms=1 i9100control=1 init=/sbin/launchd" I9100_EMMC_ROOT_CMDLINE));
 for(unsigned i=0;i<4;i++)assert((unsigned char)args[i]==0xa5);
 for(unsigned i=2052;i<sizeof(args);i++)assert((unsigned char)args[i]==0xa5);
 const char *conflicts[]={"rd=md0","-v rd=disk0s1","-v\trootdev=disk9","rootdev=uuid","rd=i9100-system"};
 for(unsigned n=0;n<5;n++){memset(args,0,sizeof(args));strcpy(args,conflicts[n]);memcpy(saved,args,sizeof(args));
  assert(!i9100_emmc_root_append(args,2048)&&!memcmp(saved,args,sizeof(args)));}
 memset(args,'x',sizeof(args));memcpy(saved,args,sizeof(args));assert(!i9100_emmc_root_append(args,2048)&&!memcmp(saved,args,sizeof(args)));
 strcpy(args,valid);memcpy(saved,args,sizeof(args));assert(!i9100_emmc_root_append(args,strlen(valid)+sizeof(I9100_EMMC_ROOT_CMDLINE)-1)&&!memcmp(saved,args,sizeof(args)));
 assert(!i9100_emmc_root_append(NULL,2048)&&!i9100_emmc_root_append(args,0));
 puts("PASS actual fixed internal-root commandline, conflicting earlier rd/rootdev, exact capacity, no writes on failure, guard bytes; no loader/hardware execution");return 0;
}
''')
e.run(['clang','-std=c99','-O1','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-fsanitize=address,undefined',
 '-fno-sanitize-recover=all','-I'+str(REPO/'include'),str(fixture),'-o',str(e.out/'models')],'compile-loader-args-model')
e.run([str(e.out/'models')],'loader-args-model-tests')
source=REPO/'arch/arm/load-kernel.c';header=REPO/'include/main/i9100-emmc-root.h'
captured={str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (source,header,REPO/'include/generated/autoconf.h')}
raw=shlex.split((REPO/'arch/arm/.load-kernel.o.cmd').read_text().splitlines()[0].split(':=',1)[1])
base=[x for x in raw if not x.startswith(('-Wp,-MD,','-DVER_TAG='))]
for mode in ('default','internal'):
 command=list(base);destination=e.out/('load-kernel-'+mode+'.o');command[command.index('-o')+1]=str(destination)
 command+=['-O1','-DI9100_CONTROL_BUILD=1','-DI9100_CONTROL_TAG="0123456789abcdef"','-MMD','-MF',str(destination.with_suffix('.d'))]
 if mode=='internal':command+=['-DI9100_EMMC_ROOT_BUILD=1']
 e.run(command,'compile-arm-loader-'+mode,cwd=REPO)
 output=e.run(['arm-none-eabi-objdump','-dr',str(destination)],'disassemble-arm-loader-'+mode,cwd=REPO)
 if mode=='internal' and b' rd=i9100-system i9100emmcdata=1' not in destination.read_bytes():raise RuntimeError('ARM object lacks fixed root suffix')
 if mode=='default' and b' rd=i9100-system i9100emmcdata=1' in destination.read_bytes():raise RuntimeError('Default loader activated internal root')
 if mode=='internal' and 'sd_arch_load_kernel_xnu' in output:raise RuntimeError('Internal loader still has SD payload fallback')
for name,expected in captured.items():
 if hashlib.sha256((REPO/name).read_bytes()).hexdigest()!=expected:raise RuntimeError('Loader source/config changed during compile')
e.result['loader_sources']=captured;e.result['loader_tests']=True
e.result['model_source_sha256']=hashlib.sha256(fixture.read_bytes()).hexdigest();e.result['model_binary_sha256']=hashlib.sha256((e.out/'models').read_bytes()).hexdigest()
e.result['arm_objects_sha256']={mode:hashlib.sha256((e.out/('load-kernel-'+mode+'.o')).read_bytes()).hexdigest() for mode in ('default','internal')}
e.finish([], 'Production fixed root helper and actual ARM load-kernel objects; default remains off, no physical loader boot/serial/storage')
