#!/usr/bin/env python3
"""Check the production previous-boot DT patch against the real generated DT."""
from datetime import datetime
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
              sys.executable,__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
repo=Path(__file__).resolve().parents[2]
out=repo/'out/automation'/('previous-boot-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
out.mkdir(parents=True)
sp=importlib.util.spec_from_file_location('dt',Path(__file__).with_name('prepare-payloads.py'))
dt=importlib.util.module_from_spec(sp);sp.loader.exec_module(dt)
tree=dt.device_tree()
source=r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
'''+'#include "'+str(repo/'include/main/i9100-previous-boot.h')+'"\n'+r'''
static unsigned checks;
#define CHECK(v) do{checks++;if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);exit(1);}}while(0)
static unsigned char tree[] = {
'''+','.join(str(v) for v in tree)+r'''
};
int main(void) {
    CHECK(sizeof(struct I9100PreviousBoot)==64);
    struct I9100PreviousBoot record={I9100_PREVIOUS_BOOT_MAGIC,1,64,3,0x7766800a,0xf103,
        0x800a,0xf103,0x80320000,0x80310001,0x80097000,0x80,{0}};
    unsigned char before[sizeof(tree)];memcpy(before,tree,sizeof(tree));
    CHECK(i9100_previous_boot_patch(tree,sizeof(tree),&record));
    unsigned changed=0;
    for(unsigned n=0;n<sizeof(tree);n++)if(tree[n]!=before[n])changed++;
    CHECK(changed>0 && changed<=64);
    unsigned target=0;
    for(unsigned n=0;n+100<=sizeof(tree);n+=4)
        if(!memcmp(before+n,I9100_PREVIOUS_BOOT_PROPERTY,sizeof(I9100_PREVIOUS_BOOT_PROPERTY)))target=n+36;
    CHECK(target && !memcmp(tree+target,&record,64));
    for(unsigned n=0;n<sizeof(tree);n++)if(n<target || n>=target+64)CHECK(tree[n]==before[n]);
    CHECK(!i9100_previous_boot_patch(0,sizeof(tree),&record));
    CHECK(!i9100_previous_boot_patch(tree,sizeof(tree),0));
    CHECK(!i9100_previous_boot_patch(tree,99,&record));
    CHECK(!i9100_previous_boot_patch(tree,65537,&record));
    memcpy(tree,before,sizeof(tree));tree[target-4]=63;
    CHECK(!i9100_previous_boot_patch(tree,sizeof(tree),&record));
    unsigned char twice[sizeof(tree)*2];memcpy(twice,before,sizeof(tree));memcpy(twice+sizeof(tree),before,sizeof(tree));
    CHECK(!i9100_previous_boot_patch(twice,sizeof(twice),&record));
    printf("PASS %u DT-slot/bounds/ambiguity checks\n",checks);
}
'''
(out/'test.c').write_text(source)
for label,cmd in [('build',['gcc','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',out/'test.c','-o',out/'test']),
                  ('test',[out/'test'])]:
    result=subprocess.run(cmd,text=True,capture_output=True)
    (out/(label+'.log')).write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
    if result.stdout:print(result.stdout,end='',flush=True)
print('Evidence:',out)
