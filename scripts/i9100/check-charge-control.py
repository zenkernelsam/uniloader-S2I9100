#!/usr/bin/env python3
"""Test the actual charger USB receive and ACK-completion path in a register model.

No device/flash/reset. W1C register effects are explicitly modeled between polls;
the FIFO payload, framing, transfer counters and endpoint actions are production.
"""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__],dict(os.environ,I9100_CPU_CAPPED='1'))
from pathlib import Path
from datetime import datetime
import subprocess
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('charge-control-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
code=r'''
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
static uint32_t registers[8192],phy[1024],clockgate,pmu;
static uint32_t receive_fifo[32];static unsigned fifo_index;
#define DWC2_BASE ((uintptr_t)registers)
#define PHY_BASE ((uintptr_t)phy)
#define PMU_USBPHYCTRL ((uintptr_t)&pmu)
#define CMU_GATE_IP_FSYS clockgate
#define FIFO_RD(n) rxpop(n)
#define I9100_CONTROL_TAG "1234567890abcdef"
static uint32_t rxpop(unsigned ep){assert(ep==1 && fifo_index<32);return receive_fifo[fifo_index++];}
void printk(int level,const char*fmt,...){(void)level;(void)fmt;}
#include "driver.c"
void console_register(const struct console*c){(void)c;}
static void reset(void){memset(registers,0,sizeof(registers));memset(&charge_control,0,sizeof(charge_control));
 charge_identity=1;usb_ok=1;configured=host_open=1;in_poll=ep1_busy=0;
 charge_action_ready=tx_written_total=tx_drained_total=tx_completed_total=ep1_transfer_total=0;
 tx_head=tx_tail=0;bulk_mps=512;DTXFSTS(1)=512;DIEPCTL(1)=DXEPCTL_USBACTEP|DXEPCTL_MPS(512);}
static void received(const char*line){unsigned n=strlen(line);assert(n<=64);memset(receive_fifo,0,sizeof(receive_fifo));
 memcpy(receive_fifo,line,n);fifo_index=0;GINTSTS=GINTSTS_RXFLVL;GRXSTSP=1U|(n<<4)|(PKTSTS_OUTRX<<17);usbcdc_poll();GINTSTS=0;}
static void complete(void){GINTSTS=GINTSTS_IEPINT;DAINT=2;DIEPINT(1)=DXEPINT_XFERCOMPL;usbcdc_poll();GINTSTS=0;DIEPINT(1)=0;}
int main(void){
 reset();received("I9CHC1 00000001 1234567890abcdef boot\n");assert(charge_control.action==1 && !usbcdc4210_charge_take_action());
 complete();assert(usbcdc4210_charge_take_action()==1 && !usbcdc4210_charge_take_action());
 received("I9CHC1 00000001 1234567890abcdef boot\n");assert(!charge_control.action);
 received("I9CHC1 00000002 1234567890abcdee download\n");assert(!charge_control.action);
 received("I9CHC1 00000003 1234567890abcdef flash\n");assert(!charge_control.action);
 received("I9CHC1 00000004 1234567890abcdef download\n");assert(charge_control.action==2);complete();assert(usbcdc4210_charge_take_action()==2);
 reset();char text[180];memset(text,'x',160);text[160]='\n';text[161]=0;
 for(unsigned n=0;n<161;n++)i9100_chg_parse(&charge_control,text[n],I9100_CONTROL_TAG);
 received("I9CHC1 00000005 1234567890abcdef boot\n");assert(charge_control.action==1);
 GINTSTS=GINTSTS_IEPINT;DAINT=2;DIEPINT(1)=DXEPINT_AHBERR;usbcdc_poll();assert(!usbcdc4210_charge_take_action() && !charge_control.action);
 reset();ring_push("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\n");ep1_kick();
 received("I9CHC1 00000006 1234567890abcdef download\n");assert(charge_control.action==2 && !charge_action_ready);
 complete();assert(!charge_action_ready);complete();assert(!charge_action_ready);complete();assert(usbcdc4210_charge_take_action()==2);
 reset();DOEPCTL(1)=DXEPCTL_USBACTEP|DXEPCTL_MPS(512);DOEPTSIZ(1)=0;GINTSTS=GINTSTS_OEPINT;DAINT=2U<<16;DOEPINT(1)=1;
 usbcdc_poll();assert(DOEPTSIZ(1)==((1U<<19)|512) && (DOEPCTL(1)&DXEPCTL_EPENA));
 puts("PASS production charger bulk OUT/IN, matching tag/new sequence, no reset before full ACK, prior logs, reply crossing packets, error cancellation and OUT rearm");}
'''
(out/'driver.c').write_text((repo/'drivers/samsung/dwc2cdc4210.c').read_text().replace('#include "../../board/samsung/i9100-charge-control.h"','#include "i9100-charge-control.h"'))
(out/'check.c').write_text(code)
for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wno-int-to-void-pointer-cast','-Wno-pointer-to-int-cast','-fsanitize=address,undefined','-fno-sanitize-recover=all',
    '-I'+str(repo/'include'),'-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],[str(out/'check')])):
    r=subprocess.run(cmd,text=True,capture_output=True);(out/f'command-{n}.log').write_text(r.stdout+r.stderr)
    if r.returncode:print((r.stdout+r.stderr)[-3500:],file=sys.stderr);r.check_returncode()
    if r.stdout:print(r.stdout.strip(),flush=True)
print('EVIDENCE',out,flush=True)
