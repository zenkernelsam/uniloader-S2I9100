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
#define I9100_CHARGER_TAG "fedcba0987654321"
static uint32_t rxpop(unsigned ep){assert(ep==0 && fifo_index<32);return receive_fifo[fifo_index++];}
void printk(int level,const char*fmt,...){(void)level;(void)fmt;}
#include "driver.c"
void console_register(const struct console*c){(void)c;}
static void reset(void){memset(registers,0,sizeof(registers));memset(&charge_control,0,sizeof(charge_control));
 charge_identity=1;usb_ok=1;configured=host_open=1;in_poll=ep1_busy=0;
 charge_action_ready=tx_written_total=tx_drained_total=tx_completed_total=ep1_transfer_total=0;
 charge_boot_available=1;
 tx_head=tx_tail=0;bulk_mps=512;DTXFSTS(1)=512;DIEPCTL(1)=DXEPCTL_USBACTEP|DXEPCTL_MPS(512);}
static void received(const char*line){unsigned n=strlen(line);assert(n<=64);memset(receive_fifo,0,sizeof(receive_fifo));
 memcpy(receive_fifo,line,n);fifo_index=0;GINTSTS=GINTSTS_RXFLVL;GRXSTSP=1U|(n<<4)|(PKTSTS_OUTRX<<17);usbcdc_poll();GINTSTS=0;}
static void complete(void){GINTSTS=GINTSTS_IEPINT;DAINT=2;DIEPINT(1)=DXEPINT_XFERCOMPL;usbcdc_poll();GINTSTS=0;DIEPINT(1)=0;}
static void setup(unsigned rt,unsigned rq,unsigned value){memset(setup_pkt,0,8);setup_pkt[0]=rt;setup_pkt[1]=rq;setup_pkt[2]=value;ep0_setup();}
int main(void){
 reset();received("I9CHC2 00000001 1234567890abcdef fedcba0987654321 boot\n");assert(charge_control.action==1 && !usbcdc4210_charge_take_action());
 complete();assert(usbcdc4210_charge_take_action()==1 && !usbcdc4210_charge_take_action());
 received("I9CHC2 00000001 1234567890abcdef fedcba0987654321 boot\n");assert(!charge_control.action);
 received("I9CHC2 00000002 1234567890abcdee fedcba0987654321 download\n");assert(!charge_control.action);
 received("I9CHC2 00000003 1234567890abcdef fedcba0987654321 flash\n");assert(!charge_control.action);
 received("I9CHC2 00000004 1234567890abcdef fedcba0987654321 download\n");assert(charge_control.action==2);complete();assert(usbcdc4210_charge_take_action()==2);
 received("I9CHC2 00000005 1234567890abcdef fedcba0987654320 boot\n");assert(!charge_control.action);
 reset();char text[180];memset(text,'x',160);text[160]='\n';text[161]=0;
 for(unsigned n=0;n<161;n++)i9100_chg_parse(&charge_control,text[n],I9100_CONTROL_TAG,I9100_CHARGER_TAG);
 received("I9CHC2 00000005 1234567890abcdef fedcba0987654321 boot\n");assert(charge_control.action==1);
 GINTSTS=GINTSTS_IEPINT;DAINT=2;DIEPINT(1)=DXEPINT_AHBERR;usbcdc_poll();assert(!usbcdc4210_charge_take_action() && !charge_control.action);
 reset();ring_push("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\n");ep1_kick();
 received("I9CHC2 00000006 1234567890abcdef fedcba0987654321 download\n");assert(charge_control.action==2 && !charge_action_ready);
 complete();assert(!charge_action_ready);complete();assert(!charge_action_ready);complete();assert(usbcdc4210_charge_take_action()==2);
 reset();DOEPCTL(1)=DXEPCTL_USBACTEP|DXEPCTL_MPS(512);DOEPTSIZ(1)=0;GINTSTS=GINTSTS_OEPINT;DAINT=2U<<16;DOEPINT(1)=1;
 usbcdc_poll();assert(DOEPTSIZ(1)==((1U<<19)|512) && (DOEPCTL(1)&DXEPCTL_EPENA));
 /* DTR0 and config0 cancel half-lines and untransmitted actions. DTR2
  * is RTS without DTR and must not leave a command opener active. */
 reset();received("I9CHC2 00000007 1234567890abcdef fedcba0987654321 ");
 setup(0x21,0x22,0);assert(!host_open && !charge_control.used);
 setup(0x21,0x22,2);assert(!host_open);received("boot\n");assert(!charge_control.action);
 setup(0x21,0x22,1);assert(host_open);
 received("I9CHC2 00000008 1234567890abcdef fedcba0987654321 boot\n");
 setup(0x21,0x22,0);assert(!charge_control.action && charge_control.last==8);
 reset();received("I9CHC2 00000009 1234567890abcdef fedcba0987654321 boot\n");
 setup(0,9,0);assert(!configured && !host_open && !charge_control.action && charge_control.last==9);
 received("I9CHC2 00000010 1234567890abcdef fedcba0987654321 boot\n");assert(!charge_control.action);
 reset();received("I9CHC2 0000000a 1234567890abcdef fedcba0987654321 boot\n");
 complete();assert(charge_action_ready);setup(0x21,0x22,0);assert(usbcdc4210_charge_take_action()==1);
 /* The same accepted nonce cannot be replayed after a bus reset. A
  * completed ACK remains committed even when the host closes immediately. */
 reset();received("I9CHC2 0000000b 1234567890abcdef fedcba0987654321 boot\n");
 dev_soft_init();assert(!charge_control.action && charge_control.last==11 && !configured && !host_open);
 setup(0,9,1);setup(0x21,0x22,1);received("I9CHC2 0000000b 1234567890abcdef fedcba0987654321 boot\n");assert(!charge_control.action);
 reset();received("I9CHC2 0000000c 1234567890abcdef fedcba0987654321 boot\n");complete();
 dev_soft_init();assert(usbcdc4210_charge_take_action()==1);
 reset();usbcdc4210_charge_set_boot_ready(0);
 received("I9CHC2 0000000d 1234567890abcdef fedcba0987654321 boot\n");assert(!charge_control.action);
 char reply[48];i9100_chg_reply(reply,13,1,0);assert(!strcmp(reply,"I9CHC2 0000000d ERR boot-unavailable\n"));
 complete();assert(!usbcdc4210_charge_take_action());
 received("I9CHC2 0000000e 1234567890abcdef fedcba0987654321 download\n");assert(charge_control.action==2);
 complete();assert(usbcdc4210_charge_take_action()==2);
 reset();received("I9CHC2 0000000f 1234567890abcdef fedcba0987654321 boot\n");
 GINTSTS=GINTSTS_IEPINT;DAINT=2;DIEPINT(1)=DXEPINT_XFERCOMPL|DXEPINT_AHBERR;
 usbcdc_poll();assert(!charge_action_ready && !usbcdc4210_charge_take_action());
 reset();received("I9CHC2 00000010 1234567890abcdef fedcba0987654321 boot\n");
 GINTSTS=GINTSTS_IEPINT;DAINT=2;DIEPINT(1)=DXEPINT_XFERCOMPL|DXEPINT_TIMEOUT;
 usbcdc_poll();assert(!charge_action_ready && !usbcdc4210_charge_take_action());
 reset();received("I9CHC1 00000011 1234567890abcdef boot\n");assert(!charge_control.action);
 puts("PASS production charger source/kernel qualification, sized OUT, DTR/config/reset cancellation, committed ACK, boot refusal and no nonce replay");}
'''
(out/'driver.c').write_text((repo/'drivers/samsung/dwc2cdc4210.c').read_text().replace('#include "../../board/samsung/i9100-charge-control.h"','#include "i9100-charge-control.h"'))
(out/'driver.c').write_text((out/'driver.c').read_text().replace('#include "../../board/samsung/i9100-charge-report.h"','#include "i9100-charge-report.h"'))
(out/'check.c').write_text(code)
for n,cmd in enumerate((['clang','-O1','-g','-fno-pie','-no-pie','-Wno-int-to-void-pointer-cast','-Wno-pointer-to-int-cast','-fsanitize=address,undefined','-fno-sanitize-recover=all',
    '-I'+str(repo/'include'),'-I'+str(repo/'board/samsung'),str(out/'check.c'),'-o',str(out/'check')],[str(out/'check')])):
    r=subprocess.run(cmd,text=True,capture_output=True);(out/f'command-{n}.log').write_text(r.stdout+r.stderr)
    if r.returncode:print((r.stdout+r.stderr)[-3500:],file=sys.stderr);r.check_returncode()
    if r.stdout:print(r.stdout.strip(),flush=True)
print('EVIDENCE',out,flush=True)
