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
/* This variant exercises the driver's real delay-service scheduling. The
 * charger supervisor is modeled; controller reset/FIFO remains the old model. */
#define CONFIG_SAMSUNG_I9100 1
#define I9100_STANDALONE_CHARGE_BUILD 1
static unsigned supervisor_calls,console_calls;
void i9100_boot_charge_service(void){supervisor_calls++;}
void i9100_boot_charge_stage(unsigned stage){(void)stage;}
void i9100_boot_charge_finish(void){}
void i9100_boot_charge_failure(unsigned reason){(void)reason;}
void printk(int level,const char*fmt,...){(void)level;(void)fmt;console_calls++;}
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
 reset();console_calls=0;setup(0x21,0x22,1);assert(!console_calls);
 charge_identity=0;setup(0x21,0x22,1);assert(console_calls>0);
 supervisor_calls=charge_delay_quanta=0;
 for(unsigned n=0;n<999;n++)udelay(1);
 assert(!supervisor_calls);udelay(1);assert(supervisor_calls==1);
 udelay(2500);assert(supervisor_calls==3 && charge_delay_quanta==500);
 /* A late opener must drain the queued status and READY over multiple
  * short packets, not lose its second packet after the initial 64 bytes. */
 reset();host_open=0;
 struct i9100_charge_report report={.sequence=1,.milliseconds=7900,.valid=1,
  .percent=2,.millivolts=3508,.charging=1,.temperature_deci_c=250,.elapsed_seconds=5};
 usbcdc4210_charge_timed_report(&report);
 unsigned initial_written=tx_written_total;assert(initial_written>64 && ep1_busy);
 unsigned first_completed=ep1_transfer_total;assert(first_completed==64);
 setup(0x21,0x22,1);assert(host_open && tx_written_total==initial_written+47);
 unsigned packet_count=0;
 while(tx_completed_total<tx_written_total && packet_count++<10){complete();}
 assert(packet_count>=3 && tx_completed_total==tx_written_total && tx_head==tx_tail && !ep1_busy);
 assert(!charge_action_ready && !usbcdc4210_charge_take_action());
 unsigned diagnostic_at=tx_head,diagnostic_before=tx_written_total;
 usbcdc4210_charge_transport_report();assert(tx_written_total==diagnostic_before+80U);
 assert(!memcmp(txring+diagnostic_at,"I9UT1 ",6));
 assert(txring[(diagnostic_at+77U)&(TXRING-1U)]=='\n');
 /* A real late opener can find hours of buffered charger messages. Logs
  * must be dropped whole and leave room for the exact READY handshake. */
 reset();host_open=0;GINTSTS=0;charge_log_dropped=0;
 char status_line[256];unsigned status_bytes=i9100_charge_format(status_line,sizeof(status_line),&report)+2U;
 unsigned accepted=0,dropped=0;
 for(unsigned n=0;n<512;n++){
  unsigned before=tx_written_total;usbcdc4210_charge_timed_report(&report);
  unsigned delta=tx_written_total-before;assert(!delta || delta==status_bytes);
  if(delta)accepted++;else dropped++;
 }
 unsigned backlog=tx_written_total;
 assert(accepted && dropped && charge_log_dropped==dropped);
 assert(((tx_tail-tx_head-1U)&(TXRING-1U))>=128U);
 setup(0x21,0x22,1);assert(tx_written_total==backlog+47U);
 char ready_line[64];unsigned ready_bytes=i9100_chg_ready(ready_line,I9100_CONTROL_TAG,I9100_CHARGER_TAG);
 assert(ready_bytes==47);
 for(unsigned n=0;n<ready_bytes;n++)assert(txring[(tx_head-ready_bytes+n)&(TXRING-1U)]==ready_line[n]);
 assert(!charge_action_ready && !usbcdc4210_charge_take_action());
 diagnostic_at=tx_head;diagnostic_before=tx_written_total;
 unsigned available=(tx_tail-tx_head-1U)&(TXRING-1U);
 /* Diagnostic records preserve the same control reserve as background
  * status. Whichever capacity applies, it is never a partial append. */
 usbcdc4210_charge_transport_report();
 assert(tx_written_total-diagnostic_before==(available>=208U?80U:0U));
 if(available<208U)assert(tx_head==diagnostic_at);
 reset();received("I9CHC2 00000001 1234567890abcdef fedcba0987654321 boot\n");assert(charge_control.action==1 && !usbcdc4210_charge_take_action());
 complete();assert(usbcdc4210_charge_take_action()==1 && !usbcdc4210_charge_take_action());
 assert(charge_control.leased && !usbcdc4210_charge_release_action(2));
 assert(usbcdc4210_charge_release_action(1) && !charge_control.action && !charge_control.leased);
 received("I9CHC2 00000001 1234567890abcdef fedcba0987654321 boot\n");assert(!charge_control.action);
 received("I9CHC2 00000002 1234567890abcdee fedcba0987654321 download\n");assert(!charge_control.action);
 received("I9CHC2 00000003 1234567890abcdef fedcba0987654321 flash\n");assert(!charge_control.action);
 received("I9CHC2 00000004 1234567890abcdef fedcba0987654321 download\n");assert(charge_control.action==2);complete();assert(usbcdc4210_charge_take_action()==2);
 assert(usbcdc4210_charge_release_action(2));
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
 /* The 500ms main-loop handoff is still one action. A later nonce must
  * not be ACKed and then silently dropped while that action is leased. */
 reset();received("I9CHC2 00000012 1234567890abcdef fedcba0987654321 boot\n");complete();
 assert(usbcdc4210_charge_take_action()==1);
 received("I9CHC2 00000013 1234567890abcdef fedcba0987654321 download\n");
 assert(charge_control.last==0x12 && charge_control.action==1 && !charge_action_ready);
 setup(0x21,0x22,0);assert(charge_control.leased && charge_control.action==1);
 dev_soft_init();assert(charge_control.leased && charge_control.action==1 && !usbcdc4210_charge_take_action());
 assert(!usbcdc4210_charge_release_action(2) && usbcdc4210_charge_release_action(1));
 assert(!charge_control.action && !charge_control.leased && charge_control.last==0x12);
 setup(0,9,1);setup(0x21,0x22,1);
 received("I9CHC2 00000012 1234567890abcdef fedcba0987654321 boot\n");assert(!charge_control.action);
 received("I9CHC2 00000013 1234567890abcdef fedcba0987654321 download\n");
 /* Reconnect queued a fresh READY ahead of this reply. Model every
  * completed FIFO packet; one packet cannot complete both messages. */
 for(unsigned n=0;n<8 && !charge_action_ready;n++)complete();
 assert(usbcdc4210_charge_take_action()==2 && charge_control.leased);
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
