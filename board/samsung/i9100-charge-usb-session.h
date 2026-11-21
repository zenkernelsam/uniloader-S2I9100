#ifndef I9100_CHARGE_USB_SESSION_H
#define I9100_CHARGE_USB_SESSION_H
#include <stdint.h>
#include <string.h>
/* USB progress deadlines are independent of the cell's charge deadline.
 * This helper owns no hardware, reset, or retry. Default-off diagnostic
 * recovery is leased once and must pass the board's checked charger stop. */
#define I9U_TICKS_PER_SECOND 24000000ULL
enum {I9U_CLOSED=0,I9U_STATUS=1,I9U_OPEN=2,I9U_FAULT=3};
enum {I9U_NO_FAULT=0,I9U_NO_OPEN=1,I9U_CONTROL_STALL=2,I9U_IN_STALL=3,I9U_IO=4,I9U_CLOCK=5};
struct i9100_charge_usb_session {
 uint64_t configured_at,pending_at,in_started,timeout_ticks;
 unsigned setup_sequence,pending_sequence,pending_dtr,configured,opened,had_open;
 unsigned state,fault,recovery_taken,ready_pending,report_pending,in_busy;
 unsigned setup_count,ep0_completions,ep1_completions,discarded_bytes;
};
static inline int i9u_init(struct i9100_charge_usb_session *s,unsigned seconds)
{
 if(!s || (seconds && (seconds<120U || seconds>600U)))return 0;
 memset(s,0,sizeof(*s));s->timeout_ticks=(uint64_t)seconds*I9U_TICKS_PER_SECOND;return 1;
}
static inline void i9u_reset_link(struct i9100_charge_usb_session *s)
{
 s->configured=s->opened=s->pending_dtr=s->ready_pending=s->report_pending=s->in_busy=0;
 s->pending_sequence=0;s->pending_at=s->in_started=0;
 s->state=s->fault?I9U_FAULT:I9U_CLOSED;
 /* Bus resets cannot postpone an already armed diagnostic deadline or
  * erase a fault/recovery lease. Ordinary charging limits are untouched. */
}
static inline void i9u_setup(struct i9100_charge_usb_session *s)
{
 if(++s->setup_sequence==0)s->setup_sequence=1;
 s->setup_count++;s->pending_dtr=s->pending_sequence=0;s->pending_at=0;
 s->state=s->fault?I9U_FAULT:s->opened?I9U_OPEN:I9U_CLOSED;
}
static inline void i9u_configure(struct i9100_charge_usb_session *s,unsigned value,uint64_t now)
{
 s->configured=value==1;s->opened=0;
 if(s->configured && !s->configured_at)s->configured_at=now;
 s->state=s->fault?I9U_FAULT:I9U_CLOSED;
}
static inline void i9u_dtr(struct i9100_charge_usb_session *s,unsigned open,uint64_t now)
{
 s->opened=0;s->ready_pending=s->report_pending=0;
 s->pending_dtr=open?1U:2U;s->pending_sequence=s->setup_sequence;s->pending_at=now;
 s->state=s->fault?I9U_FAULT:I9U_STATUS;
}
static inline void i9u_status_done(struct i9100_charge_usb_session *s,uint64_t now)
{
 (void)now;s->ep0_completions++;
 if(!s->pending_dtr || s->pending_sequence!=s->setup_sequence || s->fault)return;
 s->opened=s->configured && s->pending_dtr==1U;
 if(s->opened){s->had_open=1;s->ready_pending=s->report_pending=1;}
 s->pending_dtr=s->pending_sequence=0;s->pending_at=0;
 s->state=s->opened?I9U_OPEN:I9U_CLOSED;
}
static inline void i9u_in_start(struct i9100_charge_usb_session *s,uint64_t now)
{s->in_started=now;s->in_busy=1;}
static inline void i9u_in_done(struct i9100_charge_usb_session *s)
{s->in_busy=0;s->in_started=0;s->ep1_completions++;}
static inline void i9u_fault(struct i9100_charge_usb_session *s,unsigned reason)
{
 if(!s->fault)s->fault=reason?reason:I9U_IO;
 s->state=I9U_FAULT;s->opened=s->ready_pending=s->report_pending=0;
}
static inline unsigned i9u_poll_deadline(struct i9100_charge_usb_session *s,uint64_t now)
{
 if(!s->timeout_ticks || s->fault || !s->configured_at || !now)return s->fault;
 if(now<s->configured_at || (s->pending_at && now<s->pending_at) ||
    (s->in_started && now<s->in_started)){i9u_fault(s,I9U_CLOCK);return s->fault;}
 if(!s->had_open && now-s->configured_at>=s->timeout_ticks)i9u_fault(s,I9U_NO_OPEN);
 else if(s->pending_dtr && now-s->pending_at>=s->timeout_ticks)i9u_fault(s,I9U_CONTROL_STALL);
 else if(s->opened && s->in_busy && now-s->in_started>=s->timeout_ticks)i9u_fault(s,I9U_IN_STALL);
 return s->fault;
}
static inline unsigned i9u_take_recovery(struct i9100_charge_usb_session *s)
{
 if(!s->timeout_ticks || !s->fault || s->recovery_taken)return 0;
 s->recovery_taken=1;return s->fault;
}

/* Two 128B records within the existing excluded top-DRAM trace page.
 * Never touch panic bytes0..47 or the charging epoch at0x100..0x17f. */
#define I9U_TRACE_MAGIC 0x55533949U
#define I9U_TRACE_LIVE_OFFSET 0x300U
#define I9U_TRACE_FAULT_OFFSET 0x400U
static inline uint32_t i9u_trace_checksum(const uint32_t words[32])
{
 const uint8_t *p=(const uint8_t *)words;uint32_t sum=2166136261U;
 for(unsigned n=0;n<124;n++)sum=(sum^p[n])*16777619U;return sum;
}
static inline void i9u_trace_publish(volatile uint32_t *slot,const uint32_t words[32])
{
 slot[0]=0;__sync_synchronize();
 for(unsigned n=1;n<32;n++)slot[n]=words[n];
 __sync_synchronize();slot[0]=words[0];__sync_synchronize();
}
#endif
