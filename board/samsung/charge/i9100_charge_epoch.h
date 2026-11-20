#ifndef I9100_CHARGE_EPOCH_H
#define I9100_CHARGE_EPOCH_H
#include <stdint.h>
#include <string.h>
#include "i9100_power.h"

#define I9100_CHARGE_EPOCH_MAGIC 0x45433949U
#define I9100_CHARGE_EPOCH_MARKER 0x7766ec01U
/* Within the already excluded top-DRAM trace page; bytes 0..47 belong to
 * panic diagnostics and remain untouched. This is RAM, never a flash write. */
#define I9100_CHARGE_EPOCH_OFFSET 0x100U
#define I9100_CHARGE_EPOCH_WORDS 32U
struct I9100ChargeEpoch {
 uint32_t magic,version,bytes,flags,revision,sub_charger,valid,connected,present;
 uint32_t full,timeout,thermal_block,recharging,recharge_low_count,enabled,charging;
 uint32_t percent,millivolts,temperature_deci_c,reason,errors;
 uint32_t sampled_low,sampled_high,elapsed_low,elapsed_high,refresh_low,refresh_high;
 uint32_t rtc_low,rtc_high,route,sequence,checksum;
};
typedef char I9100ChargeEpochSize[(sizeof(struct I9100ChargeEpoch)==128)?1:-1];
enum {I9E_NONE=0,I9E_RESTORED=1,I9E_OFFLINE=2,I9E_REJECTED=3,I9E_EXPIRED=4};

static inline uint32_t i9100_charge_epoch_checksum(const struct I9100ChargeEpoch *r)
{
 const uint8_t *p=(const uint8_t*)r;uint32_t hash=2166136261U;
 for(unsigned n=0;n<124U;n++){hash^=p[n];hash*=16777619U;}
 return hash;
}
static inline int i9100_charge_epoch_valid(const struct I9100ChargeEpoch *r)
{
 return r->magic==I9100_CHARGE_EPOCH_MAGIC && r->version==2U &&
  r->bytes==sizeof(*r) && r->flags==3U && r->sequence && r->revision<=15U &&
  r->sub_charger==(r->revision>=8U) && r->valid<=1U && r->connected<=1U &&
  r->present<=1U && r->full<=1U && r->timeout<=1U && r->thermal_block<=1U &&
  r->recharging<=1U && r->recharge_low_count<=2U && r->enabled<=1U &&
  r->charging<=r->enabled && r->percent<=100U && r->route<=1U &&
  !(r->full && r->recharging) && r->checksum==i9100_charge_epoch_checksum(r);
}
static inline void i9100_charge_epoch_encode(struct I9100ChargeEpoch *r,
 const struct i9100_power_state *s,uint64_t now_ns,unsigned sequence,unsigned rtc_valid,uint64_t rtc_seconds)
{
 memset(r,0,sizeof(*r));if(!s || !s->ready || !now_ns || !sequence)return;
 r->magic=I9100_CHARGE_EPOCH_MAGIC;r->version=2;r->bytes=sizeof(*r);r->flags=rtc_valid?3U:1U;
 r->revision=s->revision;r->sub_charger=s->use_sub;r->valid=s->valid;
 r->connected=s->connected;r->present=s->present;r->full=s->full;r->timeout=s->timeout;
 r->thermal_block=s->thermal_block;r->recharging=s->recharging;r->recharge_low_count=s->recharge_low_count;
 r->enabled=s->enabled;r->charging=s->charging;r->percent=s->percent;r->millivolts=s->millivolts;
 r->temperature_deci_c=(uint32_t)s->temperature_deci_c;r->reason=(uint32_t)s->reason;r->errors=s->errors;
 r->sampled_low=(uint32_t)now_ns;r->sampled_high=(uint32_t)(now_ns>>32);
 uint64_t elapsed=i9100_power_elapsed(s->charge_start,s->charge_elapsed_base,now_ns);
 uint64_t refresh=i9100_power_elapsed(s->charge_refresh,s->refresh_elapsed_base,now_ns);
 if(s->charge_start && !elapsed)elapsed=1U;
 if(s->charge_refresh && !refresh)refresh=1U;
 r->elapsed_low=(uint32_t)elapsed;r->elapsed_high=(uint32_t)(elapsed>>32);
 r->refresh_low=(uint32_t)refresh;r->refresh_high=(uint32_t)(refresh>>32);
 r->rtc_low=(uint32_t)rtc_seconds;r->rtc_high=(uint32_t)(rtc_seconds>>32);
 r->sequence=sequence;r->checksum=i9100_charge_epoch_checksum(r);
}
static inline void i9100_charge_epoch_publish(volatile uint32_t *slot,const struct I9100ChargeEpoch *r)
{
 const uint8_t *bytes=(const uint8_t *)r;
 slot[0]=0;__sync_synchronize();
 for(unsigned n=1;n<I9100_CHARGE_EPOCH_WORDS;n++){
  uint32_t word;memcpy(&word,bytes+n*4U,4);slot[n]=word;
 }
 __sync_synchronize();slot[0]=r->magic;__sync_synchronize();
}
static inline int i9100_charge_epoch_read(const volatile uint32_t *slot,struct I9100ChargeEpoch *r)
{
 uint32_t magic=slot[0];__sync_synchronize();
 uint32_t sequence=slot[30];
 for(unsigned n=0;n<I9100_CHARGE_EPOCH_WORDS;n++){
  uint32_t word=slot[n];memcpy((uint8_t *)r+n*4U,&word,4);
 }
 __sync_synchronize();
 return magic==slot[0] && magic==r->magic && sequence==slot[30] &&
  sequence==r->sequence && i9100_charge_epoch_valid(r);
}
/* Only the ordinary, already synced halt hook seals route=1. No hardware,
 * logging, allocation, wait or retry after IRQs are masked. An uncertain
 * publication is explicit; the loader must stop rather than grant a period. */
static inline uint32_t i9100_charge_epoch_seal(volatile uint32_t *destination,
 const volatile uint32_t *live,uint64_t now_ns)
{
 struct I9100ChargeEpoch r;
 if(!i9100_charge_epoch_read(live,&r)){
  memset(&r,0,sizeof(r));r.magic=I9100_CHARGE_EPOCH_MAGIC;r.version=2;r.bytes=sizeof(r);
 }
 uint64_t sampled=((uint64_t)r.sampled_high<<32)|r.sampled_low;
 /* Shutdown may already have canceled the Power timer. The RTC gap is
  * measured from this original sample, so do not add the same shutdown time
  * twice. This record never supplies stale fuel/ADC data to a new poll. */
 if(!sampled || now_ns<sampled || now_ns-sampled>600000000000ULL)r.flags=0;
 r.route=1;
 r.checksum=i9100_charge_epoch_checksum(&r);i9100_charge_epoch_publish(destination,&r);
 return r.checksum;
}
static inline unsigned i9100_charge_epoch_restore(struct i9100_power_state *s,
 const struct I9100ChargeEpoch *r,unsigned marked,uint64_t now_ns,unsigned rtc_valid,uint64_t rtc_seconds)
{
 if(!marked)return I9E_NONE;
 if(!s || !s->ready)return I9E_REJECTED;
 if(!r || !i9100_charge_epoch_valid(r) || r->route!=1U || !now_ns || !rtc_valid ||
    r->revision!=s->revision || r->sub_charger!=s->use_sub)goto reject;
 {
  uint64_t elapsed=((uint64_t)r->elapsed_high<<32)|r->elapsed_low;
  uint64_t refresh=((uint64_t)r->refresh_high<<32)|r->refresh_low;
  uint64_t rtc=((uint64_t)r->rtc_high<<32)|r->rtc_low;
  /* S-Boot resets MCT. The actual MAX8997 battery-backed RTC dates the gap;
   * add two seconds for RTC quantization and bounded caller sampling skew.
   * Missing/backwards/large gaps
   * stop charging instead of granting another period. Never write the RTC. */
  if(rtc_seconds<rtc || rtc_seconds-rtc>600U || elapsed>86400000000000ULL ||
     refresh>86400000000000ULL)goto reject;
  if(!r->connected){
   if(elapsed || refresh || r->full || r->timeout || r->thermal_block ||
      r->recharging || r->enabled || r->charging)goto reject;
   return I9E_OFFLINE;
  }
  if(!elapsed && !r->full && !r->timeout && r->enabled)goto reject;
  if(r->full && (elapsed || refresh || r->enabled || r->charging))goto reject;
  uint64_t gap=(rtc_seconds-rtc+2U)*1000000000ULL;
  s->charge_start=elapsed?now_ns:0;s->charge_refresh=refresh?now_ns:0;
  s->charge_elapsed_base=elapsed?elapsed+gap:0;
  s->refresh_elapsed_base=refresh?refresh+gap:0;
  s->full=r->full;s->timeout=r->timeout;
  s->thermal_block=r->thermal_block;s->recharging=r->recharging;
  s->recharge_low_count=0; /* New fuel/ADC samples own recharge qualification. */
  uint64_t limit=(s->recharging?5400ULL:18000ULL)*1000000000ULL;
  if(s->timeout || i9100_power_elapsed(s->charge_start,s->charge_elapsed_base,now_ns)>=limit){
   s->timeout=1;s->reason=I9100_POWER_TIMEOUT;return I9E_EXPIRED;
  }
  return I9E_RESTORED;
 }
reject:
 s->timeout=1;s->reason=I9100_POWER_TIMEOUT;return I9E_REJECTED;
}
#endif
