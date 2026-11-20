/* GT-I9100 U1 EUR charging policy. Hardware definitions follow Samsung's
 * max8997_charger_u1.c, max8922_charger_u1.c and sec_battery_u1.c.
 * USB-rate charging only; no AC-current programming pulses. */
#include "i9100_power.h"
#include "i9100_battery_temperature.h"

static int update(struct i9100_power_state *s,unsigned reg,uint8_t mask,uint8_t value)
{
 uint8_t old,check;
 if(!s->io.pmic_read(s->io.cookie,reg,&old))return 0;
 uint8_t next=(old&~mask)|(value&mask);
 if(next!=old && !s->io.pmic_write(s->io.cookie,reg,next))return 0;
 return s->io.pmic_read(s->io.cookie,reg,&check) && (check&mask)==(next&mask);
}
int i9100_power_temperature(unsigned channel,unsigned adc,int *temperature)
{
 const struct i9100_temp_point *table=channel==7?i9100_temp_adc7:i9100_temp_adc6;
 unsigned count=channel==7?sizeof(i9100_temp_adc7)/sizeof(*table):sizeof(i9100_temp_adc6)/sizeof(*table);
 if(!temperature || (channel!=6 && channel!=7) || adc<table[0].adc || adc>table[count-1].adc)return 0;
 for(unsigned n=1;n<count;n++)if(adc<=table[n].adc){
  int span=(int)table[n].adc-table[n-1].adc;
  *temperature=table[n-1].temperature+
   ((int)adc-(int)table[n-1].adc)*(table[n].temperature-table[n-1].temperature)/span;
  return 1;
 }
 return 0;
}
int i9100_power_stop(struct i9100_power_state *s)
{
 int ok=1;
 if(s->use_sub && !s->io.sub_enable(s->io.cookie,0))ok=0;
 if(!update(s,0x51,0xc0,0))ok=0; /* Never leave both chargers enabled. */
 s->enabled=0;s->charging=0;
 return ok;
}
int i9100_power_init(struct i9100_power_state *s,const struct i9100_power_io *io,unsigned revision)
{
 if(!s || !io || !io->pmic_read || !io->pmic_write || !io->fuel_read ||
  !io->adc_read || !io->sub_read || !io->sub_enable || !io->now_ns)return I9100_POWER_IO;
 s->io=*io;s->revision=revision;s->use_sub=revision>=8 && revision<=15;
 s->ready=s->enabled=s->valid=s->connected=s->present=s->charging=0;
 s->millivolts=s->percent=s->adc=s->full=s->timeout=s->thermal_block=s->errors=0;
 s->recharging=s->recharge_low_count=s->cable_type=0;s->charge_refresh=0;
 s->temperature_deci_c=0;s->charge_start=0;s->charge_elapsed_base=s->refresh_elapsed_base=0;s->reason=I9100_POWER_REVISION;
 if(revision>15)return s->reason;
 uint8_t id,again;
 if(!io->pmic_read(io->cookie,0,&id) || id==0xff ||
  !io->pmic_read(io->cookie,0,&again) || id!=again)goto failure;
 if(!i9100_power_stop(s))goto failure;
 /* Main charger, per Samsung max8997_charger_u1.c: MBCCV=0 -> 4.2V CV,
  * MBCICHFC=5 -> 450mA USB rate (TA types get 9 = 650mA at enable),
  * ITOPOFF=5 -> 100mA, AUTOSTOP disabled (vendor relies on software
  * monitoring like our timeout below), five-hour hardware TFCH kept as
  * a safety net vendor lacks. */
 if(!s->use_sub && (!update(s,0x50,0x70,0x20) || !update(s,0x52,0x0f,0) ||
  !update(s,0x53,0x0f,5) || !update(s,0x54,0x0f,5) || !update(s,0x55,0x20,0)))goto failure;
 /* mach-u1 max8997_muic_set_safeout(AP_USB_MODE): the VBUS-to-charger
  * power rail runs through ESAFEOUT1 (SAFEOUTCTRL bit6). Without it the
  * charger reports DCINOK+charging yet zero current reaches the cell. */
 if(!s->use_sub && !update(s,0x5a,0x40,0x40))goto failure;
 /* MUIC CONTROL2(0x0d): CPEn=bit2 routes VBUS into the charger path,
  * LowPwr=bit5. Upstream extcon sets CPEn on every attach. Ensure it
  * once at init; an absent MUIC (old boards) fails soft. */
 if(s->io.muic_read && s->io.muic_write){
  uint8_t c2;
  if(s->io.muic_read(s->io.cookie,0x0d,&c2)){
   uint8_t want=(uint8_t)((c2|0x04)&~0x20);
   if(want!=c2)s->io.muic_write(s->io.cookie,0x0d,want);
  }
 }
 s->cable_type=7;s->ready=1;s->reason=I9100_POWER_OFFLINE;return 0;
failure:
 (void)i9100_power_stop(s);s->errors++;s->reason=I9100_POWER_IO;return s->reason;
}
int i9100_power_poll(struct i9100_power_state *s)
{
 uint8_t status;uint16_t version,fuel_status,voltage,soc;
 unsigned adc,connected=0,charging=0;int temp;
 if(!s || !s->ready)return I9100_POWER_REVISION;
 s->valid=0;s->charging=0;
 if(!s->io.pmic_read(s->io.cookie,0x10,&status) ||
  !s->io.fuel_read(s->io.cookie,0x21,&version) || !version || version==0xffff ||
  !s->io.fuel_read(s->io.cookie,0,&fuel_status) || fuel_status==0xffff ||
  !s->io.fuel_read(s->io.cookie,9,&voltage) ||
  !s->io.fuel_read(s->io.cookie,0xff,&soc) || soc>105U*256U)goto failure;
 s->millivolts=(uint32_t)voltage*625U/8000U;
 s->percent=soc>=100U*256U?100U:soc/256U;
 if(s->millivolts<2500 || s->millivolts>4300)goto failure;
 if(s->use_sub){if(!s->io.sub_read(s->io.cookie,&connected,&charging))goto failure;}
 else connected=(status&2U)!=0;
 s->connected=connected;s->present=!(status&4U) && !(fuel_status&8U);
 if(!s->io.adc_read(s->io.cookie,s->use_sub?7:6,&adc) ||
  !i9100_power_temperature(s->use_sub?7:6,adc,&temp))goto failure;
 s->adc=adc;s->temperature_deci_c=temp;s->valid=1;
 if(!connected){
  s->full=s->timeout=s->thermal_block=0;s->recharging=s->recharge_low_count=0;
  s->charge_start=s->charge_refresh=0;s->reason=I9100_POWER_OFFLINE;
  s->charge_elapsed_base=s->refresh_elapsed_base=0;
  if(!i9100_power_stop(s))goto failure;return 0;
 }
 if(!s->present){s->reason=I9100_POWER_NO_BATTERY;goto stop;}
 if(temp<=0 || temp>=450)s->thermal_block=1;
 else if(temp>=50 && temp<=400)s->thermal_block=0;
 if(s->thermal_block){s->reason=I9100_POWER_TEMPERATURE;goto stop;}
 /* U1 vendor resumes after a full stop when voltage falls below its
  * 4.13/4.15V recharge threshold. Use the stricter 4.13V plus SOC<=95
  * and two valid cool samples; do not clear an expired safety timeout. */
 unsigned resume_full=0;
 if(s->full && !s->timeout && s->millivolts<4130 && s->percent<=95 && temp>=50 && temp<=400){
  if(++s->recharge_low_count>=2){
   s->full=0;s->recharging=1;s->recharge_low_count=0;
   s->charge_start=s->charge_refresh=0;resume_full=1;
   s->charge_elapsed_base=s->refresh_elapsed_base=0;
  }
 }else s->recharge_low_count=0;
 /* A stale main-charger topoff bit must not immediately cancel the
  * validated restart before its enable transition can clear the bit. */
 if(!resume_full && (s->millivolts>=4200 || (s->percent>=100 && s->millivolts>=4150) ||
  (!s->use_sub && (status&1) && s->millivolts>=4100))){
  s->full=1;s->recharging=0;s->charge_start=s->charge_refresh=0;
  s->charge_elapsed_base=s->refresh_elapsed_base=0;
 }
 if(s->full){s->reason=I9100_POWER_FULL;goto stop;}
 uint64_t now=s->io.now_ns(s->io.cookie);
 if(!now)goto failure;
 uint64_t limit=(s->recharging?5400ULL:18000ULL)*1000000000ULL;
 if(i9100_power_elapsed(s->charge_start,s->charge_elapsed_base,now)>=limit)s->timeout=1;
 if(s->timeout){s->reason=I9100_POWER_TIMEOUT;goto stop;}
 /* Vendor refreshes the charger every ten minutes. The software cycle
  * start remains unchanged: refresh never postpones the safety deadline. */
 if(s->enabled && s->charge_refresh && i9100_power_elapsed(s->charge_refresh,s->refresh_elapsed_base,now)>=600ULL*1000000000ULL){
  if(!i9100_power_stop(s))goto failure;
 }
 if(!s->enabled){
  if(s->use_sub){
   if(!update(s,0x51,0xc0,0) || !s->io.sub_enable(s->io.cookie,1))goto failure;
  }else{
   /* Vendor cable-type selection: MUIC STATUS2(0x05) CHGTYP[2:0];
    * 3/4/5 = TA adapter -> 650mA (code 9); USB/unknown -> 450mA (5). */
   unsigned chgtyp=0,cur=5;
   if(s->io.muic_read){
    uint8_t st2;
    if(s->io.muic_read(s->io.cookie,0x05,&st2)){
     chgtyp=st2&7;s->cable_type=chgtyp;
     if(chgtyp>=3 && chgtyp<=5)cur=9;
    }
   }
   if(!update(s,0x53,0x0f,cur) || !update(s,0x51,0xc0,0xc0))goto failure;
  }
  s->enabled=1;if(!s->charge_start)s->charge_start=now;s->charge_refresh=now;s->refresh_elapsed_base=0;
 }
 /* Status comes from the chip/pin, not just from the enable command. */
 if(s->use_sub){if(!s->io.sub_read(s->io.cookie,&connected,&charging))goto failure;s->charging=connected && charging;}
 else {
  if(!s->io.pmic_read(s->io.cookie,0x10,&status))goto failure;
  s->charging=(status&2) && !(status&4) && (status&8) && (status&0x30) && !(status&0x40);
 }
 s->reason=I9100_POWER_OK;return 0;
stop:
 if(s->reason!=I9100_POWER_FULL)s->recharge_low_count=0;
 if(!i9100_power_stop(s))goto failure;return 0;
failure:
 s->recharge_low_count=0;
 (void)i9100_power_stop(s);s->valid=0;s->errors++;s->reason=I9100_POWER_IO;return s->reason;
}
