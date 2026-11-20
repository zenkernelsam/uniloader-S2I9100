#ifndef I9100_CHARGE_SENSE_H
#define I9100_CHARGE_SENSE_H
#include <stdint.h>
#include "charge/i9100_power.h"

/* Observe the existing standalone Power owner once per status report.
 * Charger/gauge registers are read only. ADC1 uses the existing bounded
 * five-conversion helper, which restores its mux/control/clock afterwards.
 * Missing readings never change the policy or imply zero current. */
struct i9100_charge_sense {
 unsigned sequence,mask,adc,enabled,stop_uncertain,revision,use_sub;
 unsigned vcell,soc,status4,mbcctrl2,muicctrl2,muicstatus2;
 uint32_t gpl2con,gpl2dat,gpl2pud;
 uint64_t started_ns,finished_ns;
};
static int i9100_charge_sense_capture(struct i9100_charge_sense *sample,
 const struct i9100_power_state *battery,struct i9100_power_hw *hw,unsigned sequence)
{
 if(!sample)return 0;
 *sample=(struct i9100_charge_sense){0};sample->sequence=sequence;
 sample->adc=sample->gpl2con=sample->gpl2dat=sample->gpl2pud=0xffffffffU;
 sample->vcell=sample->soc=0xffffU;
 sample->status4=sample->mbcctrl2=sample->muicctrl2=sample->muicstatus2=0xffU;
 if(!battery || !battery->ready || !sequence || !battery->io.now_ns || !hw || !hw->read32)return 0;
 sample->enabled=battery->enabled;sample->stop_uncertain=battery->stop_uncertain;
 sample->revision=battery->revision;sample->use_sub=battery->use_sub;
 sample->started_ns=battery->io.now_ns(battery->io.cookie);
 if(!sample->started_ns)return 0;
 unsigned adc=0;uint16_t fuel=0;uint8_t value=0;
 if(hw->write32 && hw->delay_us && i9100_power_charge_adc_read(hw,&adc)){
  sample->adc=adc;sample->mask|=1U;
 }
 if(battery->io.fuel_read){
  if(battery->io.fuel_read(battery->io.cookie,9,&fuel)){sample->vcell=fuel;sample->mask|=2U;}
  if(battery->io.fuel_read(battery->io.cookie,0xff,&fuel)){sample->soc=fuel;sample->mask|=4U;}
 }
 if(battery->io.pmic_read){
  if(battery->io.pmic_read(battery->io.cookie,0x10,&value)){sample->status4=value;sample->mask|=8U;}
  if(battery->io.pmic_read(battery->io.cookie,0x51,&value)){sample->mbcctrl2=value;sample->mask|=16U;}
 }
 if(battery->io.muic_read){
  if(battery->io.muic_read(battery->io.cookie,0x0d,&value)){sample->muicctrl2=value;sample->mask|=32U;}
  if(battery->io.muic_read(battery->io.cookie,5,&value)){sample->muicstatus2=value;sample->mask|=64U;}
 }
 sample->gpl2con=hw->read32(hw->cookie,1,0x100);
 sample->gpl2dat=hw->read32(hw->cookie,1,0x104);
 sample->gpl2pud=hw->read32(hw->cookie,1,0x108);
 if(sample->gpl2con!=0xffffffffU)sample->mask|=128U;
 if(sample->gpl2dat!=0xffffffffU)sample->mask|=256U;
 if(sample->gpl2pud!=0xffffffffU)sample->mask|=512U;
 sample->finished_ns=battery->io.now_ns(battery->io.cookie);
 return 1;
}
static void i9100_charge_sense_words(const struct i9100_charge_sense *sample,
 unsigned timing[8],unsigned registers[8])
{
 uint64_t ms=sample->started_ns/1000000ULL;
 uint64_t us=sample->finished_ns>=sample->started_ns?
  (sample->finished_ns-sample->started_ns)/1000ULL:~(uint64_t)0;
 timing[0]=sample->sequence;timing[1]=(unsigned)ms;timing[2]=(unsigned)(ms>>32);
 timing[3]=us>0xffffffffU?0xffffffffU:(unsigned)us;timing[4]=sample->mask;
 timing[5]=sample->adc;timing[6]=sample->enabled;timing[7]=sample->stop_uncertain;
 registers[0]=sample->sequence;registers[1]=sample->vcell;registers[2]=sample->soc;
 registers[3]=sample->status4|(sample->mbcctrl2<<8);
 registers[4]=sample->muicctrl2|(sample->muicstatus2<<8)|
  ((sample->revision&255U)<<16)|((sample->use_sub&1U)<<24);
 registers[5]=sample->gpl2con;registers[6]=sample->gpl2dat;registers[7]=sample->gpl2pud;
}
#endif
