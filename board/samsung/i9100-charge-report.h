#ifndef I9100_CHARGE_REPORT_H
#define I9100_CHARGE_REPORT_H
#include <stdint.h>
struct i9100_charge_report{
 unsigned sequence;uint64_t milliseconds;
 unsigned valid,percent,millivolts,charging,full,timeout,recharging;
 int temperature_deci_c,reason;uint64_t elapsed_seconds;
};
static unsigned i9100_charge_append(char *line,unsigned capacity,unsigned at,const char *text)
{
 while(*text){if(at+1U>=capacity)return 0;line[at++]=*text++;}
 line[at]=0;return at;
}
static unsigned i9100_charge_number(char *line,unsigned capacity,unsigned at,uint64_t value,unsigned negative)
{
 char digits[20];unsigned used=0;
 if(negative){if(at+1U>=capacity)return 0;line[at++]='-';}
 do{digits[used++]=(char)('0'+value%10U);value/=10U;}while(value && used<20);
 while(used){if(at+1U>=capacity)return 0;line[at++]=digits[--used];}
 line[at]=0;return at;
}
static unsigned i9100_charge_format(char *line,unsigned capacity,const struct i9100_charge_report *report)
{
 if(!line || !report || capacity<8 || report->valid>1 || report->charging>1 ||
    report->full>1 || report->timeout>1 || report->recharging>1 || !report->sequence)return 0;
 unsigned at=i9100_charge_append(line,capacity,0,"I9CHG2 seq=");
 if(!at)return 0;
 for(unsigned n=0;n<8;n++){if(at+1U>=capacity)return 0;line[at++]="0123456789abcdef"[(report->sequence>>((7U-n)*4))&15U];}
 at=i9100_charge_append(line,capacity,at," ms=");if(!at)return 0;
 for(unsigned n=0;n<16;n++){if(at+1U>=capacity)return 0;line[at++]="0123456789abcdef"[(report->milliseconds>>((15U-n)*4))&15U];}
 const char *keys[10]={" valid="," soc="," mv="," temp="," charging="," reason=",
  " full="," timeout="," recharging="," elapsed="};
 uint64_t values[10]={report->valid,report->percent,report->millivolts,
  (uint32_t)report->temperature_deci_c,report->charging,(uint32_t)report->reason,
  report->full,report->timeout,report->recharging,report->elapsed_seconds};
 for(unsigned n=0;n<10;n++){
  unsigned negative=(n==3 && report->temperature_deci_c<0) || (n==5 && report->reason<0);
  if(negative)values[n]=0U-(uint32_t)values[n];
  at=i9100_charge_append(line,capacity,at,keys[n]);if(!at)return 0;
  at=i9100_charge_number(line,capacity,at,values[n],negative);if(!at)return 0;
 }
 at=i9100_charge_append(line,capacity,at,"\n");return at;
}
#endif
