#ifndef I9100_RTC_TIME_H
#define I9100_RTC_TIME_H
#include <stdint.h>
/* MAX8997 RTC @0x06, observed CONTROL BCD_EN bit0 / MODEL24 bit1.
 * Accept documented binary or packed-BCD 24-hour data without rewriting
 * the clock, mode, alarm, UPDATE, WTSR or SMPL. Unqualified 12-hour layouts
 * remain rejected. Local epoch is RTC seconds since 2000. */
static inline int i9100_rtc_number(unsigned raw,unsigned bcd,unsigned *number)
{
 if(bcd){
  if((raw&15U)>9U || (raw>>4)>9U)return 0;
  raw=(raw>>4)*10U+(raw&15U);
 }
 *number=raw;return 1;
}
static inline int i9100_rtc_decode(const uint8_t data[7],unsigned control,uint64_t *seconds)
{
 if(!data || !seconds || !(control&2U) ||
    !data[3] || data[3]>64U || (data[3]&(data[3]-1U)))return 0;
 unsigned bcd=control&1U,second,minute,hour,month,year,day;
 unsigned hour_mask=bcd?0x3fU:0x1fU;
 if(data[2]&~(hour_mask|0x40U))return 0;
 if(!i9100_rtc_number(data[0],bcd,&second) || second>=60U ||
    !i9100_rtc_number(data[1],bcd,&minute) || minute>=60U ||
    !i9100_rtc_number(data[2]&hour_mask,bcd,&hour) || hour>=24U ||
    !i9100_rtc_number(data[4],bcd,&month) || !month || month>12U ||
    !i9100_rtc_number(data[5],bcd,&year) || year>(bcd?99U:127U) ||
    !i9100_rtc_number(data[6],bcd,&day) || !day)return 0;
 year+=2000U;
 const unsigned lengths[12]={31,28,31,30,31,30,31,31,30,31,30,31};
 unsigned leap=year%4U==0U && (year%100U!=0U || year%400U==0U);
 if(day>lengths[month-1U]+(month==2U && leap))return 0;
 uint64_t days=0;
 for(unsigned y=2000;y<year;y++)days+=365U+(y%4U==0U && (y%100U!=0U || y%400U==0U));
 for(unsigned m=1;m<month;m++)days+=lengths[m-1U]+(m==2U && leap);
 days+=day-1U;*seconds=((days*24U+hour)*60U+minute)*60U+second;return 1;
}
#endif
