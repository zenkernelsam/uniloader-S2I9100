#ifndef I9100_RTC_TIME_H
#define I9100_RTC_TIME_H
#include <stdint.h>
/* MAX8997 RTC @ 0x06, binary 24-hour mode, registers 0x10..0x16.
 * Decode the original register format without changing time, alarms, masks,
 * WTSR/SMPL or UPDATE registers. Epoch is local RTC seconds since 2000. */
static inline int i9100_rtc_decode(const uint8_t data[7],unsigned control,uint64_t *seconds)
{
 if(!data || !seconds || (control&3U)!=2U ||
    data[0]>=60U || data[1]>=60U || (data[2]&~0x5fU) || (data[2]&31U)>=24U ||
    !data[3] || data[3]>64U || (data[3]&(data[3]-1U)) ||
    !data[4] || data[4]>12U || data[5]>127U || !data[6])return 0;
 unsigned year=2000U+data[5],month=data[4],day=data[6];
 const unsigned lengths[12]={31,28,31,30,31,30,31,31,30,31,30,31};
 unsigned leap=year%4U==0U && (year%100U!=0U || year%400U==0U);
 if(day>lengths[month-1U]+(month==2U && leap))return 0;
 uint64_t days=0;
 for(unsigned y=2000;y<year;y++)days+=365U+(y%4U==0U && (y%100U!=0U || y%400U==0U));
 for(unsigned m=1;m<month;m++)days+=lengths[m-1U]+(m==2U && leap);
 days+=day-1U;*seconds=((days*24U+(data[2]&31U))*60U+data[1])*60U+data[0];return 1;
}
#endif
