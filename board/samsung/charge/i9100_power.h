#ifndef I9100_POWER_H
#define I9100_POWER_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct i9100_power_io {
 void *cookie;
 int (*pmic_read)(void *,unsigned,uint8_t *);
 int (*pmic_write)(void *,unsigned,uint8_t);
 int (*fuel_read)(void *,unsigned,uint16_t *);
 int (*adc_read)(void *,unsigned,unsigned *);
 int (*sub_read)(void *,unsigned *,unsigned *); /* connected, actually charging */
 int (*sub_enable)(void *,unsigned);
 int (*muic_read)(void *,unsigned,uint8_t *);  /* MUIC @0x25 on the PMIC bus */
 int (*muic_write)(void *,unsigned,uint8_t);
 uint64_t (*now_ns)(void *);
};
enum { I9100_POWER_OK=0,I9100_POWER_IO=-1,I9100_POWER_REVISION=-2,
 I9100_POWER_TEMPERATURE=-3,I9100_POWER_FULL=-4,I9100_POWER_TIMEOUT=-5,
 I9100_POWER_NO_BATTERY=-6,I9100_POWER_OFFLINE=-7 };
struct i9100_power_state {
 struct i9100_power_io io;
 unsigned ready,revision,use_sub,enabled,valid,connected,present,charging;
 unsigned cable_type; /* last MUIC STATUS2 CHGTYP read; 0x7 = unknown */
 unsigned millivolts,percent,adc,full,timeout,thermal_block,errors;
 unsigned recharging,recharge_low_count;
 int temperature_deci_c,reason;
 uint64_t charge_start;
 uint64_t charge_refresh;
 /* Duration inherited across an MCT reset; zero for an ordinary boot. */
 uint64_t charge_elapsed_base;
 uint64_t refresh_elapsed_base;
 /* A failed disable/readback is not evidence that either charger is off. */
 unsigned stop_uncertain;
};
static inline uint64_t i9100_power_elapsed(uint64_t start,uint64_t base,uint64_t now)
{
 if(!start)return base;
 if(now<start || (~(uint64_t)0)-base<now-start)return ~(uint64_t)0;
 return base+now-start;
}
int i9100_power_init(struct i9100_power_state *,const struct i9100_power_io *,unsigned);
int i9100_power_poll(struct i9100_power_state *);
int i9100_power_stop(struct i9100_power_state *);
int i9100_power_temperature(unsigned channel,unsigned adc,int *temperature);

/* GPIO1/2, CMU and ADC regions, all explicitly mapped uncached by the wrapper. */
struct i9100_power_hw {
 void *cookie;
 uint32_t (*read32)(void *,unsigned,unsigned);
 void (*write32)(void *,unsigned,unsigned,uint32_t);
 void (*delay_us)(void *,unsigned);
 void (*enter)(void *);
 void (*leave)(void *);
};
int i9100_power_pmic_read(void *,unsigned,uint8_t *);
int i9100_power_pmic_write(void *,unsigned,uint8_t);
int i9100_power_muic_read(void *,unsigned,uint8_t *);
int i9100_power_muic_write(void *,unsigned,uint8_t);
int i9100_power_fuel_read(void *,unsigned,uint16_t *);
int i9100_power_rtc_seconds(void *,uint64_t *);
/* One raw observation of each RTC transaction, published with an odd/even
 * sequence. A failure remains a failure; no mode writes, fallback or retry. */
struct i9100_rtc_read {
 uint32_t version,sequence,read_mask,controls,first_low,first_high,last_low,last_high;
 uint32_t status,seconds_low,seconds_high,reserved;
};
extern volatile uint32_t i9100_rtc_read_diag[12];
int i9100_power_rtc_snapshot(void *,uint64_t *,struct i9100_rtc_read *);
int i9100_power_adc_read(void *,unsigned,unsigned *);
/* EUR U1 charge-current sense, fixed ADC1; thermistor API remains ADC6/7. */
int i9100_power_charge_adc_read(void *,unsigned *);
int i9100_power_sub_read(void *,unsigned *,unsigned *);
int i9100_power_sub_enable(void *,unsigned);
unsigned i9100_power_revision(struct i9100_power_hw *);
#ifdef __cplusplus
}
#endif
#endif
