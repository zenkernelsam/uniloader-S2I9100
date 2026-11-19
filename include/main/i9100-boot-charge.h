#ifndef I9100_BOOT_CHARGE_H
#define I9100_BOOT_CHARGE_H
/* Only a qualified standalone-charge-to-XNU transition owns this service.
 * Ordinary boots and other boards keep their existing paths. */
/* I9BS1 stages: 1 charger return, 2 board ready, 3 late init, 4 staging,
 * 5 decode done, 6 host wait, 7 checked charger stop, 8 held for recharge,
 * 9 failed bootstrap parked in supervised charger maintenance. */
#if defined(CONFIG_SAMSUNG_I9100) && defined(I9100_STANDALONE_CHARGE_BUILD)
void i9100_boot_charge_service(void);
void i9100_boot_charge_stage(unsigned stage);
void i9100_boot_charge_finish(void);
void i9100_boot_charge_failure(unsigned reason);
#else
static inline void i9100_boot_charge_service(void){}
static inline void i9100_boot_charge_stage(unsigned stage){(void)stage;}
static inline void i9100_boot_charge_finish(void){}
static inline void i9100_boot_charge_failure(unsigned reason){(void)reason;}
#endif
#endif
