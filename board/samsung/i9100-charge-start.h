#ifndef I9100_CHARGE_START_H
#define I9100_CHARGE_START_H
#include <stdint.h>
#include "charge/i9100_power.h"
/* Startup margin is an explicit board-port qualification, not a fuel-gauge
 * recalibration or a change to the charger. A charging cell can briefly read
 * 3.5V then collapse under XNU's load. Require eleven valid samples spanning
 * at least ten real seconds; dense callbacks cannot shorten that recovery.
 * Every bad/stale sample revokes admission. */
struct i9100_charge_start { unsigned samples, ready, blocked_presses; uint64_t last_ns,first_ns; };
static void i9100_charge_start_update(struct i9100_charge_start *gate,
                                    const struct i9100_power_state *battery,
                                    unsigned poll_result,uint64_t now_ns)
{
 unsigned healthy=battery && !poll_result && battery->valid && battery->present &&
  battery->percent>=3U && battery->millivolts>=3600U &&
  battery->temperature_deci_c>=50 && battery->temperature_deci_c<=400 &&
  !battery->thermal_block && !battery->timeout;
 if(!gate)return;
 if(!healthy || !now_ns || (gate->last_ns &&
    (now_ns<=gate->last_ns || now_ns-gate->last_ns>2500000000ULL))){
  gate->samples=gate->ready=0;gate->first_ns=0;gate->last_ns=now_ns;return;
 }
 if(!gate->samples)gate->first_ns=now_ns;
 if(gate->samples<11U)gate->samples++;
 gate->last_ns=now_ns;
 gate->ready=gate->samples>=11U && now_ns>=gate->first_ns &&
  now_ns-gate->first_ns>=10000000000ULL;
}
static inline unsigned i9100_charge_start_ready(const struct i9100_charge_start *gate,uint64_t now_ns)
{
 return gate && gate->ready && gate->samples>=11U && gate->first_ns &&
  gate->last_ns>=gate->first_ns && gate->last_ns-gate->first_ns>=10000000000ULL && now_ns>=gate->last_ns &&
  now_ns-gate->last_ns<=2500000000ULL;
}
#endif
