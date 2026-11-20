#ifndef I9100_CHARGE_HANDOFF_H
#define I9100_CHARGE_HANDOFF_H
#include <stdint.h>
#include <string.h>

#define I9100_CHARGE_HANDOFF_PROPERTY "i9100-charge-handoff"
#define I9100_CHARGE_HANDOFF_MAGIC 0x48433949U
#define I9100_CHARGE_HANDOFF_BYTES 128U
/* Little-endian, fixed uint32 fields; no host/native pointer or hidden size. */
struct I9100ChargeHandoff {
 uint32_t magic,version,bytes,flags;
 uint32_t revision,sub_charger,polls,valid,present,connected,percent,millivolts;
 uint32_t temperature_deci_c,reason,full,timeout,recharging;
 uint32_t enabled_before,charging_before,enabled_after,charging_after;
 /* published_* dates the beginning of checksum/final slot publication. */
 uint32_t sampled_low,sampled_high,stopped_low,stopped_high,published_low,published_high;
 uint32_t elapsed_seconds,qualified_samples,recovery_seconds,fault,checksum;
};

static inline uint32_t i9100_charge_handoff_checksum(const struct I9100ChargeHandoff *record)
{
 const uint8_t *data=(const uint8_t*)record;uint32_t hash=2166136261U;
 for(unsigned n=0;n<I9100_CHARGE_HANDOFF_BYTES-4U;n++){hash^=data[n];hash*=16777619U;}
 return hash;
}
static inline uint32_t i9100_charge_dt_u32(const uint8_t *p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}

struct i9100_charge_dt_cursor {
 const uint8_t *data;unsigned size,at,nodes,chosen,matches,target,error;
 const char *property;unsigned property_bytes;
};
/* Walk the actual Apple flat-tree structure, never scan arbitrary value bytes
 * for a property-looking string. Only one direct /chosen slot is eligible. */
static inline void i9100_charge_dt_node(struct i9100_charge_dt_cursor *c,unsigned depth)
{
 if(c->error)return;
 if(depth>8U || ++c->nodes>128U || c->at>c->size || c->size-c->at<8U){c->error=1;return;}
 unsigned properties=i9100_charge_dt_u32(c->data+c->at),children=i9100_charge_dt_u32(c->data+c->at+4U);
 c->at+=8U;
 if(!properties || properties>128U || children>64U){c->error=1;return;}
 unsigned name_seen=0,is_chosen=0,is_root=0,slots=0,slot=0;
 const uint8_t *names[128];
 for(unsigned n=0;n<properties;n++){
  if(c->at>c->size || c->size-c->at<36U){c->error=1;return;}
  const uint8_t *property=c->data+c->at;
  unsigned length=i9100_charge_dt_u32(property+32U),value=c->at+36U;
  if(length>c->size-value || ((length+3U)&~3U)>c->size-value){c->error=1;return;}
  unsigned end=0;while(end<32U && property[end])end++;
  if(!end || end==32U){c->error=1;return;}
  for(unsigned j=end;j<32U;j++)if(property[j]){c->error=1;return;}
  for(unsigned j=0;j<n;j++)if(!memcmp(names[j],property,32U)){c->error=1;return;}
  names[n]=property;
  if(end==4U && !memcmp(property,"name",4)){
   if(++name_seen!=1U || !length || length>64U || c->data[value+length-1U]){c->error=1;return;}
   for(unsigned j=0;j+1U<length;j++)if(!c->data[value+j]){c->error=1;return;}
   is_chosen=length==7U && !memcmp(c->data+value,"chosen\0",7);
   is_root=length==12U && !memcmp(c->data+value,"device-tree\0",12);
  }
  if(end==strlen(c->property) && !memcmp(property,c->property,end)){
   if(length!=c->property_bytes){c->error=1;return;}
   slots++;slot=value;c->matches++;
  }
  c->at=value+((length+3U)&~3U);
 }
 if(name_seen!=1U || (!depth && !is_root)){c->error=1;return;}
 if(depth==1U && is_chosen){c->chosen++;if(slots==1U)c->target=slot;else{c->error=1;return;}}
 else if(slots){c->error=1;return;}
 for(unsigned n=0;n<children && !c->error;n++)i9100_charge_dt_node(c,depth+1U);
}
static inline uint8_t *i9100_charge_property_slot(void *tree,unsigned size,const char *property,unsigned bytes)
{
 if(!tree || ((uintptr_t)tree&3U) || size<172U || size>32768U || (size&3U))return 0;
 if(!property || !strlen(property) || strlen(property)>31U || !bytes || (bytes&3U))return 0;
 struct i9100_charge_dt_cursor cursor={(const uint8_t*)tree,size,0,0,0,0,0,0,property,bytes};
 i9100_charge_dt_node(&cursor,0);
 if(cursor.error || cursor.at!=size || cursor.chosen!=1U || cursor.matches!=1U || !cursor.target)return 0;
 return (uint8_t*)tree+cursor.target;
}
static inline uint8_t *i9100_charge_handoff_slot(void *tree,unsigned size)
{return i9100_charge_property_slot(tree,size,I9100_CHARGE_HANDOFF_PROPERTY,I9100_CHARGE_HANDOFF_BYTES);}
#endif
