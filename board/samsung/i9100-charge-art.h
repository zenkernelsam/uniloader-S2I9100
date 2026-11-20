#ifndef I9100_CHARGE_ART_H
#define I9100_CHARGE_ART_H
#include <stdint.h>
#include <stddef.h>

#define I9ART_WIDTH 396U
#define I9ART_HEIGHT 258U
#define I9ART_PIXELS (I9ART_WIDTH * I9ART_HEIGHT)

/* Runtime clips the native full liquid over the native empty shell.
 * This is our continuous SOC composition, not an algorithm from the PNGs. */
static inline void i9100_charge_art_levels(unsigned valid,unsigned soc,unsigned full,
    unsigned *low,unsigned *high,unsigned *weight)
{
 *low=0U;*high=16U;*weight=valid?(full?100U:soc):0U;
}

static inline unsigned i9100_charge_liquid_weight(unsigned x,unsigned percent)
{
 if(!percent)return 0U;if(percent>=100U)return 100U;
 /* Native 3/4-scaled chamber spans roughly x64..334. A two-pixel edge
  * smooths motion without crossfading two complete visible fill fronts. */
 int edge=6400+(int)percent*270-(int)x*100+100;
 return edge<=0?0U:edge>=200?100U:(unsigned)edge/2U;
}

static inline uint16_t i9100_charge_art_mix(uint16_t low,uint16_t high,unsigned weight,unsigned red)
{
 unsigned r=(((low>>11)&31U)*(100U-weight)+((high>>11)&31U)*weight+50U)/100U;
 unsigned g=(((low>>5)&63U)*(100U-weight)+((high>>5)&63U)*weight+50U)/100U;
 unsigned b=((low&31U)*(100U-weight)+(high&31U)*weight+50U)/100U;
 if(red){
  /* Only the native green liquid contribution changes hue. Glass/black and
   * silver highlights stay original. Green is 6bit; red/blue are 5bit. */
  unsigned green=(g*31U+31U)/63U,grey=r>b?r:b;
  if(green>grey+2U){unsigned liquid=green-grey;r=grey+liquid;g=grey*2U+liquid/5U;b=grey+liquid/12U;}
 }
 return (uint16_t)((r<<11)|(g<<5)|b);
}

/* Only local, qualified firmware resources are embedded. No filesystem, PNG
 * parser, display API or dynamic allocation runs in the charger. */
#ifdef I9100_CHARGE_ART_BLOB
__asm__(".pushsection .rodata.i9100_charge_art,\"a\"\n"
        ".balign 4\n.global i9100_charge_art_start\ni9100_charge_art_start:\n"
        ".incbin \"" I9100_CHARGE_ART_BLOB "\"\n"
        ".global i9100_charge_art_end\ni9100_charge_art_end:\n.popsection\n");
extern const uint8_t i9100_charge_art_start[], i9100_charge_art_end[];
#endif

static inline uint32_t i9100_art_u32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }

static inline int i9100_art_lz4(const uint8_t *source, unsigned bytes, uint8_t *out, unsigned capacity)
{
 unsigned ip=0, op=0;
 if(!source || !out || !bytes || !capacity)return 0;
 while(ip<bytes){
  unsigned token=source[ip++], literals=token>>4, match=(token&15U)+4U;
  if(literals==15U){unsigned n;do{
   if(ip==bytes)return 0;
   n=source[ip++];
   if(literals>capacity || n>capacity-literals)return 0;
   literals+=n;
  }while(n==255U);}
  if(literals>bytes-ip || literals>capacity-op)return 0;
  for(unsigned n=0;n<literals;n++)out[op++]=source[ip++];
  if(ip==bytes)return op==capacity;
  if(bytes-ip<2)return 0;
  unsigned offset=(unsigned)source[ip]|((unsigned)source[ip+1]<<8);ip+=2;
  if(!offset || offset>op)return 0;
  if((token&15U)==15U){unsigned n;do{
   if(ip==bytes)return 0;
   n=source[ip++];
   if(match>capacity || n>capacity-match)return 0;
   match+=n;
  }while(n==255U);}
  if(match>capacity-op)return 0;
  for(unsigned n=0;n<match;n++){out[op]=out[op-offset];op++;}
 }
 return 0;
}

static inline int i9100_charge_art_decode(const uint8_t *pack, unsigned bytes, unsigned frame,
                                 uint16_t *out, unsigned pixels)
{
 if(!pack || !out || bytes<32U || pixels<I9ART_PIXELS || ((uintptr_t)out&1U))return 0;
 if(pack[0]!='I' || pack[1]!='9' || pack[2]!='B' || pack[3]!='1' ||
    i9100_art_u32(pack+4)!=1U || i9100_art_u32(pack+8)!=I9ART_WIDTH ||
    i9100_art_u32(pack+12)!=I9ART_HEIGHT || i9100_art_u32(pack+16)!=18U ||
    i9100_art_u32(pack+20)!=I9ART_PIXELS*2U || i9100_art_u32(pack+24)!=176U ||
    i9100_art_u32(pack+28)!=bytes || bytes<176U || frame>=18U)return 0;
 unsigned previous=176U;
 for(unsigned n=0;n<18U;n++){
  unsigned offset=i9100_art_u32(pack+32U+n*8U), length=i9100_art_u32(pack+36U+n*8U);
  if(offset!=previous || !length || offset>bytes || length>bytes-offset)return 0;
  previous=offset+length;
 }
 if(previous!=bytes)return 0;
 unsigned offset=i9100_art_u32(pack+32U+frame*8U), length=i9100_art_u32(pack+36U+frame*8U);
 return i9100_art_lz4(pack+offset,length,(uint8_t*)out,I9ART_PIXELS*2U);
}

static inline unsigned i9100_charge_art_frame(unsigned valid, unsigned soc, unsigned full)
{
 if(!valid)return 0;
 /* The original family contains a special red frame at index3; it is not
  * a linear sequence of 17 green fills. Keep that native low-battery image,
  * and skip it in the ordinary green progression. Frame17 is an older
  * retained derivative and is no longer selected by production rendering. */
 if(!full && soc<=10U)return 3U;
 unsigned green=(soc*15U+50U)/100U;
 return full?16U:green<3U?green:green+1U;
}
#endif
