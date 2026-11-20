#ifndef I9100_CHARGE_SCREEN_H
#define I9100_CHARGE_SCREEN_H
#include <stdint.h>
#ifndef I9100_CHARGE_RENDER_PROGRESS
#define I9100_CHARGE_RENDER_PROGRESS() do{}while(0)
#endif
#include "i9100-charge-art.h"
#include "i9100-charge-font.h"
/* Standalone charger visuals. The caller supplies the observed window buffer,
 * exact pixel format, valid state and actual SOC; drawing has no hardware API. */
struct i9100_charge_screen{void*pixels;unsigned bytes,stride,bpp;};
static int i9100_charge_bind(struct i9100_charge_screen*s,unsigned con,unsigned base,
 unsigned pitch,unsigned xy,unsigned end)
{
 unsigned mode=(con>>2)&15U;
 if(!s || !(con&1U) || (mode!=5U && mode!=11U && mode!=13U) || (pitch&(8191U<<13)))return 0;
 s->bpp=mode==5?16U:32U;s->stride=pitch&8191U;s->bytes=s->stride*800U;s->pixels=(void*)(uintptr_t)base;
 unsigned owned=(base>=0x41000000U && (uint64_t)base+s->bytes<=0x47000000ULL) ||
  (base==0x5ec00000U && s->bpp==32 && s->bytes==1536000U); /* S-Boot 4d4df774 descriptor. */
 return xy==((479U<<11)|799U) && s->stride==480U*(s->bpp/8) && owned && end>=base+s->bytes &&
  base+s->bytes>=base && !(base&((s->bpp/8)-1U));
}
static int i9100_charge_screen_valid(const struct i9100_charge_screen*s)
{
 return s && s->pixels && (s->bpp==16 || s->bpp==32) &&
  !((uintptr_t)s->pixels&((s->bpp/8)-1U)) && s->stride==480U*(s->bpp/8) && s->bytes>=s->stride*800U;
}
static void i9100_charge_pixel(const struct i9100_charge_screen*s,unsigned x,unsigned y,uint32_t color)
{
 if(x>=480 || y>=800)return;
 unsigned index=y*s->stride+x*(s->bpp/8);
 if(s->bpp==32)*(volatile uint32_t*)((uint8_t*)s->pixels+index)=color|0xff000000U;
 else *(volatile uint16_t*)((uint8_t*)s->pixels+index)=
  (uint16_t)(((color>>8)&0xf800U)|((color>>5)&0x07e0U)|((color>>3)&0x001fU));
}
struct i9100_charge_render_stats {
 unsigned frames, stores, last_stores, unchanged, art_frame, art_ok;
 unsigned compared,last_compared,body_rebuilds,progress_calls,initial_hidden,initial_committed;
};
static struct i9100_charge_render_stats i9100_charge_render;
static inline void i9100_charge_render_progress(void)
{i9100_charge_render.progress_calls++;I9100_CHARGE_RENDER_PROGRESS();}
/* Private RAM is part of loader BSS, never a guessed free physical address.
 * The live scanout receives final pixels only, never a blank intermediate. */
#define I9SCREEN_TOP 284U
#define I9SCREEN_HEIGHT 320U
static uint32_t i9100_charge_composed[480U*I9SCREEN_HEIGHT];
#ifdef I9100_CHARGE_ART_BLOB
static uint16_t i9100_charge_sprite[I9ART_PIXELS];
static unsigned i9100_charge_sprite_key=~0U;
#endif
static void *i9100_charge_previous_buffer;
static unsigned i9100_charge_previous_bpp, i9100_charge_previous_key=~0U;
static inline void i9100_charge_renderer_reset(void)
{
 i9100_charge_previous_buffer=0;i9100_charge_previous_bpp=0;i9100_charge_previous_key=~0U;
 i9100_charge_render=(struct i9100_charge_render_stats){0};
#ifdef I9100_CHARGE_ART_BLOB
 i9100_charge_sprite_key=~0U;
#endif
}
static uint32_t i9100_charge_get(const struct i9100_charge_screen*s,unsigned x,unsigned y)
{
 const uint8_t*p=(const uint8_t*)s->pixels+y*s->stride+x*(s->bpp/8U);
 if(s->bpp==32U)return *(const volatile uint32_t*)p;
 return *(const volatile uint16_t*)p;
}
static uint32_t i9100_charge_encode(unsigned bpp,uint32_t c)
{
 if(bpp==32U)return c|0xff000000U;
 return ((c>>8)&0xf800U)|((c>>5)&0x07e0U)|((c>>3)&0x001fU);
}
static void i9100_charge_final_pixel(const struct i9100_charge_screen*s,unsigned x,unsigned y,uint32_t c,unsigned first)
{
 c=i9100_charge_encode(s->bpp,c);
 if(!first){
  i9100_charge_render.compared++;i9100_charge_render.last_compared++;
  if(i9100_charge_get(s,x,y)==c)return;
 }
 uint8_t*p=(uint8_t*)s->pixels+y*s->stride+x*(s->bpp/8U);
 if(s->bpp==32U)*(volatile uint32_t*)p=c;
 else *(volatile uint16_t*)p=(uint16_t)c;
 i9100_charge_render.stores++;i9100_charge_render.last_stores++;
}
static void i9100_charge_rect(const struct i9100_charge_screen*s,unsigned x,unsigned y,unsigned w,unsigned h,uint32_t c)
{for(unsigned j=0;j<h && y+j<800;j++)for(unsigned i=0;i<w && x+i<480;i++)i9100_charge_pixel(s,x+i,y+j,c);}
#ifndef I9100_CHARGE_ART_BLOB
static unsigned i9100_charge_corner(unsigned dy,unsigned height,unsigned radius)
{
 unsigned edge=dy<height/2?dy:height-1-dy;
 if(edge>=radius)return 0;
 unsigned distance=radius-edge;
 for(unsigned x=0;x<radius;x++)if((radius-x)*(radius-x)+distance*distance<=radius*radius)return x;
 return radius;
}
#endif
static unsigned i9100_charge_digit(const struct i9100_charge_screen*s,unsigned digit,unsigned x,unsigned y,uint32_t c)
{
 if(digit>=12)return 0;
 const struct i9100_charge_glyph *g=&i9100_charge_font_metrics[digit];
 for(unsigned j=0;j<g->height;j++)for(unsigned i=0;i<g->width;i++){
  unsigned alpha=i9100_charge_font_alpha[digit][j*28U+i];
  if(!alpha)continue;
  uint32_t ink=((((c>>16)&255U)*alpha+127U)/255U)<<16;
  ink|=((((c>>8)&255U)*alpha+127U)/255U)<<8;
  ink|=((c&255U)*alpha+127U)/255U;
  /* Common 28px baseline inside the unchanged 96x28 dirty rectangle. */
  i9100_charge_pixel(s,x+(unsigned)g->left+i,y+24U-(unsigned)g->top+j,ink);
 }
 return g->advance;
}
static int i9100_charge_draw(const struct i9100_charge_screen*s,unsigned valid,unsigned soc,
 unsigned connected,unsigned charging,int reason,unsigned full,unsigned frame)
{
 if(!i9100_charge_screen_valid(s) || soc>100 || charging>1 || connected>1 || full>1 || valid>1)return 0;
 (void)frame; /* Artwork follows measured state, never a fictitious fill sweep. */
 unsigned visual_reason=reason==I9100_POWER_TEMPERATURE || reason==I9100_POWER_TIMEOUT;
 unsigned key=soc|(valid<<8)|(connected<<9)|(charging<<10)|(full<<11)|(visual_reason<<12);
 unsigned first=s->pixels!=i9100_charge_previous_buffer || s->bpp!=i9100_charge_previous_bpp ||
   i9100_charge_previous_key==~0U;
 i9100_charge_render.last_stores=i9100_charge_render.last_compared=0;
 if(!first && key==i9100_charge_previous_key){i9100_charge_render.unchanged++;return 1;}
 if(first)for(unsigned y=0;y<I9SCREEN_HEIGHT;y++){
  for(unsigned x=0;x<480U;x++)i9100_charge_composed[y*480U+x]=0;
  if(!(y&7U))i9100_charge_render_progress();
 }
 struct i9100_charge_screen layer={i9100_charge_composed,sizeof(i9100_charge_composed),1920U,32U};
 const struct i9100_charge_screen*destination=s;s=&layer;
#ifdef I9100_CHARGE_ART_BLOB
 unsigned art=i9100_charge_art_frame(valid,soc,full);
 unsigned body_dirty=first || art!=i9100_charge_sprite_key;
 if(body_dirty && art!=i9100_charge_sprite_key){
  unsigned bytes=(unsigned)(i9100_charge_art_end-i9100_charge_art_start);
  i9100_charge_render_progress();
  if(!i9100_charge_art_decode(i9100_charge_art_start,bytes,art,i9100_charge_sprite,I9ART_PIXELS))return 0;
  i9100_charge_sprite_key=art;
 }
 if(body_dirty){
  for(unsigned y=0;y<I9ART_HEIGHT;y++){
   for(unsigned x=0;x<I9ART_WIDTH;x++){
    unsigned c=i9100_charge_sprite[y*I9ART_WIDTH+x],r=(c>>11)&31U,g=(c>>5)&63U,b=c&31U;
    i9100_charge_pixel(s,42U+x,y,((r*255U/31U)<<16)|((g*255U/63U)<<8)|(b*255U/31U));
   }
   if(!(y&7U))i9100_charge_render_progress();
  }
  i9100_charge_render.body_rebuilds++;
 }
 i9100_charge_render.art_frame=art;i9100_charge_render.art_ok=1;
#else
 unsigned body_dirty=1;
 if(!first)for(unsigned y=20;y<218;y++)for(unsigned x=74;x<410;x++)
  i9100_charge_composed[y*480U+x]=0;
 /* Restrained silver body and a real fill level, on black AMOLED background. */
 for(unsigned y=20;y<196;y++){
  unsigned d=y<108?y-20:195-y;
  uint32_t g=90U+d*120U/88U,c=(g<<16)|(g<<8)|g;
  unsigned inset=i9100_charge_corner(y-20,176,16);
  i9100_charge_rect(s,74+inset,y,318-2*inset,1,c);
 }
 for(unsigned y=30;y<185;y++){
  unsigned inset=i9100_charge_corner(y-30,155,9);
  i9100_charge_rect(s,83+inset,y,299-2*inset,1,0x00060606U);
 }
 i9100_charge_rect(s,392,68,17,80,0x00777777U);
 i9100_charge_rect(s,396,77,10,62,0x00999999U);
 unsigned length=valid?287U*soc/100U:0;
 for(unsigned y=38;y<178;y++){
  unsigned dy=y-38,brightness=dy<70?220U-dy:110U+(dy-70U)/2U;
  uint32_t color=(charging || full) ? (brightness<<8)|0x00080008U :
   reason==I9100_POWER_TEMPERATURE || reason==I9100_POWER_TIMEOUT ? (brightness<<16)|0x00004000U :0x004c4c4cU;
  unsigned inset=i9100_charge_corner(y-38,140,5);
  if(length>inset)i9100_charge_rect(s,89+inset,y,length-inset,1,color);
 }
 if(valid)for(unsigned y=197;y<218;y++){
  unsigned glow=(218-y)*2U;
  uint32_t c=(charging||full)?glow<<8:(glow<<16)|(glow<<8)|glow;
  i9100_charge_rect(s,89,y,length,1,c);
 }
 i9100_charge_render.body_rebuilds++;
#endif
 /* The largest previous/new percentage occupies exactly this rectangle.
  * Keep the decoded body/reflection for a same-level percentage change. */
 for(unsigned y=280;y<308;y++)for(unsigned x=192;x<288;x++)
  i9100_charge_composed[y*480U+x]=0;
 unsigned digits=valid?(soc>=100?3U:soc>=10?2U:1U):2U;
 unsigned width=valid?digits*16U+28U:2U*11U+28U,x=(480U-width)/2U;
 uint32_t ink=visual_reason?0x00ce9f59U:valid && soc<=10U?0x00c98480U:0x00bdbdbdU;
 if(!valid){x+=i9100_charge_digit(s,11,x,280,ink);x+=i9100_charge_digit(s,11,x,280,ink);}
 else{
  if(digits==3)x+=i9100_charge_digit(s,1,x,280,ink);
  if(digits>=2)x+=i9100_charge_digit(s,(soc/10)%10,x,280,ink);
  x+=i9100_charge_digit(s,soc%10,x,280,ink);
 }
 (void)i9100_charge_digit(s,10,x,280,ink);
 /* Compare only changed visual regions after the hidden initial fill.
  * At the same sprite level, at most 96x28 live pixels are inspected. */
 for(unsigned y=0;y<800U;y++){
  unsigned left=0,right=480U;
  if(!first){
   unsigned local=y>=I9SCREEN_TOP?y-I9SCREEN_TOP:~0U;
#ifdef I9100_CHARGE_ART_BLOB
   if(body_dirty && local<I9ART_HEIGHT){left=42U;right=438U;}
#else
   if(body_dirty && local>=20U && local<218U){left=74U;right=410U;}
#endif
   else if(local>=280U && local<308U){left=192U;right=288U;}
   else continue;
  }
  for(unsigned x=left;x<right;x++){
   uint32_t c=y>=I9SCREEN_TOP && y<I9SCREEN_TOP+I9SCREEN_HEIGHT?
     i9100_charge_composed[(y-I9SCREEN_TOP)*480U+x]:0;
   i9100_charge_final_pixel(destination,x,y,c,first);
  }
  if(!(y&7U))i9100_charge_render_progress();
 }
 i9100_charge_previous_buffer=destination->pixels;i9100_charge_previous_bpp=destination->bpp;
 i9100_charge_previous_key=key;i9100_charge_render.frames++;
 return 1;
}
#endif
