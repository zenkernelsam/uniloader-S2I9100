#ifndef I9100_CHARGE_SCREEN_H
#define I9100_CHARGE_SCREEN_H
#include <stdint.h>
/* Standalone charger visuals. The caller supplies the observed window buffer,
 * exact pixel format, valid state and actual SOC; drawing has no hardware API. */
struct i9100_charge_screen{void*pixels;unsigned bytes,stride,bpp;};
static int i9100_charge_bind(struct i9100_charge_screen*s,unsigned con,unsigned base,
 unsigned pitch,unsigned xy,unsigned end)
{
 unsigned mode=(con>>2)&15U;
 if(!s || !(con&1U) || (mode!=5U && mode!=11U) || (pitch&(8191U<<13)))return 0;
 s->bpp=mode==5?16U:32U;s->stride=pitch&8191U;s->bytes=s->stride*800U;s->pixels=(void*)(uintptr_t)base;
 return xy==((479U<<11)|799U) && s->stride==480U*(s->bpp/8) &&
  base>=0x41000000U && (uint64_t)base+s->bytes<=0x47000000ULL && end>=base+s->bytes &&
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
 if(s->bpp==32)*(volatile uint32_t*)((uint8_t*)s->pixels+index)=color;
 else *(volatile uint16_t*)((uint8_t*)s->pixels+index)=
  (uint16_t)(((color>>8)&0xf800U)|((color>>5)&0x07e0U)|((color>>3)&0x001fU));
}
static void i9100_charge_rect(const struct i9100_charge_screen*s,unsigned x,unsigned y,unsigned w,unsigned h,uint32_t c)
{for(unsigned j=0;j<h && y+j<800;j++)for(unsigned i=0;i<w && x+i<480;i++)i9100_charge_pixel(s,x+i,y+j,c);}
static unsigned i9100_charge_corner(unsigned dy,unsigned height,unsigned radius)
{
 unsigned edge=dy<height/2?dy:height-1-dy;
 if(edge>=radius)return 0;
 unsigned distance=radius-edge;
 for(unsigned x=0;x<radius;x++)if((radius-x)*(radius-x)+distance*distance<=radius*radius)return x;
 return radius;
}
static const uint8_t i9100_charge_digits[12][7]={
 {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},{14,17,1,2,4,8,31},
 {30,1,1,14,1,1,30},{2,6,10,18,31,2,2},{31,16,16,30,1,1,30},
 {14,16,16,30,17,17,14},{31,1,2,4,8,8,8},{14,17,17,14,17,17,14},
 {14,17,17,15,1,1,14},{17,2,4,8,16,17,0},{0,0,0,31,0,0,0}};
static void i9100_charge_digit(const struct i9100_charge_screen*s,unsigned digit,unsigned x,unsigned y,unsigned scale,uint32_t c)
{
 if(digit>=12)return;
 for(unsigned j=0;j<7;j++)for(unsigned i=0;i<5;i++)if(i9100_charge_digits[digit][j]&(1U<<(4U-i)))
  i9100_charge_rect(s,x+i*scale,y+j*scale,scale,scale,c);
}
static int i9100_charge_draw(const struct i9100_charge_screen*s,unsigned valid,unsigned soc,
 unsigned connected,unsigned charging,int reason,unsigned full,unsigned frame)
{
 if(!i9100_charge_screen_valid(s) || soc>100 || charging>1 || connected>1 || full>1 || valid>1)return 0;
 i9100_charge_rect(s,0,0,480,800,0);
 /* Restrained silver body and a real fill level, on black AMOLED background. */
 for(unsigned y=304;y<480;y++){
  unsigned d=y<392?y-304:479-y;
  uint32_t g=90U+d*120U/88U,c=(g<<16)|(g<<8)|g;
  unsigned inset=i9100_charge_corner(y-304,176,16);
  i9100_charge_rect(s,74+inset,y,318-2*inset,1,c);
 }
 for(unsigned y=314;y<469;y++){
  unsigned inset=i9100_charge_corner(y-314,155,9);
  i9100_charge_rect(s,83+inset,y,299-2*inset,1,0x00060606U);
 }
 i9100_charge_rect(s,392,352,17,80,0x00777777U);
 i9100_charge_rect(s,396,361,10,62,0x00999999U);
 unsigned length=valid?287U*soc/100U:0;
 for(unsigned y=322;y<462;y++){
  unsigned dy=y-322,brightness=dy<70?220U-dy:110U+(dy-70U)/2U;
  uint32_t color=(charging || full) ? (brightness<<8)|0x00080008U :
   reason==I9100_POWER_TEMPERATURE || reason==I9100_POWER_TIMEOUT ? (brightness<<16)|0x00004000U :0x004c4c4cU;
  unsigned inset=i9100_charge_corner(y-322,140,5);
  if(length>inset)i9100_charge_rect(s,89+inset,y,length-inset,1,color);
 }
 if(valid && charging && !full && length>12){
  unsigned band=12U+(frame%8U)*(length-12U)/8U;
  i9100_charge_rect(s,89+band-8U,322,5,140,0x003df26bU);
 }
 unsigned digits=valid?(soc>=100?3U:soc>=10?2U:1U):2U;
 unsigned width=(digits+1U)*30U,x=(480U-width)/2U;
 if(!valid){i9100_charge_digit(s,11,x,523,5,0x00b0b0b0);i9100_charge_digit(s,11,x+30,523,5,0x00b0b0b0);}
 else{
  if(digits==3){i9100_charge_digit(s,1,x,523,5,0x00e8e8e8);x+=30;}
  if(digits>=2){i9100_charge_digit(s,(soc/10)%10,x,523,5,0x00e8e8e8);x+=30;}
  i9100_charge_digit(s,soc%10,x,523,5,0x00e8e8e8);x+=30;
 }
 i9100_charge_digit(s,10,x,523,5,0x00e8e8e8);
 /* Dim static reflection below the glass body; no independent animation. */
 if(valid)for(unsigned y=481;y<502;y++){
  unsigned glow=(502-y)*2U;
  uint32_t c=(charging||full)?glow<<8:(glow<<16)|(glow<<8)|glow;
  i9100_charge_rect(s,89,y,length,1,c);
 }
 if(valid && connected && (charging || full)){
  /* Small charge bolt; amber pause mark for a protected/offline state. */
  for(unsigned y=597;y<621;y++)i9100_charge_rect(s,242-(y-597)/2,y,7,1,0x0074bc7aU);
  for(unsigned y=611;y<636;y++)i9100_charge_rect(s,230+(y-611)/2,y,7,1,0x0074bc7aU);
 }else{i9100_charge_rect(s,228,603,7,28,0x00826a38U);i9100_charge_rect(s,245,603,7,28,0x00826a38U);}
 return 1;
}
#endif
