#ifndef I9100_CHARGE_CONTROL_H
#define I9100_CHARGE_CONTROL_H
#include <stdint.h>
#include <string.h>
/* Two fixed actions on the distinct charger identity. No memory/flash API,
 * arbitrary PMU writes or direct reset from the USB receive interrupt. */
struct i9100_charge_control{char line[96];unsigned used,drop,last,action,reply_target;};
static unsigned i9100_chg_hex(char c)
{return c>='0'&&c<='9'?(unsigned)(c-'0'):c>='a'&&c<='f'?(unsigned)(c-'a'+10):16;}
static int i9100_chg_parse(struct i9100_charge_control*s,char c,const char*tag)
{
 if(c=='\r')return 0;
 if(c!='\n'){
  if(c<32 || c>126 || s->used>=sizeof(s->line)-1)s->drop=1;
  else if(!s->drop)s->line[s->used++]=c;
  return 0;
 }
 s->line[s->used]=0;unsigned seq=0,action=0;
 if(!s->drop && !s->action && s->used>=35 && !memcmp(s->line,"I9CHC1 ",7)){
  unsigned n;
  for(n=0;n<8;n++){unsigned h=i9100_chg_hex(s->line[7+n]);if(h>15)break;seq=(seq<<4)|h;}
  if(n==8 && seq && seq>s->last && s->line[15]==' ' && !memcmp(s->line+16,tag,16) && s->line[32]==' '){
   if(!strcmp(s->line+33,"boot"))action=1;
   if(!strcmp(s->line+33,"download"))action=2;
  }
 }
 s->used=s->drop=0;
 if(action){s->last=seq;s->action=action;return 1;}return 0;
}
static unsigned i9100_chg_ready(char*out,const char*tag)
{
 memcpy(out,"I9CHC1 READY ",13);memcpy(out+13,tag,16);out[29]='\n';out[30]=0;return 30;
}
static unsigned i9100_chg_reply(char*out,unsigned seq,unsigned action)
{
 memcpy(out,"I9CHC1 ",7);for(unsigned n=0;n<8;n++)out[7+n]="0123456789abcdef"[(seq>>((7-n)*4))&15U];
 const char*text=action==1?" OK boot\n":" OK download\n";unsigned n=0;
 do{out[15+n]=text[n];}while(text[n++]);return 15+n-1;
}
#endif
