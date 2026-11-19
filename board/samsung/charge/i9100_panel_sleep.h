#ifndef I9100_PANEL_SLEEP_H
#define I9100_PANEL_SLEEP_H
#include <stdint.h>

/* Panel sleep with retained rail/reset/gamma: DCS off(28), sleep-in(10),
 * sleep-out(11), display-on(29), and the original FIMD ENVID bits only.
 * Caller supplies exclusive display gate and bounded transport. No PMIC
 * write, gamma rewrite or panel reset. DCS mode0a must actually confirm
 * sleep-out bit4/display-on bit2; unrecognized hardware stays unqualified. */
enum {I9P_ERROR_ARGUMENT=1,I9P_ERROR_IDENTITY=2,I9P_ERROR_IO=3,
 I9P_ERROR_MODE=4,I9P_ERROR_SCANOUT=5,I9P_ERROR_STATE=6};
enum {I9P_UNQUALIFIED=0,I9P_AWAKE=1,I9P_OFF=2,I9P_SLEEP=3,I9P_FAULT=4};
struct i9100_panel_sleep_io {
 void *cookie;
 int (*read_byte)(void *,unsigned,uint8_t *);
 int (*command)(void *,unsigned);
 uint32_t (*scanout_read)(void *);
 void (*scanout_write)(void *,uint32_t);
 void (*wait_ms)(void *,unsigned);
};
struct i9100_panel_sleep {
 struct i9100_panel_sleep_io io;
 uint32_t stage,qualified,error,cleanup_error,mode,commands,requests,saved_scanout,owned_scanout,identity_reads;
 uint8_t id[3];
};
static int i9100_panel_identity(const uint8_t id[3])
{return (id[0]==0xa1 || id[0]==0xa2) && id[1]==0x12 && id[2]!=0xff;}
static int i9100_panel_mode(struct i9100_panel_sleep *p,unsigned mask,unsigned expected)
{
 uint8_t mode=0;
 if(!p->io.read_byte(p->io.cookie,0x0a,&mode))return I9P_ERROR_IO;
 p->mode=mode;return (mode&mask)==expected?0:I9P_ERROR_MODE;
}
static int i9100_panel_probe(struct i9100_panel_sleep *p)
{
 if(!p || !p->io.read_byte || !p->io.command || !p->io.scanout_read || !p->io.scanout_write ||
    !p->io.wait_ms || p->stage!=I9P_UNQUALIFIED)return I9P_ERROR_ARGUMENT;
 uint8_t id[3],again[3];
 for(unsigned n=0;n<3;n++){
  if(!p->io.read_byte(p->io.cookie,0xda+n,&id[n])){p->error=I9P_ERROR_IO;return p->error;}
  p->id[n]=id[n];p->identity_reads|=1U<<n;
  if(!p->io.read_byte(p->io.cookie,0xda+n,&again[n])){p->error=I9P_ERROR_IO;return p->error;}
  p->identity_reads|=1U<<(n+3U);
 }
 for(unsigned n=0;n<3;n++)if(id[n]!=again[n]){p->identity_reads|=1U<<6;p->error=I9P_ERROR_IDENTITY;return p->error;}
 if(!i9100_panel_identity(id)){p->error=I9P_ERROR_IDENTITY;return p->error;}
 int result=i9100_panel_mode(p,0x14,0x14);
 if(result){p->error=result;return result;}
 if((p->io.scanout_read(p->io.cookie)&3U)!=3U){p->error=I9P_ERROR_SCANOUT;return p->error;}
 p->qualified=1;p->stage=I9P_AWAKE;p->error=0;return 0;
}
static int i9100_panel_issue(struct i9100_panel_sleep *p,unsigned command)
{
 ++p->commands;return p->io.command(p->io.cookie,command)?0:I9P_ERROR_IO;
}
static int i9100_panel_sleep_change(struct i9100_panel_sleep *p,unsigned active)
{
 if(!p || active>1 || !p->qualified)return I9P_ERROR_ARGUMENT;
 ++p->requests;
 if(p->stage==I9P_FAULT)return p->error?p->error:I9P_ERROR_STATE;
 if((active && p->stage==I9P_AWAKE) || (!active && p->stage==I9P_SLEEP))return 0;
 int result=0;
 if(!active){
  if(p->stage!=I9P_AWAKE)return I9P_ERROR_STATE;
  p->saved_scanout=p->io.scanout_read(p->io.cookie);
  if((p->saved_scanout&3U)!=3U){result=I9P_ERROR_SCANOUT;goto fault;}
  result=i9100_panel_issue(p,0x28);if(result)goto fault;
  result=i9100_panel_mode(p,4,0);if(result)goto fault;p->stage=I9P_OFF;
  result=i9100_panel_issue(p,0x10);if(result)goto fault;
  p->io.wait_ms(p->io.cookie,120);
  result=i9100_panel_mode(p,0x14,0);if(result)goto fault;p->stage=I9P_SLEEP;
  /* First finish current frame, then clear ENVID. Retain all timing,
   * window buffers and pixel formats. No clock gate or framebuffer free. */
  p->io.scanout_write(p->io.cookie,p->saved_scanout&~1U);p->io.wait_ms(p->io.cookie,34);
  if((p->io.scanout_read(p->io.cookie)&~1U)!=(p->saved_scanout&~1U)){
   result=I9P_ERROR_SCANOUT;goto fault;
  }
  p->owned_scanout=p->saved_scanout&~3U;p->io.scanout_write(p->io.cookie,p->owned_scanout);
  if(p->io.scanout_read(p->io.cookie)!=p->owned_scanout){result=I9P_ERROR_SCANOUT;goto fault;}
  return 0;
 }
 if(p->stage!=I9P_SLEEP || p->io.scanout_read(p->io.cookie)!=p->owned_scanout){result=I9P_ERROR_SCANOUT;goto fault;}
 /* Restore scanning while the panel is still off, before showing it. */
 p->io.scanout_write(p->io.cookie,p->saved_scanout);
 if(p->io.scanout_read(p->io.cookie)!=p->saved_scanout){result=I9P_ERROR_SCANOUT;goto fault;}
 result=i9100_panel_issue(p,0x11);if(result)goto fault;
 p->io.wait_ms(p->io.cookie,120);result=i9100_panel_mode(p,0x10,0x10);if(result)goto fault;
 result=i9100_panel_issue(p,0x29);if(result)goto fault;
 result=i9100_panel_mode(p,0x14,0x14);if(result)goto fault;
 p->stage=I9P_AWAKE;return 0;
fault:
 /* First error is retained; no automatic retry or unblank after uncertain
  * transport. Owner may keep the known black mapping for diagnosis. */
 p->error=result;p->stage=I9P_FAULT;return result;
}
#endif
