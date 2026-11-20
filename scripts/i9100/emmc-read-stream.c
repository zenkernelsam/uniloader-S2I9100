/* SPDX-License-Identifier: BSD-2-Clause */
#include "emmc-read-stream.h"
static void copy(uint8_t *to,const uint8_t *from,uint32_t n){while(n--)*to++=*from++;}
static void zero(void *out,uint32_t n){uint8_t *p=(uint8_t *)out;while(n--)*p++=0;}
static int equal(const void *a,const void *b,uint32_t n)
{const uint8_t *x=(const uint8_t *)a,*y=(const uint8_t *)b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint32_t get32(const uint8_t *p){return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t get64(const uint8_t *p){return get32(p)|(uint64_t)get32(p+4)<<32;}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(8U*i));}
static void put64(uint8_t *p,uint64_t n){put32(p,(uint32_t)n);put32(p+4,(uint32_t)(n>>32));}
uint32_t i9ro_crc32(uint32_t c,const uint8_t *p,uint32_t n)
{
 /* Single producer only. Build the standard CRC table once so a full
  * 15.76GB read does not execute eight polynomial steps per input byte. */
 static uint32_t table[256];static unsigned prepared;
 if(!prepared){for(unsigned i=0;i<256;i++){uint32_t v=i;for(unsigned b=0;b<8;b++)v=(v>>1)^((0U-(v&1U))&0xedb88320U);table[i]=v;}prepared=1;}
 while(n--)c=(c>>8)^table[(c^*p++)&255U];return c;
}
static int source_read(const struct i9ro_io *io,uint64_t offset,uint32_t n,uint8_t *out,uint64_t sectors)
{
 uint64_t capacity=sectors*512U;
 if(!n||(offset&511U)||(n&511U)||offset>=capacity||n>capacity-offset||n>I9RO_CHUNK_BYTES)return I9RO_ARGUMENT;
 return io->read_at(io->cookie,offset,n,out)?I9RO_IO:0;
}
static int gpt_header(const uint8_t h[512],uint64_t sectors,uint64_t self,uint64_t *array,uint32_t *bytes)
{
 if(!equal(h,"EFI PART",8)||get32(h+8)!=0x10000U||get32(h+12)<92U||get32(h+12)>512U||get32(h+20))return I9RO_TABLE;
 uint8_t clean[512];copy(clean,h,512);zero(clean+16,4);
 if((i9ro_crc32(~0U,clean,get32(h+12))^~0U)!=get32(h+16)||get64(h+24)!=self||
    get64(h+32)!=(self==1U?sectors-1U:1U)||get64(h+40)<2U||get64(h+40)>get64(h+48)||get64(h+48)>=sectors-1U)return I9RO_TABLE;
 uint32_t count=get32(h+80),stride=get32(h+84);
 if(!count||count>128U||stride!=128U)return I9RO_TABLE;
 uint32_t n=(count*128U+511U)&~511U;uint64_t a=get64(h+72),blocks=n/512U;
 if(a<2U||a>=sectors||blocks>sectors-a||
    (self==1U?a+blocks>get64(h+40):a<=get64(h+48)||a+blocks>self))return I9RO_TABLE;
 *array=a;*bytes=n;return 0;
}
static int capture_tables(const struct i9ro_io *io,uint64_t sectors,struct i9ro_tables *t,uint8_t *scratch)
{
 zero(t,sizeof(*t));int e=source_read(io,0,512,t->mbr,sectors);
 if(e||t->mbr[510]!=0x55||t->mbr[511]!=0xaa)return e?e:I9RO_TABLE;
 unsigned protective=0;
 for(unsigned i=0;i<4;i++){const uint8_t *p=t->mbr+446+i*16U;
  if(p[4]==0xee&&get32(p+8)==1U&&get32(p+12)==sectors-1U)protective++;
  else for(unsigned j=0;j<16;j++)if(p[j])return I9RO_TABLE;}
 if(protective!=1)return I9RO_TABLE;
 if((e=source_read(io,512,512,t->primary,sectors))||
    (e=source_read(io,(sectors-1U)*512U,512,t->backup,sectors)))return e;
 uint32_t other_bytes=0;
 if(gpt_header(t->primary,sectors,1,&t->primary_lba,&t->array_bytes)||
    gpt_header(t->backup,sectors,sectors-1U,&t->backup_lba,&other_bytes)||other_bytes!=t->array_bytes)return I9RO_TABLE;
 if(!equal(t->primary+40,t->backup+40,32)||!equal(t->primary+80,t->backup+80,12))return I9RO_TABLE;
 if((e=source_read(io,t->primary_lba*512U,t->array_bytes,t->primary_array,sectors))||
    (e=source_read(io,t->backup_lba*512U,t->array_bytes,t->backup_array,sectors)))return e;
 if(!equal(t->primary_array,t->backup_array,t->array_bytes)||
    (i9ro_crc32(~0U,t->primary_array,get32(t->primary+80)*128U)^~0U)!=get32(t->primary+88))return I9RO_TABLE;
 if((e=source_read(io,I9RO_PIT_OFFSET,512,scratch,sectors)))return e;
 uint32_t count=get32(scratch+4);if(get32(scratch)!=0x12349876U||!count||count>32U)return I9RO_TABLE;
 t->pit_bytes=28U+count*132U;uint32_t padded=(t->pit_bytes+511U)&~511U;
 if((e=source_read(io,I9RO_PIT_OFFSET,padded,scratch,sectors)))return e;
 copy(t->pit,scratch,t->pit_bytes);return 0;
}
static int output(struct i9ro_stream *s,const struct i9ro_io *io,uint32_t kind,uint32_t flags,uint64_t offset,const uint8_t *data,uint32_t n)
{
 if(s->sequence==UINT32_MAX||n>I9RO_CHUNK_BYTES||(!data&&n))return I9RO_ARGUMENT;
 uint8_t h[I9RO_FRAME_BYTES]={0};copy(h,(const uint8_t *)"I9RF",4);put32(h+4,s->sequence++);
 put32(h+8,kind|(flags<<16));put32(h+12,n);put64(h+16,offset);
 put32(h+24,i9ro_crc32(~0U,data,n)^~0U);put32(h+28,i9ro_crc32(~0U,h,28)^~0U);
 if(io->write_all(io->cookie,h,sizeof(h))||(n&&io->write_all(io->cookie,data,n)))return I9RO_OUTPUT;
 if(kind!=I9RO_END){s->stream_crc=i9ro_crc32(s->stream_crc,h,sizeof(h));s->stream_crc=i9ro_crc32(s->stream_crc,data,n);}
 return 0;
}
static int table_frames(struct i9ro_stream *s,const struct i9ro_io *io,const struct i9ro_tables *t,uint32_t flags)
{
 const uint8_t *data[]={t->mbr,t->primary,t->primary_array,t->backup,t->backup_array,t->pit};
 const uint32_t sizes[]={512,512,t->array_bytes,512,t->array_bytes,t->pit_bytes};
 const uint64_t offsets[]={0,512,t->primary_lba*512U,(s->identity.sectors-1U)*512U,t->backup_lba*512U,I9RO_PIT_OFFSET};
 for(unsigned i=0;i<6;i++){int e=output(s,io,i+1U,flags,offsets[i],data[i],sizes[i]);if(e)return e;}return 0;
}
static int identity_matches(const struct i9ro_identity *a,const struct i9ro_identity *b)
{return a->sectors==b->sectors&&equal(a->cid,b->cid,16)&&a->major==b->major&&a->minor==b->minor&&a->flags==b->flags;}
int i9ro_emit(int enabled,struct i9ro_stream *s,const struct i9ro_io *io,uint32_t mode,
 const uint8_t nonce[16],const uint32_t expected[4],uint8_t *chunk,uint32_t chunk_bytes)
{
 if(!enabled)return I9RO_DISABLED;
 if(enabled!=1||!s||!io||!io->identity||!io->read_at||!io->write_all||!io->metadata||!nonce||
    !chunk||chunk_bytes<I9RO_CHUNK_BYTES||(mode!=I9RO_INVENTORY&&mode!=I9RO_BACKUP_USER)||
    (mode==I9RO_BACKUP_USER&&!expected)||!io->producer_source_sha256)return I9RO_ARGUMENT;
 unsigned nonce_set=0;for(unsigned i=0;i<16;i++)nonce_set|=nonce[i];if(!nonce_set)return I9RO_ARGUMENT;
 unsigned tag_set=0;for(unsigned i=0;i<32;i++)tag_set|=io->producer_source_sha256[i];if(!tag_set)return I9RO_ARGUMENT;
 zero(s,sizeof(*s));s->mode=mode;s->stream_crc=s->data_crc=~0U;
 int e=io->identity(io->cookie,&s->identity);if(e)return s->error=I9RO_IDENTITY;
 uint32_t flags=s->identity.flags;
 if((flags&~I9RO_MODEL_FLAG)!=I9RO_SAFE_FLAGS||!s->identity.sectors||s->identity.sectors>UINT32_MAX||
    (!(flags&I9RO_MODEL_FLAG)&&s->identity.sectors!=I9RO_USER_SECTORS)||
    !(s->identity.cid[0]|s->identity.cid[1]|s->identity.cid[2]|s->identity.cid[3])||
    (expected&&!equal(s->identity.cid,expected,16)))return s->error=I9RO_IDENTITY;
 if((e=capture_tables(io,s->identity.sectors,&s->tables,chunk)))return s->error=e;
 uint8_t h[I9RO_HEADER_BYTES]={0};copy(h,(const uint8_t *)"I9ROSTR1",8);put32(h+8,1);put32(h+12,sizeof(h));
 put32(h+16,mode);put32(h+20,I9RO_CHUNK_BYTES);put64(h+24,s->identity.sectors);
 for(unsigned i=0;i<4;i++)put32(h+32+i*4,s->identity.cid[i]);copy(h+48,nonce,16);
 put32(h+64,s->identity.major);put32(h+68,s->identity.minor);put32(h+72,flags);
 copy(h+76,io->producer_source_sha256,32);
 put32(h+124,i9ro_crc32(~0U,h,124)^~0U);
 if(io->write_all(io->cookie,h,sizeof(h)))return s->error=I9RO_OUTPUT;
 s->stream_crc=i9ro_crc32(s->stream_crc,h,sizeof(h));
 for(uint32_t kind=I9RO_DEV_TEXT;kind<=I9RO_BLOCKSIZE_TEXT;kind++){
  const uint8_t *raw=0;uint32_t n=0;
  if(io->metadata(io->cookie,kind,&raw,&n)||!raw||!n||n>I9RO_MAX_METADATA){e=I9RO_IO;goto failed;}
  if((e=output(s,io,kind,0,0,raw,n)))goto failed;
 }
 if((e=table_frames(s,io,&s->tables,0)))goto failed;
 if(mode==I9RO_BACKUP_USER){
  uint64_t capacity=s->identity.sectors*512U;
  while(s->data_bytes<capacity){
   if(!(s->data_bytes%(64ULL*1024U*1024U))){struct i9ro_identity current;
    if(io->identity(io->cookie,&current)||!identity_matches(&s->identity,&current)){e=I9RO_CHANGED;goto failed;}}
   uint32_t n=capacity-s->data_bytes<I9RO_CHUNK_BYTES?(uint32_t)(capacity-s->data_bytes):I9RO_CHUNK_BYTES;
   if((e=source_read(io,s->data_bytes,n,chunk,s->identity.sectors)))goto failed;
   s->data_crc=i9ro_crc32(s->data_crc,chunk,n);
   if((e=output(s,io,I9RO_DATA,0,s->data_bytes,chunk,n)))goto failed;
   s->data_bytes+=n;
  }
 }
 {
  struct i9ro_identity current;struct i9ro_tables after;
  if(io->identity(io->cookie,&current)||!identity_matches(&s->identity,&current)){e=I9RO_CHANGED;goto failed;}
  if((e=capture_tables(io,s->identity.sectors,&after,chunk)))goto failed;
  if(!equal(&s->tables,&after,sizeof(after))){e=I9RO_CHANGED;goto failed;}
  if((e=table_frames(s,io,&after,I9RO_POST)))goto failed;
 }
 {
  uint8_t end[32]={0};put64(end,s->data_bytes);put32(end+8,s->data_crc^~0U);
  put32(end+12,s->stream_crc^~0U);put32(end+16,s->sequence);put32(end+20,mode);
  e=output(s,io,I9RO_END,0,0,end,sizeof(end));s->error=e;return e;
 }
failed:
 s->error=e;
 if(e!=I9RO_OUTPUT){uint8_t error[16]={0};put32(error,(uint32_t)e);put32(error+4,s->sequence);put64(error+8,s->data_bytes);
  (void)output(s,io,I9RO_ERROR,0,0,error,sizeof(error));}
 return e;
}
