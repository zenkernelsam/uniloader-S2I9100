/* SPDX-License-Identifier: BSD-2-Clause */
/* Read-only Linux/TWRP collector. No libc, disk writes, MMC ioctl commands,
 * sysfs writes, mount/unmount, block flushing or implicit recovery. */
#include "emmc-read-stream.h"
#ifndef I9RO_PRODUCER_SOURCE_HEX
#error Build using the source-tagged offline collector compiler
#endif
typedef unsigned long word;
extern long i9ro_syscall6(word,word,word,word,word,word,word);
enum {N_READ=3,N_WRITE=4,N_OPEN=5,N_CLOSE=6,N_IOCTL=54,N_LLSEEK=140,N_FSTAT64=197};
enum {OPEN_RDONLY=0,OPEN_EXCL=0200,OPEN_NOFOLLOW=0100000,OPEN_LARGEFILE=0400000};
#define BLK_BYTES 0x80041272UL /* ARM32 _IOR(0x12,114,size_t): body is u64. */
#define BLK_SECTOR 0x1268UL
static const char device[]="/dev/block/mmcblk0";
static const char *const sources[]={
 "/sys/class/block/mmcblk0/dev","/sys/class/block/mmcblk0/device/cid","/sys/class/block/mmcblk0/size",
 "/sys/class/block/mmcblk0/device/type","/proc/self/mountinfo","/proc/swaps","/proc/iomem",
 "/sys/kernel/debug/clk/clk_summary","/sys/class/block/mmcblk0/queue/logical_block_size"};
static struct i9ro_stream stream;
static uint8_t chunk[I9RO_CHUNK_BYTES],text[I9RO_MAX_METADATA],original_cid[64];
static long fd=-1;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static int same(const char *a,const char *b){unsigned i=0;while(a[i]&&a[i]==b[i])i++;return a[i]==b[i];}
static void bytes_copy(void *d,const void *s,unsigned n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;}
static long call(unsigned n,word a,word b,word c,word d,word e,word f){return i9ro_syscall6(n,a,b,c,d,e,f);}
static long open_ro(const char *path,unsigned extra){return call(N_OPEN,(word)path,OPEN_RDONLY|OPEN_NOFOLLOW|OPEN_LARGEFILE|extra,0,0,0,0);}
static int close_fd(long n){return call(N_CLOSE,(word)n,0,0,0,0,0)<0?-1:0;}
static int text_read(const char *path,uint8_t *out,uint32_t capacity,uint32_t *count)
{
 long file=open_ro(path,0);if(file<0)return -1;uint32_t total=0;int error=0;
 while(total<capacity){long n=call(N_READ,(word)file,(word)(out+total),capacity-total,0,0,0);
  if(n<0){error=-1;break;}if(!n)break;total+=(uint32_t)n;}
 if(total==capacity)error=-1;
 if(close_fd(file))error=-1;if(error)return -1;out[total]=0;*count=total;return 0;
}
static int decimal(const uint8_t **at,uint64_t *out)
{const uint8_t *p=*at;uint64_t v=0;if(*p<'0'||*p>'9')return -1;
 while(*p>='0'&&*p<='9'){unsigned d=*p++-'0';if(v>1844674407370955161ULL||(v==1844674407370955161ULL&&d>5U))return -1;v=v*10U+d;}
 *at=p;*out=v;return 0;}
static int hex(unsigned char ch){return ch>='0'&&ch<='9'?ch-'0':ch>='a'&&ch<='f'?ch-'a'+10:ch>='A'&&ch<='F'?ch-'A'+10:-1;}
static int cid_decode(const uint8_t *s,uint32_t out[4])
{for(unsigned i=0;i<4;i++){uint32_t v=0;for(unsigned j=0;j<8;j++){int d=hex(*s++);if(d<0)return -1;v=v<<4|(unsigned)d;}out[i]=v;}
 return *s&&*s!='\n'?-1:s[0]=='\n'&&s[1]?-1:0;}
static int nonce_decode(const char *s,uint8_t out[16])
{if(length(s)!=32)return -1;unsigned sum=0;for(unsigned i=0;i<16;i++){int hi=hex(s[i*2]),lo=hex(s[i*2+1]);if(hi<0||lo<0)return -1;out[i]=(uint8_t)(hi*16+lo);sum|=out[i];}return sum?0:-1;}
static int mount_clear(uint32_t major)
{
 uint32_t n=0;if(text_read(sources[I9RO_MOUNTINFO-I9RO_DEV_TEXT],text,sizeof(text)-1,&n))return -1;
 uint8_t *line=text;
 while(*line){uint8_t *p=line;for(unsigned i=0;i<2;i++){while(*p&&*p!=' '&&*p!='\n')p++;if(*p!=' ')return -1;p++;}
  const uint8_t *number=p;uint64_t ma,mi;if(decimal(&number,&ma)||*number++!=':'||decimal(&number,&mi)||*number!=' ')return -1;
  if(ma==major&&mi<=12U)return -1; /* Other MMC disks (external SD) are independent. */
  while(*line&&*line!='\n')line++;if(*line)line++;
 }
 // Only the header is accepted. File-backed swap on internal storage is
 // harder to identify than a block path and still prevents a clean backup.
 if(text_read(sources[I9RO_SWAPS-I9RO_DEV_TEXT],text,sizeof(text)-1,&n))return -1;
 uint32_t i=0;while(i<n&&text[i]!='\n')i++;if(i==n)return -1;
 for(i++;i<n;i++)if(text[i]!='\n'&&text[i]!='\r'&&text[i]!=' '&&text[i]!='\t')return -1;
 // /proc/partitions links are not an ownership proof. Refuse device-mapper
 // / sysfs holders for both the whole card and each possible child slice.
 return 0;
}
static int holders_clear()
{
 // getdents64 has a fixed ABI and reports every entry, including unknown
 // holders. Directories only are opened; no dentry/sysfs modification.
 char path[96];
 for(unsigned part=0;part<=12;part++){
  const char *base="/sys/class/block/mmcblk0";unsigned n=length(base);bytes_copy(path,base,n);
  if(part){path[n++]='p';if(part>=10)path[n++]='1';path[n++]=(char)('0'+part%10);}
  const char *suffix="/holders";bytes_copy(path+n,suffix,length(suffix)+1);
  long dir=open_ro(path,040000);if(dir<0)return -1;
  int error=0;for(;;){long got=call(217,(word)dir,(word)text,4096,0,0,0);if(got<0){error=-1;break;}if(!got)break;
   unsigned at=0;while(at<(unsigned)got){if((unsigned)got-at<20){error=-1;break;}
    unsigned record=text[at+16]|(unsigned)text[at+17]<<8;if(record<20||record>(unsigned)got-at){error=-1;break;}
    const char *name=(const char *)text+at+19;unsigned end=19;while(end<record&&text[at+end])end++;
    if(end==record||(!same(name,".")&&!same(name,".."))){error=-1;break;}at+=record;
   }if(error)break;
  }if(close_fd(dir))error=-1;if(error)return -1;
 }return 0;
}
static int inspect_identity(void *cookie,struct i9ro_identity *out)
{
 (void)cookie;uint32_t n=0;uint64_t sys_sectors=0,size=0,major=0,minor=0;uint32_t sector=0;
 // ARM stat64 ABI from arch/arm/include/asm/stat.h. Avoid architecture-
 // dependent libc structures; the output region exceeds the actual96B.
 uint64_t status[16]={0};if(call(N_FSTAT64,(word)fd,(word)status,0,0,0,0)<0)return -1;
 const uint32_t *words=(const uint32_t *)status;
 if((words[4]&0170000U)!=0060000U)return -1; // S_IFBLK at offset16.
 if(text_read(sources[0],text,sizeof(text)-1,&n))return -1;
 const uint8_t *p=text;if(decimal(&p,&major)||*p++!=':'||decimal(&p,&minor)||(*p&&(*p!='\n'||p[1]))||major!=179U||minor)return -1;
 uint64_t rdev=status[4];uint32_t ma=(uint32_t)(rdev>>8)&0xfffU,mi=(uint32_t)(rdev&255U)|((uint32_t)(rdev>>12)&0xfffff00U);
 if(ma!=major||mi!=minor)return -1;
 if(call(N_IOCTL,(word)fd,BLK_BYTES,(word)&size,0,0,0)<0||call(N_IOCTL,(word)fd,BLK_SECTOR,(word)&sector,0,0,0)<0||sector!=512U||size!=I9RO_USER_SECTORS*512U)return -1;
 if(text_read(sources[2],text,sizeof(text)-1,&n))return -1;p=text;if(decimal(&p,&sys_sectors)||(*p&&(*p!='\n'||p[1]))||sys_sectors!=I9RO_USER_SECTORS)return -1;
 if(text_read(sources[3],text,sizeof(text)-1,&n)||n!=4||!same((char *)text,"MMC\n"))return -1;
 if(text_read(sources[1],text,sizeof(text)-1,&n)||n!=33||cid_decode(text,out->cid))return -1;
 if(!original_cid[0])bytes_copy(original_cid,text,n+1);else if(!same((char *)text,(char *)original_cid))return -1;
 if(mount_clear((uint32_t)major)||holders_clear())return -1;
 out->sectors=I9RO_USER_SECTORS;out->major=(uint32_t)major;out->minor=(uint32_t)minor;out->flags=I9RO_SAFE_FLAGS;return 0;
}
static int block_read(void *cookie,uint64_t offset,uint32_t count,uint8_t *out)
{
 (void)cookie;uint64_t actual=0;
 if(call(N_LLSEEK,(word)fd,(word)(offset>>32),(word)(uint32_t)offset,(word)&actual,0,0)<0||actual!=offset)return -1;
 uint32_t total=0;while(total<count){long n=call(N_READ,(word)fd,(word)(out+total),count-total,0,0,0);if(n<=0)return -1;total+=(uint32_t)n;}
 return 0;
}
static int stdout_write(void *cookie,const uint8_t *bytes,uint32_t count)
{
 (void)cookie;uint32_t done=0;while(done<count){long n=call(N_WRITE,1,(word)(bytes+done),count-done,0,0,0);if(n<=0)return -1;done+=(uint32_t)n;}return 0;
}
static int metadata(void *cookie,uint32_t kind,const uint8_t **bytes,uint32_t *n)
{
 (void)cookie;if(kind<I9RO_DEV_TEXT||kind>I9RO_BLOCKSIZE_TEXT)return -1;
 if(text_read(sources[kind-I9RO_DEV_TEXT],text,sizeof(text)-1,n)){
  if(kind!=I9RO_CLOCKS)return -1;static const uint8_t missing[]="UNAVAILABLE: clock summary was not readable; CIU not verified\n";
  *bytes=missing;*n=sizeof(missing)-1;return 0;
 }
 *bytes=text;return *n?0:-1;
}
int i9ro_linux_main(unsigned argc,const char **argv)
{
 static const uint8_t usage[]="Usage: emmc-read-linux inventory NONCE32 | backup-user NONCE32 EXPECTED-CID32\nRead-only mmcblk0, all mounts/swaps/holders must be clear. No retries.\n";
 if(argc<3||argc>4||(!same(argv[1],"inventory")&&!same(argv[1],"backup-user"))){(void)call(N_WRITE,2,(word)usage,sizeof(usage)-1,0,0,0);return 2;}
 uint32_t mode=same(argv[1],"inventory")?I9RO_INVENTORY:I9RO_BACKUP_USER;
 uint8_t nonce[16];uint32_t expected[4];
 if(nonce_decode(argv[2],nonce)||argc!=(mode==I9RO_INVENTORY?3U:4U)||
    (mode==I9RO_BACKUP_USER&&(length(argv[3])!=32||cid_decode((const uint8_t *)argv[3],expected))))return 2;
 const char *producer_text=I9RO_PRODUCER_SOURCE_HEX;uint8_t producer[32];
 if(length(producer_text)!=64)return 2;
 for(unsigned i=0;i<32;i++){int hi=hex(producer_text[i*2]),lo=hex(producer_text[i*2+1]);if(hi<0||lo<0)return 2;producer[i]=(uint8_t)(hi*16+lo);}
 fd=open_ro(device,OPEN_EXCL);if(fd<0)return 3;
 const struct i9ro_io io={0,inspect_identity,block_read,stdout_write,metadata,producer};
 int result=i9ro_emit(1,&stream,&io,mode,nonce,mode==I9RO_BACKUP_USER?expected:0,chunk,sizeof(chunk));
 if(close_fd(fd)&&!result)result=I9RO_IO;return result?4:0;
}

/* ARM compiler memory helpers only; no runtime arithmetic or disk libc. */
void *__aeabi_memcpy(void *d,const void *s,unsigned n){bytes_copy(d,s,n);return d;}
void *__aeabi_memcpy4(void *d,const void *s,unsigned n){return __aeabi_memcpy(d,s,n);}
void *__aeabi_memclr(void *d,unsigned n){uint8_t *p=d;while(n--)*p++=0;return d;}
void *__aeabi_memclr4(void *d,unsigned n){return __aeabi_memclr(d,n);}
void *memset(void *d,int value,size_t n){uint8_t *p=d;while(n--)*p++=(uint8_t)value;return d;}
void *memcpy(void *d,const void *s,size_t n){bytes_copy(d,s,(unsigned)n);return d;}
