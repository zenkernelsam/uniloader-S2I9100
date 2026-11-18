#ifndef I9100_BOOT_SOURCE_H
#define I9100_BOOT_SOURCE_H
#define I9100_BOOT_SOURCE_MAGIC 0x53503949U
#define I9100_BOOT_SOURCE_PROPERTY "i9100-boot-source"
struct I9100BootSource {
 unsigned magic,version,flags,inform2,inform3,sboot_mode,r1,r2;
};
extern struct I9100BootSource i9100_boot_source;
void i9100_capture_boot_source(void);
static int i9100_boot_source_patch(void *tree,unsigned size,const struct I9100BootSource *record)
{
 static const char name[32]=I9100_BOOT_SOURCE_PROPERTY;
 unsigned char *data=tree;unsigned found=0,target=0;
 if(!tree || !record || size<68 || size>65536 ||
    record->magic!=I9100_BOOT_SOURCE_MAGIC || record->version!=1)return 0;
 for(unsigned off=0;off<=size-68;off+=4)
  if(!memcmp(data+off,name,32) && data[off+32]==32 &&
     !data[off+33] && !data[off+34] && !data[off+35]){found++;target=off+36;}
 if(found!=1)return 0;
 memcpy(data+target,record,32);return 1;
}
#endif
