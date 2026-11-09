#ifndef I9100_PREVIOUS_BOOT_H
#define I9100_PREVIOUS_BOOT_H
#define I9100_PREVIOUS_BOOT_MAGIC 0x42503949U
#define I9100_PREVIOUS_BOOT_PROPERTY "i9100-prev-boot"
/* Fixed little-endian wire record. Inform validity and DDR validity are
 * separate; an absent prior record must not be interpreted as a clean boot. */
struct I9100PreviousBoot {
    unsigned magic, version, bytes, valid, inform6, inform7;
    unsigned stage, reason, pc, lr, far, fsr, reserved[4];
};
extern struct I9100PreviousBoot i9100_previous_boot;
/* The generated Apple DT reserves exactly one padded property slot. Locate
 * it before writing; malformed, duplicate or oversized blobs stay untouched. */
static int i9100_previous_boot_patch(void *tree, unsigned size,
                                     const struct I9100PreviousBoot *record)
{
    static const char name[32] = I9100_PREVIOUS_BOOT_PROPERTY;
    unsigned found = 0, target = 0;
    unsigned char *data = (unsigned char *)tree;
    if (!tree || !record || size < 100 || size > 65536) return 0;
    for (unsigned off=0;off<=size-100;off+=4) {
        if (!memcmp(data+off,name,32) && data[off+32]==64 &&
            !data[off+33] && !data[off+34] && !data[off+35]) {
            found++;target=off+36;
        }
    }
    if (found!=1) return 0;
    memcpy(data+target,record,64);
    return 1;
}
#endif
