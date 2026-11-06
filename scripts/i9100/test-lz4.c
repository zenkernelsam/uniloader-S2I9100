/* Bounds regression and exact production-block decode, under ASan/UBSan. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
void fb_mark_asm(unsigned int o, unsigned int c) { (void)o; (void)c; }
void printk(int l, const char *f, ...) { (void)l; (void)f; }
#include "../../arch/arm/lz4dec.c"

static unsigned char *read_file(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) exit(2);
    fseek(f, 0, SEEK_END); *n = ftell(f); rewind(f);
    unsigned char *d = malloc(*n);
    if (fread(d, 1, *n, f) != *n) exit(2);
    fclose(f); return d;
}
int main(int argc, char **argv)
{
    static const uint8_t bad[][4] = {
        {0xf0}, {0xf0,0xff}, {0x10,'x',0}, {0x10,'x',0,0},
        {0x0f,1,0,0xff}, {0x1f,'x',1,0}
    };
    const unsigned sizes[] = {1,2,3,4,4,4};
    unsigned char out[16];
    for (unsigned i=0;i<6;i++) {
        /* Exact allocation makes an end read visible to ASan. */
        uint8_t *b = malloc(sizes[i]); memcpy(b,bad[i],sizes[i]);
        if (lz4_decompress(b,sizes[i],out,sizeof(out)) != 0) return 1;
        free(b);
    }
    uint8_t literal[] = {0x30,'a','b','c'};
    if (lz4_decompress(literal,sizeof(literal),out,2) != 0) return 1;
    if (lz4_decompress(literal,sizeof(literal),out,sizeof(out)) != 3 || memcmp(out,"abc",3)) return 1;
    if (argc == 3) {
        size_t cn,rn;
        uint8_t *c=read_file(argv[1],&cn), *r=read_file(argv[2],&rn), *decoded=malloc(rn);
        if (lz4_decompress(c,cn,decoded,rn) != rn || memcmp(r,decoded,rn)) return 1;
        free(c); free(r); free(decoded);
    }
    puts("PASS LZ4 bounds and production payload"); return 0;
}
