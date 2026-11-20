/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef I9100_EMMC_READ_STREAM_H
#define I9100_EMMC_READ_STREAM_H
#include <stdint.h>
#include <stddef.h>

#define I9RO_USER_SECTORS 30777344ULL
#define I9RO_BLOCK_BYTES 512U
#define I9RO_CHUNK_BYTES (1024U*1024U)
#define I9RO_HEADER_BYTES 128U
#define I9RO_FRAME_BYTES 32U
#define I9RO_PIT_OFFSET 0x4400U
#define I9RO_ARRAY_BYTES 16384U
#define I9RO_PIT_BYTES (28U+32U*132U)
#define I9RO_MAX_METADATA 131072U
#define I9RO_MODEL_FLAG 0x80000000U
#define I9RO_SAFE_FLAGS 15U /* RDONLY, exclusive, mount/swap clear, holders clear */
enum {I9RO_INVENTORY=1,I9RO_BACKUP_USER=2};
enum {I9RO_MBR=1,I9RO_PRIMARY_HEADER=2,I9RO_PRIMARY_ARRAY=3,
 I9RO_BACKUP_HEADER=4,I9RO_BACKUP_ARRAY=5,I9RO_PIT=6,I9RO_DATA=8,I9RO_END=9,I9RO_ERROR=10,
 I9RO_DEV_TEXT=16,I9RO_CID_TEXT=17,I9RO_SIZE_TEXT=18,I9RO_TYPE_TEXT=19,
 I9RO_MOUNTINFO=20,I9RO_SWAPS=21,I9RO_IOMEM=22,I9RO_CLOCKS=23,I9RO_BLOCKSIZE_TEXT=24};
enum {I9RO_POST=1};
enum {I9RO_ARGUMENT=-1,I9RO_DISABLED=-2,I9RO_IO=-3,I9RO_TABLE=-4,I9RO_IDENTITY=-5,
 I9RO_CHANGED=-6,I9RO_OUTPUT=-7};
struct i9ro_identity {uint64_t sectors;uint32_t cid[4],major,minor,flags;};
struct i9ro_io {
 void *cookie;
 int (*identity)(void *,struct i9ro_identity *); /* Also recheck mounts/holders. */
 int (*read_at)(void *,uint64_t byte_offset,uint32_t bytes,uint8_t *);
 int (*write_all)(void *,const uint8_t *,uint32_t);
 int (*metadata)(void *,uint32_t kind,const uint8_t **,uint32_t *);
 const uint8_t *producer_source_sha256; /*32B compile provenance, not authentication. */
};
struct i9ro_tables {
 uint8_t mbr[512],primary[512],backup[512],primary_array[I9RO_ARRAY_BYTES],backup_array[I9RO_ARRAY_BYTES];
 uint8_t pit[I9RO_PIT_BYTES];uint32_t array_bytes,pit_bytes;uint64_t primary_lba,backup_lba;
};
struct i9ro_stream {
 struct i9ro_identity identity;struct i9ro_tables tables;
 uint64_t data_bytes;uint32_t sequence,stream_crc,data_crc,mode;int error;
};
uint32_t i9ro_crc32(uint32_t state,const uint8_t *,uint32_t); /* Running state starts ~0U, final xor ~0U. */
int i9ro_emit(int enabled,struct i9ro_stream *,const struct i9ro_io *,uint32_t mode,
 const uint8_t nonce[16],const uint32_t expected_cid[4],uint8_t *chunk,uint32_t chunk_bytes);
/* Fixed read-only protocol. No write-to-device callback, raw command,
 * arbitrary partition/offset CLI or flush/format/erase operation exists.
 * Metadata and table CRCs detect damage; they do not authenticate hardware.
 * Whole-user backup checkpoints current identity/mount ownership each64MiB,
 * then compares both GPTs/PIT/MBR byte-for-byte before publishing END.
 * Linux RDONLY|EXCL blocks mounted/cooperating holders, not an unrelated
 * raw writer ignoring EXCL. Device operators must pause other writers.
 * Model flag cannot be cleared by the host importer or become deployment. */
#endif
