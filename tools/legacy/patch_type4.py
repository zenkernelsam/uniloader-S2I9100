import re

PATH = "/mnt/d/Desktop/Git/ios-samsung-i9100/xnu-S2I9100/xnu/bsd/kern/decmpfs.c"
src = open(PATH).read()

impl = r'''
#pragma mark --- Type4 compressor (zlib blocks in the resource fork) ---

/*
 * The "Type4" compressor splits the uncompressed file into 64KB chunks,
 * deflates each with zlib, and stores them in the cmpf resource of the
 * resource fork.  The cmpf resource body layout (little-endian):
 *   +0  uint32 chunk_count
 *   +4  uint32 data_start   (offset from body start to compressed stream area)
 *   +8  uint32 table[2*n-1] (compressed size of chunk i at index 2*i;
 *                            absolute end offset of chunk i at index 2*i+1)
 * Compressed chunks are stored consecutively at body_start + data_start.
 */

#define CMP_Type4       4
#define TYPE4_CHUNK     65536U

static void *
type4_zalloc(__unused void *notused, u_int num_items, u_int size)
{
	uint32_t *mem;
	uint32_t total = num_items * size + sizeof(uint32_t);
	mem = (uint32_t *)kalloc(total);
	if (!mem)
		return NULL;
	mem[0] = total;
	return mem + 1;
}

static void
type4_zfree(__unused void *notused, void *ptr)
{
	uint32_t *mem = (uint32_t *)ptr - 1;
	kfree((void *)mem, mem[0]);
}

static int
type4_rsrc_read(vnode_t vp, vfs_context_t ctx, off_t off, void *buf, user_size_t len)
{
	uio_t auio;
	size_t resid = 0;
	int err;

	auio = uio_create(1, off, UIO_SYSSPACE, UIO_READ);
	if (!auio)
		return ENOMEM;
	err = uio_addiov(auio, CAST_USER_ADDR_T(buf), len);
	if (err == 0)
		err = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, auio, &resid,
				  XATTR_NOSECURITY, ctx);
	uio_free(auio);
	if (!err && resid != (size_t)len)
		err = EIO;
	return err;
}

static int
decmpfs_fetch_uncompressed_data_Type4(vnode_t vp, vfs_context_t ctx, decmpfs_header *hdr,
	off_t offset, user_ssize_t size, int nvec, decmpfs_vector *vec, uint64_t *bytes_read)
{
	int err = 0;
	uint64_t nchunks, cstart, cend;
	uint32_t i;
	uint8_t rhdr[16];
	uint8_t chdr[8];
	uint32_t data_off, body_start, data_start;
	uint32_t *sizes = NULL;
	uint8_t *cbuf = NULL, *ubuf = NULL;
	uint64_t produced = 0;
	int vi = 0;
	user_ssize_t vec_off = 0;
	uint64_t base;

	*bytes_read = 0;
	if (size <= 0 || offset < 0) {
		err = EINVAL;
		goto out;
	}
	nchunks = (hdr->uncompressed_size + TYPE4_CHUNK - 1) / TYPE4_CHUNK;
	if (!nchunks) {
		err = EINVAL;
		goto out;
	}
	cstart = (uint64_t)offset / TYPE4_CHUNK;
	cend = ((uint64_t)offset + size - 1) / TYPE4_CHUNK;
	if (cend >= nchunks)
		cend = nchunks - 1;

	/* resource fork header: big-endian data offset at +0 */
	err = type4_rsrc_read(vp, ctx, 0, rhdr, sizeof(rhdr));
	if (err)
		goto out;
	data_off = OSSwapBigToHostInt32(*(uint32_t *)rhdr);
	if (data_off < 16 || data_off > (1U << 26)) {
		err = EINVAL;
		goto out;
	}
	/* resource data area = {uint32 len, body}; body starts at data_off+4 */
	body_start = data_off + 4;
	err = type4_rsrc_read(vp, ctx, body_start, chdr, sizeof(chdr));
	if (err)
		goto out;
	data_start = OSReadLittleInt32(chdr, 4);
	if (data_start < 8 || data_start > (1U << 26)) {
		err = EINVAL;
		goto out;
	}

	/* size table at body_start+8; entry 2*i = compressed size of chunk i */
	MALLOC(sizes, uint32_t *, sizeof(uint32_t) * (2 * cend + 1), M_TEMP, M_WAITOK);
	if (!sizes) {
		err = ENOMEM;
		goto out;
	}
	err = type4_rsrc_read(vp, ctx, body_start + 8, sizes,
			      sizeof(uint32_t) * (2 * cend + 1));
	if (err)
		goto out;
	for (i = 0; i <= 2 * cend; i++)
		sizes[i] = OSSwapLittleToHostInt32(sizes[i]);

	MALLOC(cbuf, uint8_t *, TYPE4_CHUNK * 2, M_TEMP, M_WAITOK);
	MALLOC(ubuf, uint8_t *, TYPE4_CHUNK, M_TEMP, M_WAITOK);
	if (!cbuf || !ubuf) {
		err = ENOMEM;
		goto out;
	}

	base = body_start + data_start;
	for (i = 0; i < (uint32_t)cstart; i++)
		base += sizes[2 * i];

	for (i = (uint32_t)cstart; i <= (uint32_t)cend && size > 0; i++) {
		uint32_t csize = sizes[2 * i];
		uint64_t usize, copy_from, copy_len;
		z_stream zs;
		int zr;

		if (!csize || csize > TYPE4_CHUNK * 2) {
			err = EINVAL;
			goto out;
		}
		err = type4_rsrc_read(vp, ctx, (off_t)base, cbuf, csize);
		if (err)
			goto out;
		base += csize;

		bzero(&zs, sizeof(zs));
		zs.next_in = (Bytef *)cbuf;
		zs.avail_in = csize;
		zs.next_out = (Bytef *)ubuf;
		zs.avail_out = TYPE4_CHUNK;
		zs.zalloc = type4_zalloc;
		zs.zfree = type4_zfree;
		if (inflateInit(&zs) != Z_OK) {
			err = EIO;
			goto out;
		}
		zr = inflate(&zs, Z_FINISH);
		usize = zs.total_out;
		inflateEnd(&zs);
		if (zr != Z_STREAM_END || usize == 0 ||
		    (i < nchunks - 1 && usize != TYPE4_CHUNK)) {
			err = EIO;
			goto out;
		}

		copy_from = (i == (uint32_t)cstart) ?
		    ((uint64_t)offset - (uint64_t)i * TYPE4_CHUNK) : 0;
		if (copy_from >= usize)
			continue;
		copy_len = usize - copy_from;
		if (copy_len > (uint64_t)size)
			copy_len = size;

		while (copy_len && vi < nvec) {
			user_ssize_t room = vec[vi].size - vec_off;
			user_ssize_t n;
			if (room <= 0) {
				vi++;
				vec_off = 0;
				continue;
			}
			n = (copy_len < (uint64_t)room) ? (user_ssize_t)copy_len : room;
			memcpy((char *)vec[vi].buf + vec_off, ubuf + copy_from, n);
			vec_off += n;
			copy_from += n;
			copy_len -= n;
			produced += n;
			size -= n;
		}
		if (copy_len)
			break;
	}
	if (bytes_read)
		*bytes_read = produced;
	err = 0;
out:
	if (sizes)
		FREE(sizes, M_TEMP);
	if (cbuf)
		FREE(cbuf, M_TEMP);
	if (ubuf)
		FREE(ubuf, M_TEMP);
	return err;
}

static int
decmpfs_validate_compressed_file_Type4(__unused vnode_t vp, __unused vfs_context_t ctx,
	__unused decmpfs_header *hdr)
{
	return 0;
}

static decmpfs_registration Type4Reg =
{
	.decmpfs_registration = DECMPFS_REGISTRATION_VERSION,
	.validate          = decmpfs_validate_compressed_file_Type4,
	.adjust_fetch      = NULL,
	.fetch             = decmpfs_fetch_uncompressed_data_Type4,
	.free_data         = NULL,
	.get_flags         = NULL
};

#pragma mark --- decmpfs initialization ---'''

assert src.count("\n#pragma mark --- decmpfs initialization ---") == 1
src = src.replace("\n#pragma mark --- decmpfs initialization ---", impl, 1)

old = "    register_decmpfs_decompressor(CMP_Type1, &Type1Reg);"
assert src.count(old) == 1
src = src.replace(old, old + "\n    register_decmpfs_decompressor(CMP_Type4, &Type4Reg);", 1)

old = "#include <sys/uio_internal.h>"
assert src.count(old) == 1
src = src.replace(old, old + "\n#include <libkern/zlib.h>\n#include <kern/kalloc.h>", 1)

open(PATH, "w").write(src)
print("patched OK")
