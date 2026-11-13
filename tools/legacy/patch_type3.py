PATH = "/mnt/d/Desktop/Git/ios-samsung-i9100/xnu-S2I9100/xnu/bsd/kern/decmpfs.c"
src = open(PATH).read()

impl = r'''
static int
decmpfs_fetch_uncompressed_data_Type3(vnode_t vp, vfs_context_t ctx, decmpfs_header *hdr,
	off_t offset, user_ssize_t size, int nvec, decmpfs_vector *vec, uint64_t *bytes_read)
{
	/* Type3: single zlib stream stored in the decmpfs xattr itself */
	int err = 0;
	uint8_t *ubuf;
	z_stream zs;
	int zr;
	uint64_t produced = 0;
	int vi = 0;
	user_ssize_t vec_off = 0;
	uint64_t copy_from, copy_len;

	*bytes_read = 0;
	if (size <= 0 || offset < 0)
		return EINVAL;
	if ((uint64_t)offset >= hdr->uncompressed_size)
		return 0;

	MALLOC(ubuf, uint8_t *, hdr->uncompressed_size, M_TEMP, M_WAITOK);
	if (!ubuf)
		return ENOMEM;

	bzero(&zs, sizeof(zs));
	zs.next_in = (Bytef *)hdr->attr_bytes;
	zs.avail_in = hdr->attr_size - sizeof(decmpfs_disk_header);
	zs.next_out = (Bytef *)ubuf;
	zs.avail_out = (uInt)hdr->uncompressed_size;
	zs.zalloc = type4_zalloc;
	zs.zfree = type4_zfree;
	if (inflateInit(&zs) != Z_OK) {
		FREE(ubuf, M_TEMP);
		return EIO;
	}
	zr = inflate(&zs, Z_FINISH);
	inflateEnd(&zs);
	if (zr != Z_STREAM_END || zs.total_out != hdr->uncompressed_size) {
		FREE(ubuf, M_TEMP);
		return EIO;
	}

	copy_from = (uint64_t)offset;
	copy_len = hdr->uncompressed_size - copy_from;
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
	}
	*bytes_read = produced;
	FREE(ubuf, M_TEMP);
	return err;
}

static int
decmpfs_validate_compressed_file_Type3(__unused vnode_t vp, __unused vfs_context_t ctx,
	__unused decmpfs_header *hdr)
{
	return 0;
}

static decmpfs_registration Type3Reg =
{
	.decmpfs_registration = DECMPFS_REGISTRATION_VERSION,
	.validate          = decmpfs_validate_compressed_file_Type3,
	.adjust_fetch      = NULL,
	.fetch             = decmpfs_fetch_uncompressed_data_Type3,
	.free_data         = NULL,
	.get_flags         = NULL
};

#pragma mark --- decmpfs initialization ---'''

old = "\n#pragma mark --- decmpfs initialization ---"
assert src.count(old) == 1, "init pragma not found"
src = src.replace(old, impl, 1)

old2 = "    register_decmpfs_decompressor(CMP_Type4, &Type4Reg);"
assert src.count(old2) == 1, "Type4 register not found"
src = src.replace(old2, "    register_decmpfs_decompressor(3, &Type3Reg);\n" + old2, 1)

open(PATH, "w").write(src)
print("patched OK")
