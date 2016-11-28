/*
mksef.c

Created:	December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Create a new SEF
*/

#define _POSIX_C_SOURCE 2
#define _MINIX_SOURCE

#include "os.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <sef/checkpoint.h>
#include <sef/dir.h>
#include <sef/inode.h>
#include <sef/super.h>

#include "buf.h"
#include "sha2.h"
#include "hmac_sha256.h"
#include "rijndael/rijndael-api.h"

#define DEF_MIN_BLK_SIZE	4096	/* 4K seems a good default minimum. */

#define DEF_MAX_INDIR		  16	/* Too much? */

/* Should get this from a header */
#define MIN_BLOCK_SIZE		1024
#define MAX_BLOCK_SIZE		(512*1024)
#define MAX_ALLOC_LEVELS	   4
#define DEF_START_RESERVED	(64*1024)
#define MIN_BLOCKS		 128	/* Minimum number of data blocks */

#define ARGON2_TIME		3.0	/* Target time for argon2 hash */

typedef unsigned long long fsize_T;

#define strtoull(s,c,d) strtoul(s,c,d)

static struct
{
	sef_super_T *super;
	buf_T *super_buf;

	sef_checkpoint_T *checkpoint;
	buf_T *checkpoint_buf;

	fsize_T alloc_block;
	buf_T *alloc_buf;
	uint32_T *alloc_data;
	unsigned alloc_next;

	unsigned inode_max_indir;	/* Max number of indirections. */
	struct
	{
		unsigned count;
		unsigned slot;
	} indirs[SEF_INODE_MAX_INDIR+1];

	int fd;

	char *password;

	int argon2_iter;
	int argon2_mem;
	int argon2_par;
} state;

static fsize_T parse_size(char *str, char **endptr);
static void compute_params(fsize_T size, unsigned min_blk_size, 
	unsigned max_indir, fsize_T max_file_size, int do_resize,
	fsize_T start_reserved, fsize_T end_reserved);
static int alloc_level(fsize_T size, unsigned block_size);
static int file_indir(fsize_T size, unsigned block_size);
static fsize_T compute_max_file_size(unsigned block_size, unsigned indirs);
static void super_init(unsigned block_size,
	fsize_T first_super_block, fsize_T second_super_block,
	fsize_T first_checkpoint_block, fsize_T second_checkpoint_block,
	fsize_T first_data_block, fsize_T last_data_block,
	unsigned bm_ind_levels, unsigned indirs);
static void super_write(void);
static void calibrate_argon2(double time);
static void do_argon2(int iter, int mem, int par, int hashlen, char *salt,
	char *passwd, char *hash, double *durationp);
static void compute_inode_indir(unsigned indirs);
static void checkpoint_init(void);
static void checkpoint_write(void);
static void alloc_init(fsize_T bmblock);
static void alloc_setup(fsize_T block, buf_T *buf);
static fsize_T alloc_block(void);
static void alloc_stop(void);
static void bitmap_init(fsize_T skip_bmblock);
static void bm_init_bits(fsize_T block, void *data);
static void special_inodes_init(void);
static void rootdir_init(void);
static void print_ptr(lbptr_T lbptr);
static buf_T *read_block(lbptr_T lbptr, size_t size);
static void make_writable(buf_T *buf);
static lbptr_T get_parent(lbptr_T lbptr, unsigned *offsetp);
static void write_buf(buf_T *buf);
static char *get_password(char *password_file);
static void bin2hex_str(void *in, size_t in_len, char *out, size_t out_len);
static void hex_str2bin(char *str, void *out, size_t out_len);
static void print_bin(void *buf, size_t size);
static char *fatal(char *fmt, ...) _NORETURN;
static void usage(void);

int main(int argc, char *argv[])
{
	int c, do_resize;
	unsigned min_blk_size, max_indir;
	fsize_T size;
	fsize_T max_file_size;
	fsize_T start_reserved, end_reserved;
	char *check;
	char *special;
	char *min_blk_size_str;
	char *max_file_size_str;
	char *max_indir_str;
	char *password_file;
	char *size_str;

	min_blk_size_str= NULL;
	max_file_size_str= NULL;
	max_indir_str= NULL;
	password_file= NULL;
	size_str= NULL;

#if 0
	printf("@ses_block_size: %u\n",
	    (unsigned)offsetof(sef_super_T, ses_block_size));
	printf("size sef_super_T: %u\n", sizeof(sef_super_T));
	assert(sizeof(sef_super_T) == 512);
	abort();
#endif
	printf("size sef_inode_T: %u\n", (unsigned)sizeof(sef_inode_T));

	while(c= getopt(argc, argv, "?b:f:I:p:s:"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'b':
			min_blk_size_str= optarg;
			break;
		case 'f':
			max_file_size_str= optarg;
			break;
		case 'I':
			max_indir_str= optarg;
			break;
		case 'p':
			password_file= optarg;
			break;
		case 's':
			size_str= optarg;
			break;
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	if (optind >= argc)
		usage();
	special= argv[optind++];

	if (optind != argc)
		usage();

	if (min_blk_size_str)
	{
		min_blk_size= strtoul(min_blk_size_str, &check, 0);
		if (check[0] != '\0')
		{
			fatal("unable to parse block size '%s'",
				min_blk_size_str);
		}
	}
	else
		min_blk_size= DEF_MIN_BLK_SIZE;

	if (max_indir_str)
	{
		max_indir= strtoul(max_indir_str, &check, 0);
		if (check[0] != '\0')
		{
			fatal("unable to parse max indir '%s'",
				max_indir_str);
		}
	}
	else
		max_indir= DEF_MAX_INDIR;

	if (size_str)
	{
		size= parse_size(size_str, &check);
		if (check[0] != '\0')
			fatal("unable to parse size '%s'", size_str);
	}
	else
		fatal("should get size from device");

	do_resize= 0;
	if (max_file_size_str)
	{
		if (strcmp(max_file_size_str, "dense") == 0)
		{
			do_resize= 1;
			max_file_size= size;
		}
		else if (strcmp(max_file_size_str, "sparse") == 0)
			max_file_size= -1;
		else
		{
			max_file_size= parse_size(max_file_size_str, &check);
			if (check[0] != '\0')
			{
				fatal("unable to parse max file size '%s'",
					max_file_size_str);
			}
		}
	}
	else
	{
		/* Assume dense mode */
		do_resize= 1;
		max_file_size= size;
	}

	state.fd= open(special, O_RDWR);
	if (state.fd == -1)
		fatal("unable to open '%s': %s", special, strerror(errno));

	buf_init(write_buf);

	state.password= get_password(password_file);

	calibrate_argon2(ARGON2_TIME);

	start_reserved= DEF_START_RESERVED;
	end_reserved= 0;
	compute_params(size, min_blk_size, max_indir, max_file_size,
		do_resize, start_reserved, end_reserved);

	/* Assume that the first bitmap block will always have enough
	 * free space to bootstrap. Otherwise, we should take a block from
	 * the middle of free space.
	 */
	alloc_init(0);

	bitmap_init(0);

	special_inodes_init();

	rootdir_init();

	alloc_stop();

	lbuf_sync();

	checkpoint_write();

	super_write();

	buf_flush();

	/* And we are done */
	return 0;
}

static struct
{
	char *prefix;
	int count;
	unsigned base;
} prefix_table[]=
{
	{ "k", 1, 1000 },
	{ "M", 2, 1000 },
	{ "G", 3, 1000 },
	{ "T", 4, 1000 },
	{ "P", 5, 1000 },
	{ "E", 6, 1000 },
	{ "Z", 7, 1000 },
	{ "Y", 8, 1000 },
	{ "Ki", 1, 1024 },
	{ "Mi", 2, 1024 },
	{ "Gi", 3, 1024 },
	{ "Ti", 4, 1024 },
	{ "Pi", 5, 1024 },
	{ "Ei", 6, 1024 },
	{ "Zi", 7, 1024 },
	{ "Yi", 8, 1024 },
	{ NULL }
};

static fsize_T parse_size(char *str, char **endptr)
{
	int i, j;
	char *check;
	fsize_T size, next;

	size= strtoull(str, &check, 0);
	if (check[0] == '\0')
	{
		if (endptr)
			*endptr= check;
		return size;
	}

	/* Skip one space if there is one */
	if (check[0] == ' ') check++;

	/* For the prefix in the table */
	for (i= 0; prefix_table[i].prefix != NULL; i++)
	{
		if (strcmp(check, prefix_table[i].prefix) == 0)
			break;
	}
	if (prefix_table[i].prefix == NULL)
	{
		/* Error, unknown prefix */
		if (endptr)
			*endptr= check;
		errno= EINVAL;
		return 0;
	}

	for (j= 0; j<prefix_table[i].count; j++)
	{
		next= size * prefix_table[i].base;
		if (next / prefix_table[i].base != size)
		{
			/* Overflow */
			if (endptr)
				*endptr= check;
			errno= ERANGE;
			return 0;
		}
		size= next;
	}

	check += strlen(prefix_table[i].prefix);

	if (endptr)
		*endptr= check;
	return size;
}

static void compute_params(fsize_T size, unsigned min_blk_size, 
	unsigned max_indir, fsize_T max_file_size, int do_resize,
	fsize_T start_reserved, fsize_T end_reserved)
{
	unsigned block_size;
	int levels, indirs;
	fsize_T first_super_block, second_super_block;
	fsize_T first_data_block, last_data_block;
	fsize_T first_checkpoint_block, second_checkpoint_block;

	/* The most basic parameter is the block size. The block size 
	 * subjected to a few constraints:
	 * - min block size based on filesystem datastructures such as
	 *   checkpoint blocks and inodes
	 * - max block size determined by the filesystem implementation
	 * - a maximum number of index levels for block allocation
	 * - a maximum number of indirect levels to reach the desired 
	 *   maximum file size.
	 */

	/* Consistency check */
	assert(MIN_BLOCK_SIZE >= SEF_SUPER_BLOCK_SIZE);
	assert(MIN_BLOCK_SIZE >= SEF_CHECKPOINT_SIZE);
	assert(MIN_BLOCK_SIZE >= SEF_INODE_SIZE);

	block_size= MIN_BLOCK_SIZE;

	if (min_blk_size > MAX_BLOCK_SIZE)
		fatal("min block size too big (>%u)", MAX_BLOCK_SIZE);
	while (block_size < min_blk_size)
		block_size *= 2;
	assert(block_size >= min_blk_size);

	for (;;)
	{
		levels= alloc_level(size, block_size);
		if (levels <= MAX_ALLOC_LEVELS)
			break;
		block_size *= 2;
	}

	/* Just an assert. Assume parameters are selected appropriately */
	assert (block_size <= MAX_BLOCK_SIZE);

	printf("levels %d for block size %d\n", levels, block_size);

	for (;;)
	{
		indirs= file_indir(max_file_size, block_size);
		if (indirs <= max_indir)
			break;
		block_size *= 2;
	}

	if (block_size > MAX_BLOCK_SIZE)
		fatal("Max indir too low for file size");
	
	printf("indirs %d for block size %d\n", indirs, block_size);

	if (do_resize)
	{
		max_file_size= compute_max_file_size(block_size, indirs);
		printf("new max file size %lld\n", max_file_size);
	}

	/* Recompute bitmap levels */
	levels= alloc_level(size, block_size);
	printf("new bitmap levels %d\n", levels);

	/* The superblock starts after start_reserved bytes. Round up to
	 * the superblock block size.
	 */
	if (start_reserved == 0)
		first_super_block= 0;
	else
		first_super_block= (start_reserved-1)/SEF_SUPER_BLOCK_SIZE + 1;

	printf("first super block at #%lld\n", first_super_block);

	/* The second superblock starts just before the end_reserved area,
	 * rounded down.
	 */
	second_super_block= (size-end_reserved)/SEF_SUPER_BLOCK_SIZE - 1;

	printf("second super block at #%lld\n", second_super_block);

	/* The first data block starts right after the first super block,
	 * subject to rounding of course.
	 */
	first_data_block= ((first_super_block+1)*SEF_SUPER_BLOCK_SIZE-1)/
		block_size+1;

	/* The last data block ends before the second super block */
	last_data_block= second_super_block*SEF_SUPER_BLOCK_SIZE/block_size - 1;

	if (last_data_block < first_data_block + MIN_BLOCKS)
		fatal("File system too small");
	printf("data blocks [%lld..%lld]\n", first_data_block,
		last_data_block);

	/* Put the checkpoint blocks at 1/3 and 2/3. */
	first_checkpoint_block= first_data_block +
		(last_data_block-first_data_block)/3;
	second_checkpoint_block= first_data_block +
		(last_data_block-first_data_block)/3*2;

	printf("checkpoint blocks: %lld and %lld\n", first_checkpoint_block,
		second_checkpoint_block);

	super_init(block_size,
		first_super_block, second_super_block,
		first_checkpoint_block, second_checkpoint_block,
		first_data_block, last_data_block, levels, indirs);
	checkpoint_init();
}

static int alloc_level(fsize_T size, unsigned block_size)
{
	fsize_T blocks, bm_blocks, index_blocks;
	unsigned bits_per_block, pointers_per_block;
	int levels;

	/* We have to keep rounding up. Avoid zero */
	assert(size > 0);

	blocks= (size-1)/block_size + 1;

	bits_per_block= block_size*8;

	bm_blocks= (blocks-1)/bits_per_block + 1;

	pointers_per_block= block_size / SEF_BLKPTR_SIZE;

	index_blocks= (bm_blocks-1)/pointers_per_block + 1;
	for (levels= 1;; levels++)
	{
		if (index_blocks <= 1)
			return levels;
		index_blocks= (index_blocks-1)/pointers_per_block + 1;
	}
}

static int file_indir(fsize_T size, unsigned block_size)
{
	fsize_T blocks, index_blocks;
	unsigned pointers_per_block;
	int levels;

	/* We have to keep rounding up. Avoid zero */
	assert(size > 0);

	blocks= (size-1)/block_size + 1;

	pointers_per_block= block_size / SEF_BLKPTR_SIZE;

	index_blocks= (blocks-1)/pointers_per_block + 1;
	for (levels= 1;; levels++)
	{
		if (index_blocks <= 1)
			return levels;
		index_blocks= (index_blocks-1)/pointers_per_block + 1;
	}
}

static fsize_T compute_max_file_size(unsigned block_size, unsigned indirs)
{
	unsigned pointers_per_block;
	int i;
	fsize_T size;

	/* First check for overflow */
	size= -1;
	if (file_indir(size, block_size) <= indirs)
	{
		/* We can handle the largest possible file size */
		return size;
	}

	pointers_per_block= block_size / SEF_BLKPTR_SIZE;

	size= block_size;
	for (i= 0; i<indirs; i++)
		size *= pointers_per_block;

	return size;
}

static void super_init(unsigned block_size,
	fsize_T first_super_block, fsize_T second_super_block,
	fsize_T first_checkpoint_block, fsize_T second_checkpoint_block,
	fsize_T first_data_block, fsize_T last_data_block,
	unsigned bm_ind_levels, unsigned indirs)
{
	sef_super_T *super;
	buf_T *buf;
	lbptr_T lbptr;
	sef_hash_T hash, rnd;
	hmac_sha256_ctx_t hm_ctx;
	uint8_T salt[256 / 8];
	char salt_str[2*sizeof(salt)+1];
	char hash_str[2*sizeof(hash)+1];

	if (sizeof(*super) != SEF_SUPER_BLOCK_SIZE)
	{
		printf("super_init: sizeof sef_super_T = %u\n",
			(unsigned)sizeof(sef_super_T));
	}
	assert(SEF_SUPER_BLOCK_SIZE == sizeof(*super));
	lbptr= lbuf_mkptr(LT_SUPER, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, SEF_SUPER_BLOCK_SIZE);

	super= buf_data_ptr(buf);
	memset(super, '\0', sizeof(*super));
	super->ses_first_super_block= first_super_block;
	super->ses_second_super_block= second_super_block;
	super->ses_block_size= block_size;
	super->ses_first_checkpoint_block= first_checkpoint_block;
	super->ses_second_checkpoint_block= second_checkpoint_block;
	super->ses_first_data_block= first_data_block;
	super->ses_last_data_block= last_data_block;
	super->ses_bm_ind_levels= bm_ind_levels;

	/* Fetch the password and hash it. We mix in the password hash to
	 * deal with bad random nmuber generators.
	 */
	os_random(salt, sizeof(salt));

	/* Convert salt to hex string */
	bin2hex_str(salt, sizeof(salt), salt_str, sizeof(salt_str));

	/* Call argon2 */
	do_argon2(state.argon2_iter, state.argon2_mem,
		state.argon2_par, sizeof(hash),
		salt_str, state.password, hash_str, NULL);

	/* Decode hash */
	hex_str2bin(hash_str, &hash, sizeof(hash));

	memset(hash_str, '\0', sizeof(hash_str));

	os_random(&rnd, sizeof(rnd));
	hmac_sha256_init(&hm_ctx, (unsigned char *)&hash, sizeof(hash));
	hmac_sha256_update(&hm_ctx, &rnd, sizeof(rnd));
	hmac_sha256_finish(&hm_ctx, super->ses_disk_key);
	hmac_sha256_cleanup(&hm_ctx);
	memset(&rnd, '\0', sizeof(rnd));
	memset(&hash, '\0', sizeof(hash));

	buf_lock(buf);
	buf_release(buf);

	state.super_buf= buf;
	state.super= super;

	compute_inode_indir(indirs);
}

static void super_write(void)
{
	int i;
	unsigned block_size, offset;
	uint8_T *data, *ciphertext;
	sef_super_T *super_out;
	fsize_T block;
	SHA256_CTX ctx;
	hmac_sha256_ctx_t hm_ctx;
	sef_hash_T hash, super_key, super_sign_key;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;
	sef_iv_T iv;
	ses_argon2_params_T argon2_params;
	char salt_str[2*sizeof(state.super->ses_argon2_salt)+1];
	char hash_str[2*sizeof(super_key)+1];

	block_size= SEF_SUPER_BLOCK_SIZE;

	/* Force all previous writes out */
	fsync(state.fd);

	/* Write two copies of the super block. Write the second one
	 * first.
	 */
	for (i= 0; i<2; i++)
	{
		/* Argon2 salt and 'encrypt' argon2 parameters with the
		 * salt.
		 */
		os_random(&state.super->ses_argon2_salt,
			sizeof(state.super->ses_argon2_salt));
		memset(&argon2_params, '\0', sizeof(argon2_params));
		argon2_params.sap_endian= 0;
		argon2_params.sap_parallelism= state.argon2_par;
		argon2_params.sap_iterations= state.argon2_iter;
		argon2_params.sap_mem= state.argon2_mem;

		/* AES CBC encrypt */
		if (rijndael_makekey(&aes_ctx,
			sizeof(state.super->ses_argon2_salt),
			state.super->ses_argon2_salt) != 0)
		{
			fatal("rijndael_makekey failed");
		}
		memset(&iv, '\0', sizeof(iv));
		if (rijndael_cbc_encrypt(&aes_ctx, &argon2_params,
			&state.super->ses_argon2_params,
			sizeof(state.super->ses_argon2_params),
			&iv) != sizeof(argon2_params))
		{
			fatal("rijndael_cbc_encrypt failed");
		}

		/* Convert salt to hex string */
		bin2hex_str(state.super->ses_argon2_salt, 
			sizeof(state.super->ses_argon2_salt),
			salt_str, sizeof(salt_str));

		/* Call argon2 */
		do_argon2(state.argon2_iter, state.argon2_mem,
			state.argon2_par, sizeof(super_key),
			salt_str, state.password, hash_str, NULL);

		/* Decode hash */
		hex_str2bin(hash_str, &super_key, sizeof(super_key));

		memset(hash_str, '\0', sizeof(hash_str));

		/* Compute super_sign_key */
		hmac_sha256_init(&hm_ctx, (unsigned char *)&super_key,
			sizeof(super_key));
		hmac_sha256_update(&hm_ctx, "S", 1);
		hmac_sha256_finish(&hm_ctx,
			(unsigned char *)&super_sign_key);
		hmac_sha256_cleanup(&hm_ctx);

		os_random(&state.super->ses_iv,
			sizeof(state.super->ses_iv));

		memset(&state.super->ses_flags, '\0',
			sizeof(state.super->ses_flags));
		/* Should set endian flag */

		block= i == 0 ? state.super->ses_second_super_block :
			state.super->ses_first_super_block;
		state.super->ses_block= block;

		/* Hash all except the hash */
		offset= offsetof(sef_super_T, ses_iv);
		assert(offset == sizeof(state.super->ses_argon2_salt) +
			sizeof(ses_argon2_params_T) + sizeof(sef_hash_T));
		data= (uint8_T *)state.super;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, data+offset, block_size-offset);
		SHA256_Final((unsigned char *)&hash, &ctx);

		/* Sign hash */
		hmac_sha256_init(&hm_ctx, (unsigned char *)&super_sign_key, 
			sizeof(super_sign_key));
		hmac_sha256_update(&hm_ctx, &hash, sizeof(hash));
		hmac_sha256_finish(&hm_ctx,
			(unsigned char *)&state.super->ses_signed_hash);
		hmac_sha256_cleanup(&hm_ctx);

		/* Create the AES encryption key */
		hmac_sha256_init(&hm_ctx, &super_key, sizeof(super_key));
		hmac_sha256_update(&hm_ctx,
			&state.super->ses_signed_hash,
			sizeof(state.super->ses_signed_hash));
		hmac_sha256_finish(&hm_ctx, aes_key);
		hmac_sha256_cleanup(&hm_ctx);

		ciphertext= malloc(block_size);
		super_out= (sef_super_T *)ciphertext;
		memcpy(super_out->ses_argon2_salt,
			state.super->ses_argon2_salt,
			sizeof(super_out->ses_argon2_salt));
		super_out->ses_argon2_params= state.super->ses_argon2_params;
		super_out->ses_signed_hash= state.super->ses_signed_hash;

		/* AES CBC encrypt */
		if (rijndael_makekey(&aes_ctx, sizeof(aes_key), aes_key) != 0)
			fatal("rijndael_makekey failed");
		memset(aes_key, '\0', sizeof(aes_key));
		
		memset(&iv, '\0', sizeof(iv));
		if (rijndael_cbc_encrypt(&aes_ctx, data+offset,
			ciphertext+offset, block_size-offset,
			&iv) != block_size-offset)
		{
			fatal("rijndael_cbc_encrypt failed");
		}

		memset(&aes_ctx, '\0', sizeof(aes_ctx));

		printf("write_buf: block %lld, offset %lld\n",
			block, block*block_size);

		lseek(state.fd, block*block_size, SEEK_SET);
		if (write(state.fd, ciphertext, block_size) != block_size)
			fatal("write failed");

		free(ciphertext);

		/* Make sure this block makes it to disk */
		fsync(state.fd);
	}

	memset(state.password, '\0', strlen(state.password));
	free(state.password); state.password= NULL;

	memset(&super_sign_key, '\0', sizeof(super_sign_key));

	/* Mark the buffer as not writable. Assume we only have a lock. */
	state.super= NULL;
	buf_setclean(state.super_buf);
	buf_unlock(state.super_buf);
	state.super_buf= NULL;
}

static void calibrate_argon2(double time)
{
	int iter, mem, par, iter_ref;
	double duration;
	char *salt= "test salt";
	char *passwd= "test passwd";
	char hash[256 / 8];

	iter= 1;
	mem= 3;
	par= 1;

	for (;;)
	{
		do_argon2(iter, mem, par, sizeof(hash), salt, passwd, NULL,
			&duration);
		if (duration >= time)
			break;
		iter *= 2;
		mem++;
	}

	/* Reduce iter */
	iter_ref= iter;
	iter= iter_ref * time / duration + 1;

	printf("reducing iter from %d to %d\n", iter_ref, iter);

	state.argon2_iter= iter;
	state.argon2_mem= mem;
	state.argon2_par= par;

	printf("argon2 params: iter %d, mem %d, par %d\n", iter, mem, par);
}

static void do_argon2(int iter, int mem, int par, int hashlen, char *salt,
	char *passwd, char *hash, double *durationp)
{
	pid_t pid;
	int r, status;
	FILE *file;
	double duration;
	int paramfds[2];
	int hashfds[2];
	struct timeval start_tv, end_tv;

#if 0
	printf("do_argon2: iter %d, mem %d, par %d, hashlen %d, salt '%s', passwd '%s'\n",
		iter, mem, par, hashlen, salt, passwd);
#endif

	pipe(paramfds);
	pipe(hashfds);

	pid= fork();
	if (pid == 0)
	{
		/* Child */
		dup2(paramfds[0], 0);
		close(paramfds[1]);
		dup2(hashfds[1], 1);
		close(hashfds[0]);

		close(state.fd);

		execlp("argon2a", "argon2a", "-f", NULL);
		fatal("exec of argon2a failed");
	}
	else if (pid == -1)
		fatal("fork failed");

	/* Parent */
	close(hashfds[1]);
	close(paramfds[0]);

	file= fdopen(paramfds[1], "w");
	fprintf(file, "%s\n", passwd);
	fprintf(file, "%d\n", iter);
	fprintf(file, "%d\n", mem);
	fprintf(file, "%d\n", par);
	fprintf(file, "%d\n", hashlen);
	fprintf(file, "%s\n", salt);
	fclose(file);

	gettimeofday(&start_tv, NULL);

	r= waitpid(pid, &status, 0);
	if (r == -1)
		fatal("waitpid failed");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fatal("argon2a failed");

	gettimeofday(&end_tv, NULL);

	duration= (end_tv.tv_sec-start_tv.tv_sec) +
		(end_tv.tv_usec-start_tv.tv_usec)/1e6;
	printf("argon2a took %f s\n", duration);

	if (hash)
	{
		file= fdopen(hashfds[0], "r");
		if (fread(hash, 1, 2*hashlen+1, file) != 2*hashlen+1)
			fatal("do_argon2: short hash string");
		fclose(file);
		if (hash[2*hashlen] != '\n')
			fatal("do_argon2: hash too long");
		hash[2*hashlen]= '\0';
	}

	if (durationp)
		*durationp= duration;
}

static void compute_inode_indir(unsigned indirs)
{
	int i;
	unsigned directs, level;

	if (indirs < SEF_INODE_BLKPTRS)
	{
		directs= SEF_INODE_BLKPTRS-indirs;
		for (i= 0; i<directs; i++)
			state.super->ses_inode_blkptrs[i]= 0;
		for (i= 0; i<indirs; i++)
			state.super->ses_inode_blkptrs[directs+i]= i+1;
	}
	else
		fatal("compute_inode_indir: should allocate indirs");
	printf("compute_inode_indir:");
	for (i= 0; i<SEF_INODE_BLKPTRS; i++)
		printf(" %d", state.super->ses_inode_blkptrs[i]);
	printf("\n");

	for (i= 0; i<SEF_INODE_BLKPTRS; i++)
	{
		level= state.super->ses_inode_blkptrs[i];
		assert(level <= SEF_INODE_MAX_INDIR);
		if (state.indirs[level].count == 0)
		{
			state.indirs[level].count= 1;
			state.indirs[level].slot= i;
		}
		else
			state.indirs[level].count++;
	}
	for (i= 0; i<SEF_INODE_BLKPTRS; i++)
	{
		if (!state.indirs[i].count)
			continue;
		printf("compute_inode_indir: indirs[%d]: count %d, slot %d\n",
			i, state.indirs[i].count,
			state.indirs[i].slot);
	}
	state.inode_max_indir= indirs;
}

static void checkpoint_init(void)
{
	sef_checkpoint_T *cp;
	buf_T *buf;
	lbptr_T lbptr;

	if (sizeof(*cp) != SEF_CHECKPOINT_SIZE)
	{
		printf("checkpoint_init: sizeof sef_checkpoint_T = %u\n",
			(unsigned)sizeof(sef_checkpoint_T));
	}
	assert(SEF_CHECKPOINT_SIZE == sizeof(*cp));
	lbptr= lbuf_mkptr(LT_CHECKPOINT, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, state.super->ses_block_size);

	cp= buf_data_ptr(buf);
	memset(cp, '\0', state.super->ses_block_size);
	cp->secp_free_blocks= 0;

	buf_setvalid(buf);
	buf_setwritable(buf);
	buf_lock(buf);
	buf_release(buf);
	buf_write_ref(buf);	/* To avoid the getting written out */

	state.checkpoint_buf= buf;
	state.checkpoint= cp;
}

static void checkpoint_write(void)
{
	int i;
	unsigned block_size, offset;
	uint8_T *data, *ciphertext;
	fsize_T block;
	SHA256_CTX ctx;
	hmac_sha256_ctx_t hm_ctx;
	sef_hash_T hash, disk_sign_key;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;
	sef_iv_T iv;

	block_size= state.super->ses_block_size;

	/* Compute disk_sign_key */
	hmac_sha256_init(&hm_ctx,
		(unsigned char *)&state.super->ses_disk_key, 
			sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx, "S", 1);
	hmac_sha256_finish(&hm_ctx,
		(unsigned char *)&disk_sign_key);
	hmac_sha256_cleanup(&hm_ctx);

	/* Write two copies of the checkpoint block */
	for (i= 0; i<2; i++)
	{
		os_random(&state.checkpoint->secp_iv,
			sizeof(state.checkpoint->secp_iv));

		memset(&state.checkpoint->secp_flags, '\0',
			sizeof(state.checkpoint->secp_flags));
		/* Should set endian flag */

		block= i == 0 ? state.super->ses_first_checkpoint_block :
			state.super->ses_second_checkpoint_block;
		state.checkpoint->secp_block= block;

		state.checkpoint->secp_seqnr= i;

		/* Hash all except the hash */
		offset= offsetof(sef_checkpoint_T, secp_iv);
		assert(offset == sizeof(sef_hash_T));
		data= (uint8_T *)state.checkpoint;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, data+offset, block_size-offset);
		SHA256_Final((unsigned char *)&hash, &ctx);

		/* Sign hash */
		hmac_sha256_init(&hm_ctx, (unsigned char *)&disk_sign_key, 
			sizeof(disk_sign_key));
		hmac_sha256_update(&hm_ctx, &hash, sizeof(hash));
		hmac_sha256_finish(&hm_ctx,
			(unsigned char *)&state.checkpoint->secp_signed_hash);
		hmac_sha256_cleanup(&hm_ctx);

		/* Create the AES encryption key */
		hmac_sha256_init(&hm_ctx, state.super->ses_disk_key, 
			sizeof(state.super->ses_disk_key));
		hmac_sha256_update(&hm_ctx,
			&state.checkpoint->secp_signed_hash,
			sizeof(state.checkpoint->secp_signed_hash));
		hmac_sha256_finish(&hm_ctx, aes_key);
		hmac_sha256_cleanup(&hm_ctx);

		ciphertext= malloc(block_size);
		memcpy(ciphertext, &state.checkpoint->secp_signed_hash,
			sizeof(state.checkpoint->secp_signed_hash));

#if 0
		{ int i;
		printf("checkpoint_write: ");
		for(i= 0; i<block_size; i++)
			printf("%02x", ((uint8_T *)data)[i]);
		printf("\n");
		}
#endif

		/* AES CBC encrypt */
		if (rijndael_makekey(&aes_ctx, sizeof(aes_key), aes_key) != 0)
			fatal("rijndael_makekey failed");
		memset(aes_key, '\0', sizeof(aes_key));
		
		memset(&iv, '\0', sizeof(iv));
		if (rijndael_cbc_encrypt(&aes_ctx, data+offset,
			ciphertext+offset, block_size-offset,
			&iv) != block_size-offset)
		{
			fatal("rijndael_cbc_encrypt failed");
		}

		memset(&aes_ctx, '\0', sizeof(aes_ctx));

		printf("write_buf: block %lld, offset %lld\n",
			block, block*block_size);

		lseek(state.fd, block*block_size, SEEK_SET);
		if (write(state.fd, ciphertext, block_size) != block_size)
			fatal("write failed");

		free(ciphertext);
	}

	memset(&disk_sign_key, '\0', sizeof(disk_sign_key));

	/* Mark the buffer as not writable. Assume we only have a lock. */
	state.checkpoint= NULL;
	buf_setclean(state.checkpoint_buf);
	buf_unlock(state.checkpoint_buf);
	buf_release_write(state.checkpoint_buf);
	state.checkpoint_buf= NULL;
}

static void alloc_init(fsize_T bmblock)
{
	unsigned block_size;
	lbptr_T lbptr;
	buf_T *buf;

	block_size= state.super->ses_block_size;

	lbptr= lbuf_mkptr(LT_BITMAP, 0, 0, 0, bmblock);
	buf= lbuf_alloc(lbptr, block_size);

	bm_init_bits(bmblock, buf_data_ptr(buf));

	buf_setvalid(buf);

	alloc_setup(bmblock, buf);

	make_writable(buf);

	/* Now we got two references, a read reference and a write
	 * reference. Drop them both.
	 */
	buf_release(buf);
	buf_release_write(buf);
}

static void alloc_setup(fsize_T block, buf_T *buf)
{
	/* Lock the buffer. This keeps the buffer in the same place
	 * in memory and serves as our reference.
	 */
	buf_lock(buf);

	state.alloc_block= block;
	state.alloc_buf= buf;
	state.alloc_data= buf_data_ptr(buf);
	state.alloc_next= 0;
}

static fsize_T alloc_block(void)
{
	unsigned bits_per_block, next, bit, ind;

	bits_per_block= state.super->ses_block_size * 8;
	next= state.alloc_next;
	while (next < bits_per_block)
	{
		bit= next % 32;
		ind= next / 32;
		if (!(state.alloc_data[ind] & (1 << bit)))
		{
			next++;
			continue;
		}
		state.alloc_data[ind] &=  ~(((uint32_T)1) << bit);
		state.checkpoint->secp_free_blocks--;
		state.alloc_next= next+1;
		return state.alloc_block*bits_per_block + next;
	}
	fatal("alloc_block: should find new block");
}

static void alloc_stop(void)
{
	buf_T *buf;

	buf= state.alloc_buf;
	state.alloc_buf= NULL;
	state.alloc_data= NULL;

	/* The only reference we are expected to have is a lock */
	buf_unlock(buf);
	buf= NULL;
}

static void bitmap_init(fsize_T skip_bmblock)
{
	unsigned block_size, bits_per_blocks;
	buf_T *buf;
	fsize_T block, bm_blocks;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	bits_per_blocks= block_size * 8;
	bm_blocks= state.super->ses_last_data_block/bits_per_blocks + 1;

	for (block= 0; block < bm_blocks; block++)
	{
		if (block == skip_bmblock)
			continue;
		lbptr= lbuf_mkptr(LT_BITMAP, 0, 0, 0, block);
		buf= read_block(lbptr, block_size);
		make_writable(buf);
		bm_init_bits(block, buf_data_ptr(buf));

		/* We got a read and a write reference, drop them */
		buf_release(buf);
		buf_release_write(buf);
	}
}

static void bm_init_bits(fsize_T block, void *data)
{
	int i;
	unsigned block_size, bits_per_block, bit, ind;
	fsize_T base, start, end, checkpoint_block;
	uint32_T *words;

	block_size= state.super->ses_block_size;

	/* Computer start and end block numbers */
	bits_per_block= block_size * 8;
	base= block * bits_per_block;
	start= base;
	end= start + bits_per_block;

	if (start < state.super->ses_first_data_block)
		start= state.super->ses_first_data_block;
	if (end > state.super->ses_last_data_block+1)
		end= state.super->ses_last_data_block+1;

	memset(data, '\0', block_size);
	if (start >= end)
		return;	/* Nothing to do */

	words= data;

	while (start % 32 != 0 && start < end)
	{
		bit= start % 32;
		ind= (start-base)/32;
#if 0
		printf("block %lld, index %d, bit %d\n",
			start, ind, bit);
#endif
		words[ind] |= (1 << bit);
		state.checkpoint->secp_free_blocks++;
		start++;
	}
	while (start+32 <= end)
	{
		ind= (start-base)/32;
#if 0
		printf("block %lld, index %d\n", start, ind);
#endif
		words[ind] |= 0xffffffff;
		state.checkpoint->secp_free_blocks += 32;
		start += 32;
	}
	while (start < end)
	{
		bit= start % 32;
		ind= (start-base)/32;
#if 0
		printf("block %lld, index %d, bit %d\n",
			start, ind, bit);
#endif
		words[ind] |= (1 << bit);
		state.checkpoint->secp_free_blocks++;
		start++;
	}

	for (i= 0; i<2; i++)
	{
		checkpoint_block= i == 0 ? 
			state.super->ses_first_checkpoint_block :
			state.super->ses_second_checkpoint_block;
		if (checkpoint_block >= base && checkpoint_block < end)
		{
			bit= checkpoint_block % 32;
			ind= (checkpoint_block-base)/32;
#if 0
			printf("block %lld, index %d, bit %d\n",
				start, ind, bit);
#endif
			words[ind] &= ~(((uint32_T)1) << bit);
			state.checkpoint->secp_free_blocks--;
		}
	}
}

static void special_inodes_init(void)
{
	unsigned block_size, inodes_per_block, ind;
	uint64_T ino;
	buf_T *buf;
	sef_inode_T *inodep;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	for (ino= 0; ino<SEF_ROOT_INODE; ino++)
	{
		lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0,
			ino/inodes_per_block);

		buf= read_block(lbptr, block_size);
		make_writable(buf);

		ind= ino % inodes_per_block;

		assert(sizeof(*inodep) == SEF_INODE_SIZE);
		inodep= &((sef_inode_T *)buf_data_ptr(buf))[ind];

		memset(inodep, '\0', sizeof(*inodep));

		if (ino == SEF_UNREF_INODE)
			inodep->sei_mode= SIM_UNREF;
		else
			inodep->sei_mode= SIM_RESERVED;
		inodep->sei_nlink= 1;

		state.checkpoint->secp_inodes++;

		/* Clean up */
		inodep= NULL;
		buf_release(buf);
		buf_release_write(buf);
		buf= NULL;
	}
}

static void rootdir_init(void)
{
	unsigned block_size, inodes_per_block, ind, size, space;
	buf_T *buf;
	sef_inode_T *inodep;
	lbptr_T lbptr;
	sef_dirent_T dot_dotdot[2];

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	printf("rootdir_init: inodes per block %d\n", inodes_per_block);

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, SEF_ROOT_INODE/inodes_per_block);

	buf= read_block(lbptr, block_size);
	make_writable(buf);

	ind= SEF_ROOT_INODE % inodes_per_block;

	printf("inode size = %u\n", (unsigned)sizeof(*inodep));
	assert(sizeof(*inodep) == SEF_INODE_SIZE);
	inodep= &((sef_inode_T *)buf_data_ptr(buf))[ind];

	memset(dot_dotdot, '\0', sizeof(dot_dotdot));	/* Don't leak */

	assert(sizeof(dot_dotdot[0]) == 16);
	dot_dotdot[0].sed_inode= SEF_ROOT_INODE;
	dot_dotdot[0].sed_extra= 0;
	strlcpy((char *)dot_dotdot[0].sed_name, ".",
		sizeof(dot_dotdot[0].sed_name));
	dot_dotdot[1].sed_inode= SEF_ROOT_INODE;
	dot_dotdot[1].sed_extra= 0;
	strlcpy((char *)dot_dotdot[1].sed_name, "..",
		sizeof(dot_dotdot[1].sed_name));

	size= sizeof(dot_dotdot);

	/* Amount of space */
	space= SEF_INODE_SIZE - offsetof(sef_inode_T, sei_blkptrs[0]);

	/* There is enough space */
	assert(size <= space);

	memcpy(inodep->sei_blkptrs, dot_dotdot, size);

	inodep->sei_mode= SIM_DIRECTORY;
	inodep->sei_nlink= 2;
	inodep->sei_size= size;
	inodep->sei_flags= SIF_IMMEDIATE;

	/* More inode fields */

	state.checkpoint->secp_inodes++;

	/* Clean up */
	inodep= NULL;
	buf_release(buf);
	buf_release_write(buf);
	buf= NULL;
}

static void print_ptr(lbptr_T lbptr)
{
	char *type_str;

	type_str= NULL;
	switch(lbptr.lbp_type)
	{
	case LT_CHECKPOINT: type_str= "CHECKPOINT"; break;
	case LT_BM_INDEX: type_str= "BM_INDEX"; break;
	case LT_BITMAP: type_str= "BITMAP"; break;
	case LT_INODE_INDEX: type_str= "INODE_INDEX"; break;
	case LT_INODE: type_str= "INODE"; break;
	}
	if (type_str)
		printf("(%s", type_str);
	else
		printf("(t%u", lbptr.lbp_type);
	printf(",s%llu,i%llu,l%u,o%llu)",
		(unsigned long long)lbptr.lbp_space,
		(unsigned long long)lbptr.lbp_inode,
		lbptr.lbp_level,
		(unsigned long long)lbptr.lbp_offset);
}

buf_T *read_block(lbptr_T lbptr, size_t size)
{
	uint8_T *p_data;
	buf_T *p_buf;
	buf_T *buf;
	unsigned offset;
	uint64_T block;
	lbptr_T parent;

	printf("read_block: for block ");
	print_ptr(lbptr);
	printf("\n");

	buf= lbuf_alloc(lbptr, size);
	if (buf_is_valid(buf))
		return buf;

	parent= get_parent(lbptr, &offset);
	p_buf= read_block(parent, state.super->ses_block_size);

	printf("read_block: got parent ");
	print_ptr(parent);
	printf(" offset %u for block ", offset);
	print_ptr(lbptr);
	printf("\n");

	p_data= buf_data_ptr(p_buf);
	block= ((sef_blkptr_T *)(p_data+offset))->sebp_block;
	buf_release(p_buf); p_buf= NULL;
	p_data= NULL;

	if (block == 0)
	{
		/* This logical block does not exist. Just clear the block
		 * an mark it valid.
		 */
		memset(buf_data_ptr(buf), '\0', state.super->ses_block_size);
		buf_setvalid(buf);
		return buf;
	}
	printf("read_block: my block is %llu\n", (unsigned long long)block);

	fatal("read_block: should read");
}

static void make_writable(buf_T *buf)
{
	unsigned offset;
	buf_T *p_buf;
	uint8_T *p_data;
	sef_blkptr_T *blkptr;
	fsize_T block, old_block;
	lbptr_T lbptr, parent;

	if (buf_is_writable(buf))
	{
		buf_write_ref(buf);
		return;
	}
	lbptr= buf_get_ptr(buf);

	printf("make_writable: for block ");
	print_ptr(lbptr);
	printf("\n");

	parent= get_parent(lbptr, &offset);
	p_buf= read_block(parent, state.super->ses_block_size);
	make_writable(p_buf);

	/* Drop the read reference. We implicitly keep the write reference. */
	buf_release(p_buf);

	printf("write_block: got parent ");
	print_ptr(parent);
	printf(" offset %u for block ", offset);
	print_ptr(lbptr);
	printf("\n");

	block= alloc_block();
	printf("make_writable: got new block %lld\n", block);

	/* Extract old block and update block pointer */
	p_data= buf_data_ptr(p_buf);
	blkptr= (sef_blkptr_T *)(p_data + offset);
	old_block= blkptr->sebp_block;
	memset(blkptr, '\0', sizeof(*blkptr));
	blkptr->sebp_block= block;
	p_data= NULL;
	blkptr= NULL;

	/* We don't expect to update the same block twice. */
	assert(old_block == 0);

	/* Make writable and add a write ref */
	buf_setwritable(buf);
	buf_write_ref(buf);

	printf("make_writable: buf refs: r%d, w%d, l%d\n",
		buf->b_readers, buf->b_writers, buf->b_locks);
	printf("make_writable: p_buf refs: r%d, w%d, l%d\n",
		p_buf->b_readers, p_buf->b_writers, p_buf->b_locks);
}

static lbptr_T get_parent(lbptr_T lbptr, unsigned *offsetp)
{
	unsigned block_size, pointers_per_block, slot;
	int ind_levels;

	block_size= state.super->ses_block_size;
	pointers_per_block= block_size / SEF_BLKPTR_SIZE;
	switch(lbptr.lbp_type)
	{
	case LT_CHECKPOINT:
		fatal("get_parent: checkpoint has no parent");

	case LT_BM_INDEX:
		assert(lbptr.lbp_inode == 0);
		/* If the index level is equal to height of the index then
		 * the parent is the checkpoint block.
		 */
		ind_levels= state.super->ses_bm_ind_levels;
		if (lbptr.lbp_level < ind_levels)
		{
			*offsetp= (lbptr.lbp_offset % pointers_per_block)*
				SEF_BLKPTR_SIZE;
			return lbuf_mkptr(LT_BM_INDEX,
				lbptr.lbp_space, lbptr.lbp_inode,
				lbptr.lbp_level+1,
				lbptr.lbp_offset / pointers_per_block);
		}
		assert(lbptr.lbp_level == ind_levels);
		*offsetp= offsetof(sef_checkpoint_T, secp_bm_index);
		return lbuf_mkptr(LT_CHECKPOINT,
			lbptr.lbp_space, 0, 0, 0);

	case LT_BITMAP:
		/* There is always at least one index level */
		assert(lbptr.lbp_inode == 0);
		assert(lbptr.lbp_level == 0);
		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_BM_INDEX,
			lbptr.lbp_space, 0, 1,
			lbptr.lbp_offset / pointers_per_block);

	case LT_INODE_INDEX:
		assert(lbptr.lbp_inode == 0);
		assert(lbptr.lbp_level <= state.inode_max_indir);

		if (lbptr.lbp_offset < state.indirs[lbptr.lbp_level].count)
		{
			slot= state.indirs[lbptr.lbp_level].slot +
				lbptr.lbp_offset;
			*offsetp= offsetof(sef_checkpoint_T, secp_blkptrs[0]) +
				slot * sizeof(sef_blkptr_T);
			return lbuf_mkptr(LT_CHECKPOINT,
				lbptr.lbp_space, 0, 0, 0);
		}

		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_INODE_INDEX,
			lbptr.lbp_space, 0, lbptr.lbp_level+1,
			lbptr.lbp_offset / pointers_per_block);

	case LT_INODE:
		assert(lbptr.lbp_inode == 0);
		assert(lbptr.lbp_level == 0);
		if (lbptr.lbp_offset < state.indirs[0].count)
		{
			slot= state.indirs[0].slot + lbptr.lbp_offset;
			*offsetp= offsetof(sef_checkpoint_T, secp_blkptrs[0]) +
				slot * sizeof(sef_blkptr_T);
			return lbuf_mkptr(LT_CHECKPOINT,
				lbptr.lbp_space, 0, 0, 0);
		}

		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_INODE_INDEX,
			lbptr.lbp_space, 0, 1,
			lbptr.lbp_offset / pointers_per_block);

	default:
		fatal("get_parent: should support type %d", lbptr.lbp_type);
	}
}

static void write_buf(buf_T *buf)
{
	unsigned block_size, offset;
	fsize_T block;
	buf_T *p_buf;
	uint8_T *p_data, *ciphertext;
	sef_blkptr_T *p_blkptr;
	lbptr_T lbptr, p_lbptr;
	sef_blkptr_T blkptr;
	SHA256_CTX ctx;
	hmac_sha256_ctx_t hm_ctx;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;

	block_size= state.super->ses_block_size;

	lbptr= buf_get_ptr(buf);
	printf("write_buf: writing block ");
	print_ptr(lbptr);
	printf("\n");

	p_lbptr= get_parent(lbptr, &offset);
	p_buf= lbuf_alloc(p_lbptr, state.super->ses_block_size);

	/* The parent is valid and writable */
	assert(buf_is_valid(p_buf));
	assert(buf_is_writable(p_buf));

	printf("write_buf: parent ");
	print_ptr(p_lbptr);
	printf(", offset %u\n", offset);

	printf("write_buf: block data: ");
	print_bin(buf_data_ptr(buf), block_size);
	printf("\n");

	/* Start filling in the block pointer */
	/* Hash */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf_data_ptr(buf), block_size);
	SHA256_Final((unsigned char *)&blkptr.sebp_hash, &ctx);

	os_random(&blkptr.sebp_iv, sizeof(blkptr.sebp_iv));

	memset(&blkptr.sebp_flags, '\0', sizeof(blkptr.sebp_flags));
	/* Should set endian flag */

	p_data= buf_data_ptr(p_buf);
	p_blkptr= (sef_blkptr_T *)(p_data + offset);
	block= blkptr.sebp_block= p_blkptr->sebp_block;

	/* Copy block pointer back to parent */
	*p_blkptr= blkptr;

	/* We are done with the parent */
	p_blkptr= NULL;
	p_data= NULL;
	buf_release(p_buf);
	buf_release_write(p_buf);
	p_buf= NULL;

#if 1
	printf("write_buf: blkptr: ");
	print_bin(&blkptr, sizeof(blkptr));
	printf("\n");
	printf("write_buf: ses_disk_key: ");
	print_bin(state.super->ses_disk_key,
		sizeof(state.super->ses_disk_key));
	printf("\n");
#endif

	/* Create the AES encryption key */
	hmac_sha256_init(&hm_ctx, state.super->ses_disk_key, 
		sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx, &blkptr, sizeof(blkptr));
	hmac_sha256_finish(&hm_ctx, aes_key);
	hmac_sha256_cleanup(&hm_ctx);


#if 1
	printf("write_buf: aes_key: ");
	print_bin(aes_key, sizeof(aes_key));
	printf("\n");
#endif

	/* AES CBC encrypt */
	ciphertext= malloc(block_size);
	if (rijndael_makekey(&aes_ctx, sizeof(aes_key), aes_key) != 0)
		fatal("rijndael_makekey failed");
	memset(aes_key, '\0', sizeof(aes_key));

#if 0
	{ int i; uint8_T *data;
	data= buf_data_ptr(buf);
	printf("write_buf: plaintext: ");
	for(i= 0; i<block_size; i++)
		printf("%02x", data[i]);
	printf("\n");
	}
#endif
	
	if (rijndael_cbc_encrypt(&aes_ctx, buf_data_ptr(buf), 
		ciphertext, block_size, &blkptr.sebp_iv) != block_size)
		fatal("rijndael_cbc_encrypt failed");

	memset(&aes_ctx, '\0', sizeof(aes_ctx));
	memset(&blkptr, '\0', sizeof(blkptr));

	printf("write_buf: block %lld, offset %lld\n",
		block, block*block_size);

	lseek(state.fd, block*block_size, SEEK_SET);
	if (write(state.fd, ciphertext, block_size) != block_size)
		fatal("write failed");

	free(ciphertext);

	buf_setclean(buf);
}

static char *get_password(char *password_file)
{
	size_t size;
	char *pw, *pw_o;
	FILE *fh;

	if (password_file)
	{
		fh= fopen(password_file, "r");
		if (!fh)
		{
			fatal("unable to open '%s': %s",
				password_file, strerror(errno));
		}
		size= 256;
		pw= malloc(size);

		if (fgets(pw, size, fh) == NULL)
		{
			fatal("error reading from '%s': %s",
				password_file, strerror(errno));
		}

		fclose(fh);

		size= strlen(pw);
		if (size == 0 || pw[size-1] != '\n')
		{
			memset(pw, '\0', size);
			fatal("bad password in '%s'", password_file);
		}
		pw[size-1]= '\0';

		return pw;
	}
	pw_o= getpass("Disk password: ");
	pw= strdup(pw_o);
	memset(pw_o, '\0', strlen(pw_o));
	return pw;
}

static void bin2hex_str(void *in, size_t in_len, char *out, size_t out_len)
{
	int i, v;
	uint8_T *uin;
	char *hex= "0123456789abcdef";

	if (out_len < 2*in_len+1)
		fatal("bin2hex_str: output buffer to small");

	uin= in;
	for (i= 0; i<in_len; i++)
	{
		v= uin[i];
		out[2*i]= hex[v >> 4];
		out[2*i+1]= hex[v & 0xf];
	}
	out[2*i]= '\0';
}

static int hex2val(char hex)
{
	if (hex >= '0' && hex <= '9')
		return hex-'0';
	if (hex >= 'a' && hex <= 'f')
		return hex-'a'+10;
	if (hex >= 'A' && hex <= 'F')
		return hex-'A'+10;
	fatal("hex2val: bad hex char '%c'", hex);
}

static void hex_str2bin(char *str, void *out, size_t out_len)
{
	char c1, c2;
	int i, v1, v2;
	size_t in_len;
	uint8_T *uout;

	in_len= strlen(str);
	if (in_len != 2*out_len)
		fatal("hex_str2bin: string does not match buffer");

	uout= out;
	for (i= 0; i<out_len; i++)
	{
		c1= str[2*i];
		c2= str[2*i+1];

		v1= hex2val(c1);
		v2= hex2val(c2);

		uout[i]= (v1 << 4) | v2;
	}
}

static void print_bin(void *buf, size_t size)
{
	int i;
	uint8_T *uc;

	uc= buf;
	for (i= 0; i<size; i++)
		printf("%02x", uc[i]);
}

static char *fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "mksef: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: mksef [ options ] <device>\n");
	exit(2);
}
