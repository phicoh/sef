/*
fsck_sef.c

Created:	January 2016 by Philip Homburg <philip@f-src.phicoh.com>

Check a SEF
*/

#define _POSIX_C_SOURCE 2

#include "os.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <sef/checkpoint.h>
#include <sef/dir.h>
#include <sef/super.h>

#include "buf.h"
#include "sha2.h"
#include "hmac_sha256.h"
#include "rijndael/rijndael-api.h"

static struct 
{
	sef_super_T *super;

	unsigned inode_max_indir;
	struct
	{
		unsigned count;
		unsigned slot;
	} indirs[SEF_INODE_MAX_INDIR+1];

	sef_checkpoint_T *checkpoint;

	int fd;

	uint64_T bitmap_blocks;
	uint32_T *bitmap;
	uint64_T use_count;

	uint64_T inode_count;

	uint32_T *link_counts;
	uint64_T link_count_nr;
	uint64_T link_inode_count;

	char *password;
} state;

static void load_super(void);
static void super_decrypt(uint64_T block, uint8_T *ciphertext,
	uint8_T *plaintext);
static void do_argon2(int iter, int mem, int par, int hashlen, char *salt,
	char *passwd, char *hash, double *durationp);
static void load_checkpoint(void);
static void unload_checkpoint(void);
static int checkpoint_decrypt(uint8_T *ciphertext, uint8_T *plaintext);
static void check_dir(uint64_T inode, uint64_T parent);
static void check_dir_imm(sef_inode_T *inop, uint64_T inode, uint64_T parent);
static void check_dir_normal(sef_inode_T *inop, uint64_T inode,
	uint64_T parent);
static void check_unref(void);
static void check_unref_imm(sef_inode_T *inop);
static void check_unref_normal(sef_inode_T *inop);
static void check_special_inodes(void);
static void check_alloc(void);
static void count_bitmap(buf_T *buf);
static void count_inodes(void);
static void check_parent(lbptr_T lbptr);
static void check_inode(buf_T *buf);
static void check_inode_index(buf_T *buf);
static void check_fbt(void);
static void check_fbt_index_block(lbptr_T lbptr);
static void check_fbt_block(lbptr_T lbptr);
static uint64_T count_data_blocks(uint64_T inode, sef_inode_T *inop);
static uint64_T check_data_index(buf_T *buf);
static unsigned check_bitmap_block(uint64_T block);
static void link_count_init(void);
static uint32_T link_count_read(uint64_T inode);
static void link_count_inc(uint64_T inode);
buf_T *read_block(lbptr_T lbptr, size_t size);
static void decrypt_block(sef_blkptr_T *blkptr, uint8_T *ciphertext,
	uint8_T *plaintext);
static lbptr_T get_parent(lbptr_T lbptr, unsigned *offsetp);
static void print_ptr(lbptr_T lbptr);
static char *get_password(char *password_file);
static void bin2hex_str(void *in, size_t in_len, char *out, size_t out_len);
static void hex_str2bin(char *str, void *out, size_t out_len);
#if 0
static void print_bin(void *buf, size_t size);
#endif
static char *fatal(char *fmt, ...) _NORETURN;
static void usage(void);

int main(int argc, char *argv[])
{
	int c;
	char *special;
	char *password_file;

	password_file= NULL;

	while(c= getopt(argc, argv, "?p:"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'p':
			password_file= optarg;
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

	state.password= get_password(password_file);

	state.fd= open(special, O_RDONLY);
	if (state.fd == -1)
		fatal("unable to open '%s': %s", special, strerror(errno));

	buf_init(0 /* no write callback */);

	load_super();

	memset(state.password, '\0', strlen(state.password));
	free(state.password); state.password= NULL;

	load_checkpoint();

	link_count_init();

	check_dir(SEF_ROOT_INODE, SEF_ROOT_INODE);

	check_unref();

	check_special_inodes();

	check_alloc();

	if (state.inode_count != state.checkpoint->secp_inodes)
	{
		fatal("found %llu inodes, in checkpoint %llu",
			state.inode_count, state.checkpoint->secp_inodes);
	}

	if (state.link_inode_count != state.checkpoint->secp_inodes)
	{
		fatal("found %llu inodes in directory tree, in checkpoint %llu",
			state.link_inode_count, state.checkpoint->secp_inodes);
	}

	unload_checkpoint();

	buf_flush();

	printf("OK\n");

	/* And we are done */
	return 0;
}

static void load_super(void)
{
	int i;
	unsigned block_size, level, start_reserved;
	uint64_T first_super_block, second_super_block;
	uint8_T *ciphertext, *plaintext;

	/* Where do we find the first super block? */
	start_reserved= (64*1024);

	block_size= SEF_SUPER_BLOCK_SIZE;
	first_super_block= (start_reserved-1)/block_size + 1;

	ciphertext= malloc(block_size);

	lseek(state.fd, first_super_block*block_size, SEEK_SET);

	if (read(state.fd, ciphertext, block_size) != block_size)
	{
		fatal("load_super: unable to read first super block");
	}

	plaintext= malloc(block_size);

	super_decrypt(first_super_block, ciphertext, plaintext);

	state.super= (sef_super_T *)plaintext;

	if (state.super->ses_first_super_block != first_super_block)
		fatal("load_super: first super block mismatch");

	second_super_block= state.super->ses_second_super_block;

	lseek(state.fd, second_super_block*block_size, SEEK_SET);

	if (read(state.fd, ciphertext, block_size) != block_size)
	{
		fatal("load_super: unable to read second super block");
	}

	plaintext= malloc(block_size);

	super_decrypt(second_super_block, ciphertext, plaintext);

	free(ciphertext); ciphertext= NULL;

	printf("load_super: should check consistency of super blocks\n");

	memset(plaintext, '\0', block_size);
	free(plaintext);

	state.inode_max_indir=
		state.super->ses_inode_blkptrs[SEF_INODE_BLKPTRS-1];
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
}

static void super_decrypt(uint64_T block, uint8_T *ciphertext,
	uint8_T *plaintext)
{
	unsigned block_size, offset;
	sef_super_T *superp, *super_in;
	hmac_sha256_ctx_t hm_ctx;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;
	sef_iv_T iv;
	SHA256_CTX ctx;
	sef_hash_T hash, super_key, super_sign_key, signed_hash;
	ses_argon2_params_T argon2_params;
	char salt_str[2*sizeof(super_in->ses_argon2_salt)+1];
	char hash_str[2*sizeof(hash)+1];

	block_size= SEF_SUPER_BLOCK_SIZE;
	offset= offsetof(sef_super_T, ses_iv);

	superp= (sef_super_T *)plaintext;
	super_in= (sef_super_T *)ciphertext;

	/* 'dncrypt' argon2 parameters with the * salt.
	 */

#if 0
	printf("super_decrypt: salt ");
	print_bin(super_in->ses_argon2_salt, sizeof(super_in->ses_argon2_salt));
	printf("\n");
	printf("super_decrypt: encrypted ");
	print_bin(&super_in->ses_argon2_params, sizeof(super_in->ses_argon2_params));
	printf("\n");
#endif

	/* AES CBC decrypt */
	if (rijndael_makekey(&aes_ctx, sizeof(super_in->ses_argon2_salt),
		super_in->ses_argon2_salt) != 0)
	{
		fatal("rijndael_makekey failed");
	}
	memset(&iv, '\0', sizeof(iv));
	if (rijndael_cbc_decrypt(&aes_ctx, &super_in->ses_argon2_params,
		&argon2_params, sizeof(super_in->ses_argon2_params),
		&iv) != sizeof(argon2_params))
	{
		fatal("rijndael_cbc_decrypt failed");
	}

	/* Convert salt to hex string */
	bin2hex_str(super_in->ses_argon2_salt, 
		sizeof(super_in->ses_argon2_salt),
		salt_str, sizeof(salt_str));

	/* Call argon2 */
	do_argon2(argon2_params.sap_iterations, argon2_params.sap_mem,
		argon2_params.sap_parallelism, sizeof(super_key),
		salt_str, state.password, hash_str, NULL);

	/* Decode hash */
	hex_str2bin(hash_str, &super_key, sizeof(super_key));

	memset(hash_str, '\0', sizeof(hash_str));

	/* Copy signed hash */
	superp->ses_signed_hash= super_in->ses_signed_hash;

	/* Create AES key */
	hmac_sha256_init(&hm_ctx, &super_key, 
		sizeof(super_key));
	hmac_sha256_update(&hm_ctx,
		&superp->ses_signed_hash,
		sizeof(superp->ses_signed_hash));
	hmac_sha256_finish(&hm_ctx, aes_key);
	hmac_sha256_cleanup(&hm_ctx);

	/* AES decrypt */
	if (rijndael_makekey(&aes_ctx, sizeof(aes_key), aes_key) != 0)
		fatal("rijndael_makekey failed");
	memset(aes_key, '\0', sizeof(aes_key));
	
	memset(&iv, '\0', sizeof(iv));
	if (rijndael_cbc_decrypt(&aes_ctx, ciphertext+offset,
		plaintext+offset, block_size-offset,
		&iv) != block_size-offset)
	{
		fatal("rijndael_cbc_decrypt failed");
	}

	memset(&aes_ctx, '\0', sizeof(aes_ctx));

	/* Hash the result */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, plaintext+offset, block_size-offset);
	SHA256_Final((unsigned char *)&hash, &ctx);

	/* Compute super_sign_key */
	hmac_sha256_init(&hm_ctx, (unsigned char *)&super_key, 
			sizeof(super_key));
	hmac_sha256_update(&hm_ctx, "S", 1);
	hmac_sha256_finish(&hm_ctx,
		(unsigned char *)&super_sign_key);
	hmac_sha256_cleanup(&hm_ctx);

	/* Sign hash */
	hmac_sha256_init(&hm_ctx, (unsigned char *)&super_sign_key, 
		sizeof(super_sign_key));
	hmac_sha256_update(&hm_ctx, &hash, sizeof(hash));
	hmac_sha256_finish(&hm_ctx,
		(unsigned char *)&signed_hash);
	hmac_sha256_cleanup(&hm_ctx);

	memset(&super_key, '\0', sizeof(super_key));
	memset(&super_sign_key, '\0', sizeof(super_sign_key));

	/* Compare signed hash */
	if (memcmp(&superp->ses_signed_hash, &signed_hash,
		sizeof(signed_hash)) != 0)
	{
		fatal("cannot decrypt super block at %lld",
			block);
	}

	/* All okay */
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

static void load_checkpoint(void)
{
	unsigned block_size;
	uint64_T block;
	uint8_T *ciphertext, *plaintext1, *plaintext2;
	buf_T *buf;
	sef_checkpoint_T *checkpoint;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	block= state.super->ses_first_checkpoint_block;

	ciphertext= malloc(block_size);

	lseek(state.fd, block*block_size, SEEK_SET);

	if (read(state.fd, ciphertext, block_size) != block_size)
	{
		fatal("load_checkpoint: unable to read first checkpoint block");
	}

	plaintext1= malloc(block_size);

	if (checkpoint_decrypt(ciphertext, plaintext1))
	{
		/* Good checkpoint. Check block number and secp_seqnr */
		checkpoint= (sef_checkpoint_T *)plaintext1;
		printf("load_checkpoint: checkpoint #1: block %llu, seq %llu\n",
			(unsigned long long)checkpoint->secp_block,
			(unsigned long long)checkpoint->secp_seqnr);
		if (checkpoint->secp_block != block)
		{
			fatal(
		"load_checkpoint: bad block number in first checkpoint block");
		}
		if ((checkpoint->secp_seqnr & 1) != 0)
		{
			fatal(
	"load_checkpoint: bad sequence number in first checkpoint block");
		}
	}
	else
	{
		/* Bad checkpoint. Wipe and free plaintext. */
		memset(plaintext1, '\0', block_size);
		free(plaintext1);

		plaintext1= NULL;
	}

	block= state.super->ses_second_checkpoint_block;

	lseek(state.fd, block*block_size, SEEK_SET);
	if (read(state.fd, ciphertext, block_size) != block_size)
	{
		fatal("load_checkpoint: unable to read second super block");
	}

	plaintext2= malloc(block_size);

	if (checkpoint_decrypt(ciphertext, plaintext2))
	{
		/* Good checkpoint. Check block number and secp_seqnr */
		checkpoint= (sef_checkpoint_T *)plaintext2;
		printf("load_checkpoint: checkpoint #2: block %llu, seq %llu\n",
			(unsigned long long)checkpoint->secp_block,
			(unsigned long long)checkpoint->secp_seqnr);
		if (checkpoint->secp_block != block)
		{
			fatal(
		"load_checkpoint: bad block number in second checkpoint block");
		}
		if ((checkpoint->secp_seqnr & 1) != 1)
		{
			fatal(
	"load_checkpoint: bad sequence number in second checkpoint block");
		}
	}
	else
	{
		/* Bad checkpoint. Wipe and free plaintext. */
		memset(plaintext2, '\0', block_size);
		free(plaintext2);

		plaintext2= NULL;
	}

	free(ciphertext); ciphertext= NULL;

	if (!plaintext1 && !plaintext2)
		fatal("load_checkpoint: no valid checkpoint block found");

	/* We got at least one checkpoint block. Get buffer. */
	lbptr= lbuf_mkptr(LT_CHECKPOINT, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, SEF_CHECKPOINT_SIZE);

	if (plaintext2 == NULL)
	{
		assert(plaintext1);
		memcpy(buf_data_ptr(buf), plaintext1, SEF_CHECKPOINT_SIZE);
	}
	else if (plaintext1 == NULL)
	{
		assert(plaintext2);
		memcpy(buf_data_ptr(buf), plaintext2, SEF_CHECKPOINT_SIZE);
	}
	else if (((sef_checkpoint_T *)plaintext1)->secp_seqnr >
		((sef_checkpoint_T *)plaintext2)->secp_seqnr)
	{
		memcpy(buf_data_ptr(buf), plaintext1, SEF_CHECKPOINT_SIZE);
	}
	else
	{
		assert((((sef_checkpoint_T *)plaintext2)->secp_seqnr >
			((sef_checkpoint_T *)plaintext1)->secp_seqnr));
		memcpy(buf_data_ptr(buf), plaintext2, SEF_CHECKPOINT_SIZE);
	}

	buf_setvalid(buf);
	buf_lock(buf);
	buf_release(buf);	/* Only keep the lock */

	state.checkpoint= buf_data_ptr(buf);

#if 0
	{ int i;
	printf("load_checkpoint: ");
	for(i= 0; i<SEF_CHECKPOINT_SIZE; i++)
		printf("%02x", ((uint8_T *)state.checkpoint)[i]);
	printf("\n");
	}
#endif

	/* Cleanup */
	if (plaintext1)
	{
		memset(plaintext1, '\0', block_size);
		free(plaintext1);
		plaintext1= NULL;
	}
	if (plaintext2)
	{
		memset(plaintext2, '\0', block_size);
		free(plaintext2);
		plaintext2= NULL;
	}
}

static void unload_checkpoint(void)
{
	buf_T *buf;
	lbptr_T lbptr;

	lbptr= lbuf_mkptr(LT_CHECKPOINT, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, SEF_CHECKPOINT_SIZE);

	/* Now we got two reference. We just got a read reference and
	 * we already had a lock.
	 */
	state.checkpoint= NULL;

	buf_release(buf);
	buf_unlock(buf);
	buf= NULL;
}

static int checkpoint_decrypt(uint8_T *ciphertext, uint8_T *plaintext)
{
	unsigned block_size, offset;
	sef_checkpoint_T *checkpoint;
	hmac_sha256_ctx_t hm_ctx;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;
	sef_iv_T iv;
	SHA256_CTX ctx;
	sef_hash_T hash, disk_sign_key, signed_hash;

	block_size= state.super->ses_block_size;
	offset= offsetof(sef_checkpoint_T, secp_iv);

	checkpoint= (sef_checkpoint_T *)plaintext;

	/* Copy signed hash */
	checkpoint->secp_signed_hash= *(sef_hash_T *)ciphertext;

	/* Create AES key */
	hmac_sha256_init(&hm_ctx, &state.super->ses_disk_key, 
		sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx,
		&checkpoint->secp_signed_hash,
		sizeof(checkpoint->secp_signed_hash));
	hmac_sha256_finish(&hm_ctx, aes_key);
	hmac_sha256_cleanup(&hm_ctx);

	/* AES decrypt */
	if (rijndael_makekey(&aes_ctx, sizeof(aes_key), aes_key) != 0)
		fatal("rijndael_makekey failed");
	memset(aes_key, '\0', sizeof(aes_key));
	
	memset(&iv, '\0', sizeof(iv));
	if (rijndael_cbc_decrypt(&aes_ctx, ciphertext+offset,
		plaintext+offset, block_size-offset,
		&iv) != block_size-offset)
	{
		fatal("rijndael_cbc_decrypt failed");
	}

	memset(&aes_ctx, '\0', sizeof(aes_ctx));

	/* Hash the result */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, plaintext+offset, block_size-offset);
	SHA256_Final((unsigned char *)&hash, &ctx);

	/* Compute super_sign_key */
	hmac_sha256_init(&hm_ctx, (unsigned char *)&state.super->ses_disk_key, 
			sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx, "S", 1);
	hmac_sha256_finish(&hm_ctx,
		(unsigned char *)&disk_sign_key);
	hmac_sha256_cleanup(&hm_ctx);

	/* Sign hash */
	hmac_sha256_init(&hm_ctx, (unsigned char *)&disk_sign_key, 
		sizeof(disk_sign_key));
	hmac_sha256_update(&hm_ctx, &hash, sizeof(hash));
	hmac_sha256_finish(&hm_ctx,
		(unsigned char *)&signed_hash);
	hmac_sha256_cleanup(&hm_ctx);

	memset(&disk_sign_key, '\0', sizeof(disk_sign_key));

	/* Compare signed hash */
	if (memcmp(&checkpoint->secp_signed_hash, &signed_hash,
		sizeof(signed_hash)) != 0)
	{
		/* Bad checkpoint block, but this possible. So just return
		 * false.
		 */
		return 0;
	}

	/* All okay */
	return 1;
}

static void check_dir(uint64_T inode, uint64_T parent)
{
	unsigned block_size, inodes_per_block, ind, expected_link_count;
	uint64_T block;
	lbptr_T lbptr;
	buf_T *buf;
	sef_inode_T *inop;

	expected_link_count= inode == SEF_ROOT_INODE ? 0 : 1;
	if (link_count_read(inode) != expected_link_count)
	{
		fatal("check_dir: directory %llu has been visited already",
			inode);
	}

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	block= inode/inodes_per_block;
	ind= inode % inodes_per_block;

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];

	if ((inop->sei_mode & SIM_TYPE) != SIM_DIRECTORY)
		fatal("check_dir: inode %llu is not a directory", inode);

	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		check_dir_imm(inop, inode, parent);
	}
	else
	{
		check_dir_normal(inop, inode, parent);
	}

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;
}

static void check_dir_imm(sef_inode_T *inop, uint64_T inode, uint64_T parent)
{
	int i;
	unsigned offset, len, block_size, inodes_per_block, ind;
	uint64_T expected, child_inode, block;
	sef_dirent_T *dirp;
	buf_T *buf;
	sef_inode_T *child_inop;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	if (inop->sei_size > sizeof(inop->sei_blkptrs))
		fatal("check_dir_imm: bad size in inode %llu", inode);

	offset= 0;
	for (i= 0; offset < inop->sei_size; offset += len, i++)
	{
		dirp= (sef_dirent_T *)(((uint8_T *)inop->sei_blkptrs)+offset);
		len= 8*(2+dirp->sed_extra);
		if (offset+len > inop->sei_size)
		{
			fatal(
	"check_dir_imm: bad length in entry %d of inode %llu: %u + %u > %llu",
				i, inode, offset, len, inop->sei_size);
		}

		/* Check for nul byte */
		if (memchr(dirp->sed_name, '\0',
			len-offsetof(sef_dirent_T, sed_name)) == NULL)
		{
			fatal(
		"check_dir_imm: unterminated string in entry %d of inode %llu",
				i, inode);
		}

		printf(
		"check_dir_imm: offset %d, i %d, inode %lld, name '%s'\n",
			offset, i, (unsigned long long)dirp->sed_inode,
			dirp->sed_name);


		if (i == 0 || i == 1)
		{
			/* "." or ".." */
			if (strcmp((char *)dirp->sed_name,
				i == 0 ? "." : "..") != 0)
			{
				fatal(
		"check_dir_imm: bad name '%s' in entry %d of inode %llu",
					dirp->sed_name, i, inode);
			}
			expected= (i == 0 ? inode : parent);
			if (dirp->sed_inode != expected)
			{
				fatal(
		"check_dir_imm: bad inode in entry %d of inode %llu, found %llu, expected %llu",
					i, inode, dirp->sed_inode, expected);
			}
			link_count_inc(dirp->sed_inode);
			continue;
		}

		child_inode= dirp->sed_inode;

		block= child_inode/inodes_per_block;
		ind= child_inode % inodes_per_block;

		lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		child_inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];

		/* First increment the link count, then recurse for
		 * consistency (check that the directory hasn't been visited
		 * yet).
		 */
		link_count_inc(dirp->sed_inode);

		if ((child_inop->sei_mode & SIM_TYPE) == SIM_DIRECTORY)
			check_dir(dirp->sed_inode, inode);

		child_inop= NULL;
		buf_unlock(buf);
	}
	if (i < 2)
	{
		fatal("check_dir_imm: not enough entries in inode %llu",
			inode);
	}
}

static void check_dir_normal(sef_inode_T *inop, uint64_T inode, uint64_T parent)
{
	int i;
	unsigned offset, len, block_size, inodes_per_block, ind, start, end;
	uint64_T expected, child_inode, block, ino_block;
	uint8_T *cp;
	sef_dirent_T *dirp;
	buf_T *buf, *ino_buf;
	sef_inode_T *child_inop;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	i= 0;
	for (block= 0; block*block_size < inop->sei_size; block++)
	{
		start= 0;
		if (block == 0)
			start= sizeof(sef_dir_sum_T);
		end= block_size;
		if (block*block_size+end > inop->sei_size)
		{
			end= inop->sei_size - block*block_size;
			assert(end > start && end < block_size);
		}

		lbptr= lbuf_mkptr(LT_DATA, 0, inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		cp= buf_data_ptr(buf);

		for (offset= start; offset < end; offset += len, i++)
		{
			dirp= (sef_dirent_T *)(cp+offset);

			printf(
"check_dir_normal: block %lld, offset %d, i %d, inode %lld, name '%s'\n",
				(unsigned long long)block, offset, i,
				(unsigned long long)dirp->sed_inode,
				dirp->sed_name);

			len= 8*(2+dirp->sed_extra);
			if (offset+len > end)
			{
				fatal(
"check_dir_normal: bad length in entry %d of inode %llu: %u + %u > %llu",
				i, inode, offset, len, end);
			}

			/* Check for nul byte */
			if (memchr(dirp->sed_name, '\0',
				len-offsetof(sef_dirent_T, sed_name)) == NULL)
			{
				fatal(
	"check_dir_normal: unterminated string in entry %d of inode %llu",
					i, inode);
			}

			if (i == 0 || i == 1)
			{
				/* "." or ".." */
				if (strcmp((char *)dirp->sed_name,
					i == 0 ? "." : "..") != 0)
				{
					fatal(
		"check_dir_normal: bad name '%s' in entry %d of inode %llu",
						dirp->sed_name, i, inode);
				}
				expected= (i == 0 ? inode : parent);
				if (dirp->sed_inode != expected)
				{
					fatal(
			"check_dir_imm: bad inode in entry %d of inode %llu, found %llu, expected %llu",
						i, inode, dirp->sed_inode, expected);
				}
				link_count_inc(dirp->sed_inode);
				continue;
			}

			child_inode= dirp->sed_inode;

			if (child_inode == 0)
				continue;	/* Empty entry */

			ino_block= child_inode/inodes_per_block;
			ind= child_inode % inodes_per_block;

			lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, ino_block);
			ino_buf= read_block(lbptr, block_size);
			buf_lock(ino_buf);
			buf_release(ino_buf);
			child_inop=
				&((sef_inode_T *)buf_data_ptr(ino_buf))[ind];

			/* First increment the link count, then recurse for
			 * consistency (check that the directory hasn't been
			 * visited yet).
			 */
			link_count_inc(dirp->sed_inode);

			if ((child_inop->sei_mode & SIM_TYPE) == SIM_DIRECTORY)
				check_dir(dirp->sed_inode, inode);

			child_inop= NULL;
			buf_unlock(ino_buf);
			ino_buf= NULL;
		}

		cp= NULL;
		buf_unlock(buf);
		buf= NULL;
	}
	if (i < 2)
	{
		fatal("check_dir_imm: not enough entries in inode %llu",
			inode);
	}
}

static void check_unref(void)
{
	unsigned block_size, inodes_per_block, ind;
	uint64_T block, inode;
	lbptr_T lbptr;
	buf_T *buf;
	sef_inode_T *inop;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	inode= SEF_UNREF_INODE;
	block= inode/inodes_per_block;
	ind= inode % inodes_per_block;

	link_count_inc(inode);

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];

	if ((inop->sei_mode & SIM_TYPE) != SIM_UNREF)
		fatal("check_dir: inode %llu is not type unref", inode);

	if (inop->sei_flags & SIF_IMMEDIATE)
		check_unref_imm(inop);
	else
		check_unref_normal(inop);

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;
}

static void check_unref_imm(sef_inode_T *inop)
{
	unsigned offset, block_size, inodes_per_block, ind;
	uint64_T child_inode, block;
	buf_T *buf;
	sef_inode_T *child_inop;
	uint64_T *p;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	if (inop->sei_size > sizeof(inop->sei_blkptrs))
		fatal("check_unref_imm: bad size %llu", inop->sei_size);

	for (offset= 0; offset < inop->sei_size; offset += sizeof(*p))
	{
		p= (uint64_T *)(((uint8_T *)inop->sei_blkptrs)+offset);

		child_inode= *p;

		printf(
		"check_unref_imm: offset %d, inode %lld\n",
			offset, (unsigned long long)child_inode);

		block= child_inode/inodes_per_block;
		ind= child_inode % inodes_per_block;

		lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		child_inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];

		if (child_inop->sei_nlink != 1)
		{
			/* All inodes here have link count 1. */
			fatal("unref inode %llu has wrong link count %d",
				child_inop->sei_nlink);
		}

		link_count_inc(child_inode);

		child_inop= NULL;
		buf_unlock(buf);
	}
}

static void check_unref_normal(sef_inode_T *inop)
{
	unsigned offset, block_size, inodes_per_block, ind, end;
	uint64_T child_inode, block, ino_block;
	uint8_T *cp;
	uint64_T *p;
	buf_T *buf, *ino_buf;
	sef_inode_T *child_inop;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	for (block= 0; block*block_size < inop->sei_size; block++)
	{
		end= block_size;
		if (block*block_size+end > inop->sei_size)
		{
			end= inop->sei_size - block*block_size;
			assert(end > 0 && end < block_size);
		}

		lbptr= lbuf_mkptr(LT_DATA, 0, SEF_UNREF_INODE, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		cp= buf_data_ptr(buf);

		for (offset= 0; offset < end; offset += sizeof(*p))
		{
			p= (uint64_T *)(cp+offset);

			child_inode= *p;

			printf(
		"check_nref_normal: block %lld, offset %d, inode %lld\n",
				(unsigned long long)block, offset,
				(unsigned long long)child_inode);

			if (child_inode == 0)
				continue;	/* Empty entry */

			ino_block= child_inode/inodes_per_block;
			ind= child_inode % inodes_per_block;

			lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, ino_block);
			ino_buf= read_block(lbptr, block_size);
			buf_lock(ino_buf);
			buf_release(ino_buf);
			child_inop=
				&((sef_inode_T *)buf_data_ptr(ino_buf))[ind];

			if (child_inop->sei_nlink != 1)
			{
				/* All inodes here have link count 1. */
				fatal(
				"unref inode %llu has wrong link count %d",
					child_inop->sei_nlink);
			}

			link_count_inc(child_inode);

			child_inop= NULL;
			buf_unlock(ino_buf);
			ino_buf= NULL;
		}

		cp= NULL;
		buf_unlock(buf);
		buf= NULL;
	}
}

static void check_special_inodes(void)
{
	uint64_T ino, bnr;
	unsigned ind, inodes_per_block, block_size;
	buf_T *buf;
	sef_inode_T *inop;
	lbptr_T lbptr;

	/* Check the special inodes before the root inode. */

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	for (ino= 0; ino<SEF_UNREF_INODE; ino++)
	{
		bnr= ino/inodes_per_block;
		ind= ino%inodes_per_block;

		lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, bnr);
		buf= read_block(lbptr, block_size);

		/* Convert to a locked reference. */
		buf_lock(buf);
		buf_release(buf);

		inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];

		if ((inop->sei_mode & SIM_TYPE) != SIM_RESERVED)
		{
			fatal(
			"check_special_inodes: inode %llu has wrong mode 0x%x",
				ino, inop->sei_mode);
		}
		if (inop->sei_nlink == 0)
		{
			fatal(
		"check_special_inodes: inode %d has number of links %d",
				ino, inop->sei_nlink);
		}

		link_count_inc(ino);

		buf_unlock(buf);
	}
}

static void check_alloc(void)
{
	int i;
	unsigned block_size, bits_per_block, bits_per_word;
	uint32_T bit;
	uint64_T block, ind, errors;

	/* For now, keep the entire bitmap in memory. */

	block_size= state.super->ses_block_size;

	bits_per_block= block_size * 8;
	bits_per_word= sizeof(state.bitmap[0]) * 8;

	/* Number of bitmap blocks. */
	state.bitmap_blocks=
		state.super->ses_last_data_block/bits_per_block + 1;

	state.bitmap= malloc(state.bitmap_blocks*block_size);
	memset(state.bitmap, '\0', state.bitmap_blocks*block_size);
	state.use_count= 0;

	/* Mark the blocks outside the filesystem */
	for (block= 0; block < state.super->ses_first_data_block; block++)
	{
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal("check_alloc: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}
	for (block= state.super->ses_last_data_block+1;
		block < state.bitmap_blocks*bits_per_block; block++)
	{
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal("check_alloc: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}

	/* Mark checkpoint blocks */
	for (i= 0; i<2; i++)
	{
		block= i == 0 ? state.super->ses_first_checkpoint_block :
			state.super->ses_second_checkpoint_block;
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal("check_alloc: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}

	count_bitmap(NULL);

	count_inodes();

	check_fbt();

	/* Now check bitmap against filesystem bitmap blocks */
	errors= 0;
	for (block= 0; block<state.bitmap_blocks; block++)
		errors += check_bitmap_block(block);

	if (errors)
		fatal("check_alloc: %d bitmap errors", errors);

	if (state.use_count + state.checkpoint->secp_free_blocks !=
		state.bitmap_blocks * bits_per_block)
	{
		fatal("wrong number of free_blocks in checkpoint");
	}
}

static void count_bitmap(buf_T *buf)
{
	int i, leaf;
	unsigned ptrs_per_block, block_size, bits_per_word;
	sef_blkptr_T *blkptrs;
	buf_T *c_buf;
	uint32_T bit;
	uint64_T block, ind, offset;
	lbptr_T lbptr, c_lbptr;

	/* This function takes ownership of one read reference to buf */

	bits_per_word= sizeof(state.bitmap[0]) * 8;
	block_size= state.super->ses_block_size;
	ptrs_per_block= block_size / sizeof(*blkptrs);

	if (buf == NULL)
	{
		/* Start at the top */
		lbptr= lbuf_mkptr(LT_BM_INDEX, 0, 0,
			state.super->ses_bm_ind_levels, 0);
		buf= read_block(lbptr, block_size);

		/* Count this block */
		block= state.checkpoint->secp_bm_index.sebp_block;
		assert(block != 0);
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"count_bitmap: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}
	else
		lbptr= buf_get_ptr(buf);

	assert(lbptr.lbp_type == LT_BM_INDEX);
	assert(lbptr.lbp_level >= 1);

	leaf= (lbptr.lbp_level == 1);

	buf_lock(buf);
	blkptrs= (sef_blkptr_T *)buf_data_ptr(buf);
	for (i= 0; i< ptrs_per_block; i++)
	{
		block= blkptrs[i].sebp_block;
		if (block == 0)
		{
			/* Nothing here */
			continue;
		}
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"count_bitmap: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;

		if (leaf)
		{
			/* Nothing more to do */
		}
		else
		{
			offset= lbptr.lbp_offset*ptrs_per_block + i;
			c_lbptr= lbuf_mkptr(LT_BM_INDEX,
			    lbptr.lbp_space, lbptr.lbp_inode,
			    lbptr.lbp_level-1, offset);

			c_buf= read_block(c_lbptr, block_size);
			count_bitmap(c_buf);
			c_buf= NULL;
		}
	}
	buf_unlock(buf);

	/* Release block here */
	buf_release(buf);
}

static void count_inodes(void)
{
	int i, j;
	unsigned block_size, bits_per_word, level, type;
	uint32_T bit;
	uint64_T block, ind, offset;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	bits_per_word= sizeof(state.bitmap[0]) * 8;

	/* Try each of the pointers an inode block or an index block */
	for (i= 0; i<SEF_INODE_BLKPTRS; i++)
	{
		block= state.checkpoint->secp_blkptrs[i].sebp_block;
		if (block == 0)
			continue;	/* Nothing here */

		/* Count this block */
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"count_inodes: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;

		/* Convert to a lbptr */
		level= state.super->ses_inode_blkptrs[i];
		type= level == 0 ? LT_INODE : LT_INODE_INDEX;
		offset= 0;
		for (j= 0; j<i; j++)
		{
			/* Count the number of block points at the 
			 * same level before this one.
			 */
			if (state.super->ses_inode_blkptrs[j] == level)
				offset++;
		}
		lbptr= lbuf_mkptr(type, 0, 0, level, offset);

		/* There is something special about block pointers in the
		 * checkpoint block: if there is a parent block, it is
		 * not allowed to store a pointer as well.
		 */
		check_parent(lbptr);

		buf= read_block(lbptr, block_size);

		/* Callee will free the buf */
		if (level == 0)
			check_inode(buf);
		else
			check_inode_index(buf);
		buf= NULL;
	}
}

static void check_parent(lbptr_T lbptr)
{
	int type;
	unsigned block_size, ptrs_per_block;
	sef_blkptr_T *blkptrp;
	buf_T *buf;
	lbptr_T p_lbptr;

	block_size= state.super->ses_block_size;
	ptrs_per_block= block_size / sizeof(*blkptrp);

	/* Compute the parent directly. */
	switch(lbptr.lbp_type)
	{
	case LT_INODE:
	case LT_INODE_INDEX:
		type= LT_INODE_INDEX;
		break;
	case LT_DATA:
	case LT_DATA_INDEX:
		type= LT_DATA_INDEX;
		break;
	default: fatal("check_parent: bad type %d", lbptr.lbp_type);
	}

	p_lbptr= lbuf_mkptr(type,
		lbptr.lbp_space, lbptr.lbp_inode,
		lbptr.lbp_level+1, lbptr.lbp_offset / ptrs_per_block);
	if (p_lbptr.lbp_level > state.inode_max_indir)
	{
		/* This is above the top level, no need to check anything */
		return;
	}

	buf= read_block(p_lbptr, block_size);
	blkptrp= (sef_blkptr_T *)buf_data_ptr(buf);
	if (blkptrp[lbptr.lbp_offset % ptrs_per_block].sebp_block != 0)
		fatal("check_parent: found block pointer in parent");

	blkptrp= NULL;
	buf_release(buf);
	buf= NULL;
}

static void check_inode(buf_T *buf)
{
	unsigned block_size, inodes_per_block, ind;
	uint64_T inode, count;
	sef_inode_T *inop;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	lbptr= buf_get_ptr(buf);

	buf_lock(buf);
	for (ind= 0; ind<inodes_per_block; ind++)
	{
		inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];
		inode= lbptr.lbp_offset*inodes_per_block + ind;

		printf(
		"check_inode: inode %llu, size %llu, nlink %u, flags 0x%x\n",
			(unsigned long long)inode,
			(unsigned long long)inop->sei_size,
			(unsigned)inop->sei_nlink,
			(unsigned)inop->sei_flags);

		if (inop->sei_nlink)
			state.inode_count++;
		if (inop->sei_nlink != link_count_read(inode))
		{
			fatal(
"check_inode: wrong number of links in inode %llu, found %u, in inode %u\n",
				inode, link_count_read(inode),
				inop->sei_nlink);
		}
		if (!(inop->sei_flags & SIF_IMMEDIATE))
			count= count_data_blocks(inode, inop);
		else
			count= 0;
		if (count != inop->sei_blocks)
		{
			fatal(
"check_inode: wrong number of blocks in inode %llu, found %llu, in inode %llu",
				inode, count, inop->sei_blocks);
		}

	}
	buf_unlock(buf);
	buf_release(buf);
}

static void check_inode_index(buf_T *buf)
{
	int i, leaf;
	unsigned ptrs_per_block, block_size, bits_per_word;
	sef_blkptr_T *blkptrs;
	buf_T *c_buf;
	uint32_T bit;
	uint64_T block, ind, offset;
	lbptr_T lbptr, c_lbptr;

	/* This function takes ownership of one read reference to buf */

	bits_per_word= sizeof(state.bitmap[0]) * 8;
	block_size= state.super->ses_block_size;
	ptrs_per_block= block_size / sizeof(*blkptrs);

	lbptr= buf_get_ptr(buf);

	assert(lbptr.lbp_type == LT_INODE_INDEX);
	assert(lbptr.lbp_level >= 1);

	leaf= (lbptr.lbp_level == 1);

	buf_lock(buf);
	blkptrs= (sef_blkptr_T *)buf_data_ptr(buf);
	for (i= 0; i< ptrs_per_block; i++)
	{
		block= blkptrs[i].sebp_block;
		if (block == 0)
		{
			/* Nothing here */
			continue;
		}
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"check_inode_index: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;

		offset= lbptr.lbp_offset*ptrs_per_block + i;
		c_lbptr= lbuf_mkptr(leaf ? LT_INODE : LT_INODE_INDEX,
		    lbptr.lbp_space, lbptr.lbp_inode,
		    lbptr.lbp_level-1, offset);

		c_buf= read_block(c_lbptr, block_size);

		/* Callee will free the buf */
		if (leaf)
			check_inode(c_buf);
		else
			check_inode_index(c_buf);
		c_buf= NULL;
	}
	buf_unlock(buf);

	/* Release block here */
	buf_release(buf);
}

static void check_fbt(void)
{
	int i;
	unsigned ind, bits_per_word;
	uint32_T bit;
	uint64_T block;
	lbptr_T lbptr;

	bits_per_word= sizeof(state.bitmap[0]) * 8;

	for (i= 0; i<SEF_BM_IND_MAX; i++)
	{
		block= state.checkpoint->secp_fbt[i].sebp_block;
		if (block == 0)
			continue;

		if (i == 0)
		{
			lbptr= lbuf_mkptr(LT_FBT, 0, 0, 0, 0);
			check_fbt_block(lbptr);
		}
		else
		{
			if (i >= state.super->ses_bm_ind_levels)
				fatal("check_fbt: unexpected fbt%d", i);
			lbptr= lbuf_mkptr(LT_FBT_INDEX, 0, i, i, 0);
			check_fbt_index_block(lbptr);
		}

		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"check_fbt: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}
}

static void check_fbt_index_block(lbptr_T lbptr)
{
	int i;
	unsigned ptrs_per_block, block_size, bits_per_word, ind;
	uint32_T bit;
	uint64_T block;
	sef_blkptr_T *p;
	buf_T *buf;
	lbptr_T n_lbptr;

	block_size= state.super->ses_block_size;
	bits_per_word= sizeof(state.bitmap[0]) * 8;

	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);

	p= (sef_blkptr_T *)buf_data_ptr(buf);
	ptrs_per_block= block_size / sizeof(*p);

	for (i= 0; i<ptrs_per_block; i++)
	{
		block= p[i].sebp_block;
		if (block == 0)
			continue;

		if (lbptr.lbp_level > 1)
		{
			n_lbptr= lbuf_mkptr(LT_FBT_INDEX, lbptr.lbp_space,
				lbptr.lbp_inode, lbptr.lbp_level-1, 
				lbptr.lbp_offset * ptrs_per_block + i);
			check_fbt_index_block(n_lbptr);
		}
		else
		{
			n_lbptr= lbuf_mkptr(LT_FBT, lbptr.lbp_space,
				lbptr.lbp_inode, lbptr.lbp_level-1, 
				lbptr.lbp_offset * ptrs_per_block + i);
			check_fbt_block(n_lbptr);
		}

		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"check_fbt_block: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}

	p= NULL;
	buf_unlock(buf);
	buf= NULL;
}

static void check_fbt_block(lbptr_T lbptr)
{
	int i;
	unsigned n, block_size, bits_per_word, ind;
	uint32_T bit;
	uint64_T block;
	uint64_T *p;
	buf_T *buf;

	block_size= state.super->ses_block_size;
	bits_per_word= sizeof(state.bitmap[0]) * 8;

	buf= read_block(lbptr, block_size);

	p= (uint64_T *)buf_data_ptr(buf);
	n= block_size / sizeof(*p);

	for (i= 0; i<n; i++)
	{
		block= p[i];
		if (block == 0)
			continue;

		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"check_fbt_block: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;
	}

	p= NULL;
	buf_release(buf);
	buf= NULL;
}

static uint64_T count_data_blocks(uint64_T inode, sef_inode_T *inop)
{
	int i, j;
	unsigned block_size, bits_per_word, level, type;
	uint32_T bit;
	uint64_T block, ind, offset, count;
	buf_T *buf;
	lbptr_T lbptr;

	count= 0;

	block_size= state.super->ses_block_size;
	bits_per_word= sizeof(state.bitmap[0]) * 8;

	/* Try each of the pointers, a data block or a data index block */
	for (i= 0; i<SEF_INODE_BLKPTRS; i++)
	{
		block= inop->sei_blkptrs[i].sebp_block;
		if (block == 0)
			continue;	/* Nothing here */

		if (block < state.super->ses_first_data_block ||
			block > state.super->ses_last_data_block)
		{
			fatal(
			"count_data_blocks: bad block %llu in inode %llu",
				block, inode);
		}

		/* Count this block */
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"count_data_blocks: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;

		count++;

		/* Convert to a lbptr */
		level= state.super->ses_inode_blkptrs[i];
		type= level == 0 ? LT_DATA : LT_DATA_INDEX;
		offset= 0;
		for (j= 0; j<i; j++)
		{
			/* Count the number of block pointers at the 
			 * same level before this one.
			 */
			if (state.super->ses_inode_blkptrs[j] == level)
				offset++;
		}
		lbptr= lbuf_mkptr(type, 0, inode, level, offset);

		/* There is something special about block pointers in the
		 * inode: if there is a parent block, it is
		 * not allowed to store a pointer as well.
		 */
		check_parent(lbptr);


		if (level == 0)
		{
			/* Actually reading the block should only happen
			 * when scrubbing.
			 */
			buf= read_block(lbptr, block_size);
			buf_release(buf);
			buf= NULL;
		}
		else
		{
			/* Callee will free the buf */
			buf= read_block(lbptr, block_size);
			count += check_data_index(buf);
			buf= NULL;
		}
	}

	return count;
}

static uint64_T check_data_index(buf_T *buf)
{
	int i, leaf;
	unsigned ptrs_per_block, block_size, bits_per_word;
	sef_blkptr_T *blkptrs;
	buf_T *c_buf;
	uint32_T bit;
	uint64_T block, ind, offset, count;
	lbptr_T lbptr, c_lbptr;

	count= 0;

	/* This function takes ownership of one read reference to buf */

	bits_per_word= sizeof(state.bitmap[0]) * 8;
	block_size= state.super->ses_block_size;
	ptrs_per_block= block_size / sizeof(*blkptrs);

	lbptr= buf_get_ptr(buf);

	assert(lbptr.lbp_type == LT_DATA_INDEX);
	assert(lbptr.lbp_level >= 1);

	leaf= (lbptr.lbp_level == 1);

	buf_lock(buf);
	blkptrs= (sef_blkptr_T *)buf_data_ptr(buf);
	for (i= 0; i< ptrs_per_block; i++)
	{
		block= blkptrs[i].sebp_block;
		if (block == 0)
		{
			/* Nothing here */
			continue;
		}
		ind= block/bits_per_word;
		bit= (1U << (block % bits_per_word));
		if (state.bitmap[ind] & bit)
			fatal(
			"check_data_index: duplicate block %llu", block);
		state.bitmap[ind] |= bit;
		state.use_count++;

		count++;

		offset= lbptr.lbp_offset*ptrs_per_block + i;
		c_lbptr= lbuf_mkptr(leaf ? LT_DATA : LT_DATA_INDEX,
		    lbptr.lbp_space, lbptr.lbp_inode,
		    lbptr.lbp_level-1, offset);


		if (leaf)
		{
			/* Block should be read only when scrubbing */
			c_buf= read_block(c_lbptr, block_size);
			buf_release(c_buf);
			c_buf= NULL;
		}
		else
		{
			/* Callee will free the buf */
			c_buf= read_block(c_lbptr, block_size);
			count += check_data_index(c_buf);
			c_buf= NULL;
		}
	}
	buf_unlock(buf);

	/* Release block here */
	buf_release(buf);

	return count;
}


static unsigned check_bitmap_block(uint64_T block)
{
	int i, j;
	unsigned bits_per_word, words_per_block, errors;
	uint32_T w, w1, w2;
	uint64_T offset;
	uint32_T *wordptr;
	lbptr_T lbptr;
	buf_T *buf;

	words_per_block= state.super->ses_block_size / sizeof(*wordptr);
	bits_per_word= sizeof(*wordptr)*8;

	lbptr= lbuf_mkptr(LT_BITMAP, 0, 0, 0, block);
	buf= read_block(lbptr, state.super->ses_block_size);

	wordptr= (uint32_T *)buf_data_ptr(buf);

	offset= block*words_per_block;
	errors= 0;
	for (i= 0; i<words_per_block; i++)
	{
		w1= state.bitmap[offset+i];
		w2= wordptr[i];
#if 0
		printf(
"check_bitmap_block: blocks %lld (offset %lld), word %d: w1 %08x w2 %08x\n",
			block, offset, i, (unsigned)w1, (unsigned)w2);
#endif
		if (w1 & w2)
		{
			/* There are block that are both marked free and
			 * are in used.
			 */
			fatal("check_bitmap_block: should handle and case");
		}
		if (~(w1 | w2) != 0)
		{
			/* Some blocks are lost */
			w= w1 | w2;
			for (j= 0; j < bits_per_word; j++)
			{
				if (w & (1U << j))
					continue;
				printf("check_bitmap_block: lost block %llu\n",
					(unsigned long long)
					((offset+i)*bits_per_word+j));
				errors++;
			}
		}
	}

	wordptr= NULL;
	buf_release(buf);
	buf= NULL;

	return errors;
}

static lbptr_T get_parent(lbptr_T lbptr, unsigned *offsetp)
{
	unsigned block_size, pointers_per_block, inodes_per_block, slot, ind;
	int ind_levels;
	uint64_T inode_block;

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

	case LT_DATA_INDEX:
		assert(lbptr.lbp_level <= state.inode_max_indir);
		if (lbptr.lbp_offset < state.indirs[lbptr.lbp_level].count)
		{
			inodes_per_block= block_size / SEF_INODE_SIZE;
			inode_block= lbptr.lbp_inode / inodes_per_block;
			ind= lbptr.lbp_inode % inodes_per_block;
			slot= state.indirs[lbptr.lbp_level].slot +
				lbptr.lbp_offset;
			*offsetp= ind*sizeof(sef_inode_T) +
				offsetof(sef_inode_T, sei_blkptrs[0]) +
				slot * sizeof(sef_blkptr_T);
			return lbuf_mkptr(LT_INODE,
				lbptr.lbp_space, 0, 0, inode_block);
		}

		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_DATA_INDEX,
			lbptr.lbp_space, lbptr.lbp_inode, lbptr.lbp_level+1,
			lbptr.lbp_offset / pointers_per_block);

	case LT_DATA:
		assert(lbptr.lbp_level == 0);
		if (lbptr.lbp_offset < state.indirs[0].count)
		{
			inodes_per_block= block_size / SEF_INODE_SIZE;
			inode_block= lbptr.lbp_inode / inodes_per_block;
			ind= lbptr.lbp_inode % inodes_per_block;
			slot= state.indirs[0].slot + lbptr.lbp_offset;
			*offsetp= ind*sizeof(sef_inode_T) +
				offsetof(sef_inode_T, sei_blkptrs[0]) +
				slot * sizeof(sef_blkptr_T);
			return lbuf_mkptr(LT_INODE,
				lbptr.lbp_space, 0, 0, inode_block);
		}

		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_DATA_INDEX,
			lbptr.lbp_space, lbptr.lbp_inode, 1,
			lbptr.lbp_offset / pointers_per_block);

	case LT_FBT_INDEX:
		if (lbptr.lbp_level == lbptr.lbp_inode)

		{
			assert(lbptr.lbp_offset == 0);
			assert( lbptr.lbp_inode < SEF_BM_IND_MAX);

			*offsetp= offsetof(sef_checkpoint_T, secp_fbt[0]) +
				lbptr.lbp_inode * sizeof(sef_blkptr_T);
			return lbuf_mkptr(LT_CHECKPOINT,
				lbptr.lbp_space, 0, 0, 0);
		}

		assert(lbptr.lbp_level < lbptr.lbp_inode);

		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_FBT_INDEX,
			lbptr.lbp_space, lbptr.lbp_inode, lbptr.lbp_level+1,
			lbptr.lbp_offset / pointers_per_block);

	case LT_FBT:
		assert(lbptr.lbp_level == 0);
		if (lbptr.lbp_inode == 0)
		{
			assert(lbptr.lbp_offset == 0);
			*offsetp= offsetof(sef_checkpoint_T, secp_fbt[0]);
			return lbuf_mkptr(LT_CHECKPOINT,
				lbptr.lbp_space, 0, 0, 0);
		}

		*offsetp= (lbptr.lbp_offset % pointers_per_block)*
			SEF_BLKPTR_SIZE;
		return lbuf_mkptr(LT_FBT_INDEX,
			lbptr.lbp_space, lbptr.lbp_inode, 1,
			lbptr.lbp_offset / pointers_per_block);

	default:
		fatal("get_parent: should support type %d", lbptr.lbp_type);
	}
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

static void link_count_init(void)
{
	state.link_count_nr= 2*state.checkpoint->secp_inodes;
	state.link_counts= malloc(state.link_count_nr *
		sizeof(*state.link_counts));
	memset(state.link_counts, '\0', state.link_count_nr *
		sizeof(*state.link_counts));
	state.link_inode_count= 0;
}

static uint32_T link_count_read(uint64_T inode)
{
	if (inode >= state.link_count_nr)
		return 0;
	return state.link_counts[inode];
}

static void link_count_inc(uint64_T inode)
{
	unsigned new_count, new_size;

	if (inode >= state.link_count_nr)
	{
		new_count= 2*inode;
		new_size= new_count*sizeof(state.link_counts[0]);
		if (new_size/sizeof(state.link_counts[0]) != new_count)
		{
			fatal("link_count_inc: bad inode number %llu", inode);
		}
		state.link_counts= realloc(state.link_counts, new_size);
		memset(&state.link_counts[state.link_count_nr], '\0',
			(new_count-state.link_count_nr)*
			sizeof(state.link_counts[0]));
		state.link_count_nr= new_count;
	}
	if (state.link_counts[inode] == 0)
		state.link_inode_count++;
	state.link_counts[inode]++;
	if (state.link_counts[inode] == 0)
		fatal("link_count_inc: overflow for inode %llu", inode);
}

buf_T *read_block(lbptr_T lbptr, size_t size)
{
	unsigned block_size, offset;
	uint64_T block;
	uint8_T *p_data, *ciphertext;
	buf_T *p_buf;
	buf_T *buf;
	lbptr_T parent;
	sef_blkptr_T blkptr;

	block_size= state.super->ses_block_size;

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
	blkptr= *(sef_blkptr_T *)(p_data+offset);
	block= blkptr.sebp_block;
	buf_release(p_buf); p_buf= NULL;
	p_data= NULL;

	if (block == 0)
	{
		/* This logical block does not exist. Just clear the block
		 * an mark it valid.
		 */
		printf("read_block: wiping buffer at %p\n", buf_data_ptr(buf));
		memset(buf_data_ptr(buf), '\0', state.super->ses_block_size);
		buf_setvalid(buf);
		return buf;
	}
	printf("read_block: my block is %llu\n", (unsigned long long)block);

	ciphertext= malloc(block_size);

	lseek(state.fd, block*block_size, SEEK_SET);
	if (read(state.fd, ciphertext, block_size) != block_size)
	{
		fatal("read_block: unable to read block %llu", block);
	}

	decrypt_block(&blkptr, ciphertext, buf_data_ptr(buf));

	free(ciphertext); ciphertext= NULL;

	buf_setvalid(buf);

	return buf;
}

static void decrypt_block(sef_blkptr_T *blkptr, uint8_T *ciphertext,
	uint8_T *plaintext)
{
	unsigned block_size;
	SHA256_CTX ctx;
	hmac_sha256_ctx_t hm_ctx;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;
	sef_hash_T hash;

	block_size= state.super->ses_block_size;

#if 0
	{ int i;
	printf("decrypt_block: blkptr: ");
	for(i= 0; i<sizeof(*blkptr); i++)
		printf("%02x", ((uint8_T *)blkptr)[i]);
	printf("\n");
	}
#endif

	/* Create the AES decryption key */
	hmac_sha256_init(&hm_ctx, state.super->ses_disk_key, 
		sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx, blkptr, sizeof(*blkptr));
	hmac_sha256_finish(&hm_ctx, aes_key);
	hmac_sha256_cleanup(&hm_ctx);

#if 0
	{ int i;
	printf("decrypt_block: aes_key: ");
	for(i= 0; i<sizeof(aes_key); i++)
		printf("%02x", aes_key[i]);
	printf("\n");
	}
#endif

	/* AES CBC decrypt */
	if (rijndael_makekey(&aes_ctx, sizeof(aes_key), aes_key) != 0)
		fatal("rijndael_makekey failed");
	memset(aes_key, '\0', sizeof(aes_key));
	
	if (rijndael_cbc_decrypt(&aes_ctx, ciphertext, 
		plaintext, block_size, &blkptr->sebp_iv) != block_size)
		fatal("rijndael_cbc_decrypt failed");

	memset(&aes_ctx, '\0', sizeof(aes_ctx));

#if 0
	{ int i;
	printf("decrypt_block: plaintext: ");
	for(i= 0; i<block_size; i++)
		printf("%02x", plaintext[i]);
	printf("\n");
	}
#endif

	/* Check hash */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, plaintext, block_size);
	SHA256_Final((unsigned char *)&hash, &ctx);

#if 0
	{ int i;
	printf("decrypt_block: hash: ");
	for(i= 0; i<sizeof(hash); i++)
		printf("%02x", ((uint8_T *)&hash)[i]);
	printf("\n");
	}
#endif

	if (memcmp(&hash, &blkptr->sebp_hash, sizeof(hash)) != 0)
	{
		fatal("decrypt_block: decryption failed for block %llu",
			blkptr->sebp_block);
	}

	memset(blkptr, '\0', sizeof(*blkptr));
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

#if 0
static void print_bin(void *buf, size_t size)
{
	int i;
	uint8_T *uc;

	uc= buf;
	for (i= 0; i<size; i++)
		printf("%02x", uc[i]);
}
#endif

static char *fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "fsck_sef: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: fsck_sof [ options ] <device>\n");
	exit(2);
}
