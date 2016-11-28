/*
sefc.c

Created:	January 2016 by Philip Homburg <philip@f-src.phicoh.com>

SEF command processor
*/

#define _POSIX_C_SOURCE 2

#include "os.h"

#include <ctype.h>
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

#define MAX_ARGS	10

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

	uint64_T alloc_block;
	unsigned alloc_next;
	buf_T *p_alloc_buf;
	uint32_T *p_alloc_data;
	buf_T *c_alloc_buf;
	uint32_T *c_alloc_data;

	uint64_T fbl_block;	/* Block where head can be stored temporarily */
	uint64_T *fbl_data;	/* Contents of the head of the free block
				 * list.
				 */
	unsigned fbl_ind_start;	/* Leave space for a block pointer */
	unsigned fbl_ind_end;	/* Based on block size */
	unsigned fbl_ind_curr;	/* Point to free space, or equal to 
				 * fbl_ind_end if full.
				 */

	uint64_T *fbt0_data;
	unsigned fbt_ind_end;	/* Based on block size */
	unsigned fbt_ind_curr;	/* Slot doesn't have to be empty */

	uint64_T cwd;

	unsigned transaction_nest;	/* transaction nesting level */

	char *password;
} state;

static void doit(void);
static void load_super(void);
static void checkpoint_write(buf_T *prev_buf);
static void super_decrypt(uint64_T block, uint8_T *ciphertext,
	uint8_T *plaintext);
static void do_argon2(int iter, int mem, int par, int hashlen, char *salt,
	char *passwd, char *hash, double *durationp);
static void load_checkpoint(void);
static void unload_checkpoint(void);
static int checkpoint_decrypt(uint8_T *ciphertext, uint8_T *plaintext);
static void transaction_start(void);
static void transaction_end(void);
buf_T *read_block(lbptr_T lbptr, size_t size);
static void decrypt_block(sef_blkptr_T *blkptr, uint8_T *ciphertext,
	uint8_T *plaintext);
static void write_buf(buf_T *buf);
static void make_writable(buf_T *buf, sef_inode_T *inop);
static void alloc_init(void);
static void alloc_setup(void);
static int alloc_check_block(uint64_T block);
static void alloc_stop(void);
static void alloc_special(void);
static uint64_T alloc_block(void);
static void free_block(uint64_T block);
static void fbl_new_head(void);
static void fbl_flush_head(void);
static void fbl_flush_tail(void);
static void fbl_unload(void);
static void fbt_setup(void);
static void fbt_flush(void);
static void fbt_flush_block(lbptr_T lbptr);
static void fbt_unload(void);
static void inode_alloc(uint64_T prev_inode, uint64_T *new_inodep,
	sef_inode_T **new_inop, buf_T **new_bufp, int is_dir);
static uint64_T inode_alloc_in_block(uint64_T block, unsigned ind,
	sef_inode_T **new_inop, buf_T **new_bufp, int is_dir, int check_free);
static lbptr_T get_parent(lbptr_T lbptr, unsigned *offsetp);
static void print_ptr(lbptr_T lbptr);
static int do_path(uint64_T curr_inode, uint64_T *dir_inodep, char **name);
static int resolve_path(uint64_T cwd, char *path, uint64_T *inodep);
static int last_dir(uint64_T cwd, char *path, uint64_T *dir_inodep,
	char **filenamep);
static int dir_lookup(uint64_T start_dir, char *name, uint64_T *res_inodep);
static int dir_insert(uint64_T dir_inode, char *name, uint64_T new_inode);
static int dir_insert_imm(buf_T *buf, uint64_T dir_inode, char *name,
	uint64_T new_inode);
static int insert_name(uint64_T dir_inode, char *name, uint64_T *new_inodep,
	sef_inode_T **new_inop, buf_T **new_bufp, int is_dir);
static int insert_name_imm(buf_T *buf, uint64_T dir_inode, char *name,
	uint64_T *new_inodep, sef_inode_T **new_inop, buf_T **new_bufp,
	int is_dir);
static void dir_imm2block(uint64_T inode, sef_inode_T *inop);
static int dir_remove(uint64_T dir_inode, char *name);
static void unref_add(uint64_T inode);
static void unref_imm2block(sef_inode_T *inop);
static void unref_clean_inode(uint64_T inode);
static void unref_clean_index_block(lbptr_T lbptr, sef_inode_T *inop);
static void unref_clean_data_block(lbptr_T lbptr, sef_inode_T *inop);
static void truncate_inode(uint64_T inode, sef_inode_T *inop,
	buf_T *inode_buf);
static void wipe_index_block(lbptr_T lbptr, sef_inode_T *inop, int do_flush);
static void get_inode(uint64_T inode, sef_inode_T **inop, buf_T **bufp);
static char *get_password(char *password_file);
static int cmp_u64(const void *v1, const void *v2);
static void bin2hex_str(void *in, size_t in_len, char *out, size_t out_len);
static void hex_str2bin(char *str, void *out, size_t out_len);
#if 0
static void print_bin(void *buf, size_t size);
#endif
static char *fatal(char *fmt, ...) _NORETURN;
static void usage(void);

static void link_file(int argc, char *argv[]);
static void make_dir(int argc, char *argv[]);
static void remove_file(int argc, char *argv[]);
static void truncate_file(int argc, char *argv[]);
static void unlink_file(int argc, char *argv[]);
static void unref_clean(int argc, char *argv[]);
static void write_file(int argc, char *argv[]);

struct cmd
{
	char *name;
	void (*f)(int argc, char *argv[]);
} cmdtab[]=
{
	{ "clean-unref",	unref_clean	},
	{ "link",		link_file	},
	{ "mkdir",		make_dir	},
	{ "rm",			remove_file	},
	{ "trunc",		truncate_file	},
	{ "unlink",		unlink_file	},
	{ "write",		write_file	},
	{ NULL				}
};


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

	state.fd= open(special, O_RDWR);
	if (state.fd == -1)
		fatal("unable to open '%s': %s", special, strerror(errno));

	state.cwd= SEF_ROOT_INODE;

	state.password= get_password(password_file);

	buf_init(write_buf);

	load_super();

	load_checkpoint();

	alloc_init();

	doit();

	unload_checkpoint();

	fbl_unload();

	buf_flush();

	/* And we are done */
	printf("done\n");
	return 0;
}

static void doit(void)
{
	int argc, istty;
	unsigned char *p;
	struct cmd *cmdp;
	char *argv[MAX_ARGS];
	char line[1024];

	istty= isatty(0);

	for (;;)
	{
		if (istty)
		{
			printf("SEF> ");
			fflush(stdout);
		}
		if (fgets(line, sizeof(line), stdin) == NULL)
		{
			if (feof(stdin))
				break;
			else if (ferror(stdin))
			{
				fatal("read error on stdin: %s",
					strerror(errno));
			}
			else
				fatal("fgets error");
		}
		if (strchr(line, '\n') == NULL)
			fatal("input line too long");

		printf("doit: got cmd '%s'\n", line);

		for (argc= 0, p= (unsigned char *)line; argc<MAX_ARGS; argc++)
		{
			while (*p != '\0' && isspace(*p))
				p++;
			if (*p == '\0')
				break;
			if (*p == '#')
			{
				/* Move p to the end of the line for the
				 * max args check.
				 */
				p += strlen((char *)p);
				break;	/* comment */
			}
			argv[argc]= (char *)p;
			while (*p != '\0' && !isspace(*p))
				p++;
			if (*p != '\0')
				*p++= '\0';
		}

		if (*p != '\0')
			fatal("too many arguments on input line");

		if (argc == 0)
			continue;

		for (cmdp= cmdtab; cmdp->name != NULL; cmdp++)
		{
			if (strcmp(argv[0], cmdp->name) == 0)
				break;
		}
		if (cmdp->name == NULL)
		{
			printf("unknown command '%s'\n", argv[0]);
			continue;
		}
		cmdp->f(argc, argv);
	}
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
	sef_super_T *super_in, *superp;
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
	buf_T *c_buf, *l_buf;
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
	lbptr= lbuf_mkptr(LT_CHECKPOINT, LS_LATEST_CHECKPOINT, 0, 0, 0);
	l_buf= lbuf_alloc(lbptr, block_size);

	if (plaintext2 == NULL)
	{
		assert(plaintext1);
		memcpy(buf_data_ptr(l_buf), plaintext1, block_size);
	}
	else if (plaintext1 == NULL)
	{
		assert(plaintext2);
		memcpy(buf_data_ptr(l_buf), plaintext2, block_size);
	}
	else if (((sef_checkpoint_T *)plaintext1)->secp_seqnr >
		((sef_checkpoint_T *)plaintext2)->secp_seqnr)
	{
		memcpy(buf_data_ptr(l_buf), plaintext1, block_size);
	}
	else
	{
		assert((((sef_checkpoint_T *)plaintext2)->secp_seqnr >
			((sef_checkpoint_T *)plaintext1)->secp_seqnr));
		memcpy(buf_data_ptr(l_buf), plaintext2, block_size);
	}

	buf_setvalid(l_buf);

	lbptr= lbuf_mkptr(LT_CHECKPOINT, 0, 0, 0, 0);
	c_buf= lbuf_alloc(lbptr, block_size);

	/* Copy data */
	memcpy(buf_data_ptr(c_buf), buf_data_ptr(l_buf), block_size);

	buf_setvalid(c_buf);
	buf_setwritable(c_buf);
	buf_write_ref(c_buf);	/* Prevent the block for getting written out */
	buf_lock(c_buf);
	buf_release(c_buf);	/* Only keep the lock */

	state.checkpoint= buf_data_ptr(c_buf);

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
	unsigned block_size;
	buf_T *buf, *prev_buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	lbptr= lbuf_mkptr(LT_CHECKPOINT, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);

	lbptr= lbuf_mkptr(LT_CHECKPOINT, LS_LATEST_CHECKPOINT, 0, 0, 0);
	prev_buf= lbuf_alloc(lbptr, block_size);

	/* Compare the two checkpoint to see if anything changed and
	 * we need to make a new checkpoint.
	 */
	assert(buf_is_valid(buf));
	assert(buf_is_valid(prev_buf));

	if (memcmp(buf_data_ptr(buf), buf_data_ptr(prev_buf),
		block_size) != 0)
	{
		checkpoint_write(prev_buf);
	}

	/* Mark the checkpoint buffer as clean */
	buf_setclean(buf);

	/* Now we got three reference. We just got a read reference and
	 * we already had a lock and a write ref.
	 */
	state.checkpoint= NULL;

	buf_release(buf);
	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;

	/* We now have two references to the prevsious checkpoint */
	buf_release(prev_buf);
	buf_release(prev_buf);
	prev_buf= NULL;
}

static void checkpoint_write(buf_T *prev_buf)
{
	unsigned block_size, offset, bits_per_block, ind;
	uint8_T *data, *ciphertext;
	uint32_T bit;
	uint64_T block, bm_block;
	SHA256_CTX ctx;
	hmac_sha256_ctx_t hm_ctx;
	sef_hash_T hash, disk_sign_key;
	uint8_T aes_key[256 / 8];
	rd_keyinstance aes_ctx;
	sef_iv_T iv;

	if (state.transaction_nest)
		fatal("checkpoint_write: in transaction");

	block_size= state.super->ses_block_size;

	for (;;)
	{
		/* Clean fbl */
		if (((sef_blkptr_T *)state.fbl_data)->sebp_block != 0)
			fbl_flush_tail();

		if (state.fbl_ind_curr != state.fbl_ind_start)
		{
			fbl_flush_head();
			continue;
		}

		if (state.fbl_block)
		{
			bits_per_block= block_size*8;

			block= state.fbl_block;
			bm_block= block/bits_per_block;

			if (bm_block == state.alloc_block &&
				state.c_alloc_buf != NULL)
			{
				ind= (block % bits_per_block)/32;
				bit= 1 << (block % 32);

				assert(!(state.c_alloc_data[ind] & bit));
				state.c_alloc_data[ind] |= bit;
				state.checkpoint->secp_free_blocks++;
				state.fbl_block= 0;

				if (!(state.p_alloc_data[ind] & bit))
				{
					printf(
			"checkpoint_write: should increase checkpoint bonus\n");
				}
			}
			else
			{
				fatal("checkpoint_write: should release fbl_block");
			}
		}

		break;
	}

	/* Stop allocator */
	alloc_stop();

	fbt_unload();

	/* Flush dirty buffers */
	lbuf_sync();

	if (fsync(state.fd) == -1)
		fatal("checkpoint_write: fsync failed");

	/* Increment sequence number */
	state.checkpoint->secp_seqnr++;

	/* Compute disk_sign_key */
	hmac_sha256_init(&hm_ctx,
		(unsigned char *)&state.super->ses_disk_key, 
			sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx, "S", 1);
	hmac_sha256_finish(&hm_ctx,
		(unsigned char *)&disk_sign_key);
	hmac_sha256_cleanup(&hm_ctx);

	os_random(&state.checkpoint->secp_iv,
		sizeof(state.checkpoint->secp_iv));

	block= (state.checkpoint->secp_seqnr & 1) == 0 ?
		state.super->ses_first_checkpoint_block :
		state.super->ses_second_checkpoint_block;
	state.checkpoint->secp_block= block;

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

	printf("checkpoint_write: block %lld, offset %lld\n",
		(unsigned long long)block,
		(unsigned long long)block*block_size);

	lseek(state.fd, block*block_size, SEEK_SET);
	if (write(state.fd, ciphertext, block_size) != block_size)
		fatal("write failed");

	if (fsync(state.fd) == -1)
		fatal("checkpoint_write: fsync failed");

	free(ciphertext);

	memset(&disk_sign_key, '\0', sizeof(disk_sign_key));

	/* Copy new checkpoint to previous checkpoint */
	memcpy(buf_data_ptr(prev_buf), state.checkpoint, block_size);

	lbuf_flush_space(LS_LATEST_CHECKPOINT);
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

static void transaction_start(void)
{
	if (!state.fbl_block)
		alloc_special();
	if (state.transaction_nest)
	{
		printf(
		"transaction_start: already in transaction, nested %d\n",
			state.transaction_nest);
	}
	state.transaction_nest++;
}

static void transaction_end(void)
{
	printf("transaction_end: should check free blocks\n");

	assert(state.transaction_nest);
	state.transaction_nest--;
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
		assert(lbptr.lbp_offset == 0);
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

	case LT_FBL:
		/* The head of the FBL has parent. For other blocks,
		 * the parent is at offset one less.
		 */
		if (lbptr.lbp_offset == 0)
			fatal("get_parent: FBL head has not parent");

		*offsetp= 0;	/* pointer is at the start of the block */
		return lbuf_mkptr(LT_FBL, lbptr.lbp_space, lbptr.lbp_inode,
			lbptr.lbp_level, lbptr.lbp_offset-1);

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
	case LT_DATA_INDEX: type_str= "DATA_INDEX"; break;
	case LT_DATA: type_str= "DATA"; break;
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
		memset(buf_data_ptr(buf), '\0', state.super->ses_block_size);
		buf_setvalid(buf);
		return buf;
	}
	printf("read_block: my block is %llu\n", (unsigned long long)block);

	ciphertext= malloc(block_size);
	assert(ciphertext);

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

static void write_buf(buf_T *buf)
{
	unsigned block_size, offset;
	uint64_T block;
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

#if 0
	{ int i;
	printf("write_buf: blkptr: ");
	for(i= 0; i<sizeof(blkptr); i++)
		printf("%02x", ((uint8_T *)&blkptr)[i]);
	printf("\n");
	}
#endif

	/* Create the AES encryption key */
	hmac_sha256_init(&hm_ctx, state.super->ses_disk_key, 
		sizeof(state.super->ses_disk_key));
	hmac_sha256_update(&hm_ctx, &blkptr, sizeof(blkptr));
	hmac_sha256_finish(&hm_ctx, aes_key);
	hmac_sha256_cleanup(&hm_ctx);


#if 0
	{ int i;
	printf("write_buf: aes_key: ");
	for(i= 0; i<sizeof(aes_key); i++)
		printf("%02x", aes_key[i]);
	printf("\n");
	}
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
		(unsigned long long)block,
		(unsigned long long)block*block_size);

	lseek(state.fd, block*block_size, SEEK_SET);
	if (write(state.fd, ciphertext, block_size) != block_size)
		fatal("write failed");

	free(ciphertext);

	buf_setclean(buf);
}

static void make_writable(buf_T *buf, sef_inode_T *inop)
{
	unsigned offset;
	buf_T *p_buf;
	uint8_T *p_data;
	sef_blkptr_T *blkptr;
	uint64_T block, old_block;
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
	make_writable(p_buf, inop);

	/* Drop the read reference. We implicitly keep the write reference. */
	buf_release(p_buf);

	printf("write_block: got parent ");
	print_ptr(parent);
	printf(" offset %u for block ", offset);
	print_ptr(lbptr);
	printf("\n");

	block= alloc_block();
	printf("make_writable: got new block %lld\n",
		(unsigned long long)block);

	/* Extract old block and update block pointer */
	p_data= buf_data_ptr(p_buf);
	blkptr= (sef_blkptr_T *)(p_data + offset);
	old_block= blkptr->sebp_block;
	memset(blkptr, '\0', sizeof(*blkptr));
	blkptr->sebp_block= block;
	p_data= NULL;
	blkptr= NULL;

	if (old_block)
		free_block(old_block);
	else
	{
		/* May be a new file block */
		if (lbptr.lbp_type == LT_DATA ||
			lbptr.lbp_type == LT_DATA_INDEX)
		{
			assert(inop);
			inop->sei_blocks++;
		}
	}

	/* Make writable and add a write ref */
	buf_setwritable(buf);
	buf_write_ref(buf);

	printf("make_writable: buf refs: r%d, w%d, l%d\n",
		buf->b_readers, buf->b_writers, buf->b_locks);
	printf("make_writable: p_buf refs: r%d, w%d, l%d\n",
		p_buf->b_readers, p_buf->b_writers, p_buf->b_locks);
}

static void alloc_init(void)
{
	unsigned block_size;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	/* Should make this a random block */
	state.alloc_block= 0;

	/* Trigger new block. */
	state.alloc_next= state.super->ses_block_size * 8;

	state.p_alloc_buf= NULL;
	state.p_alloc_data= NULL;
	state.c_alloc_buf= NULL;
	state.c_alloc_data= NULL;

	assert(state.fbl_data == NULL);
	lbptr= lbuf_mkptr(LT_FBL, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	state.fbl_data= buf_data_ptr(buf);
	memset(state.fbl_data, '\0', block_size);
	buf_setvalid(buf);
	/* Don't make it writable. Do that when it is no longer the head of
	 * the list.
	 */
	buf= NULL;

	state.fbl_ind_start= sizeof(sef_blkptr_T)/sizeof(state.fbl_data[0]);
	state.fbl_ind_end= block_size/sizeof(state.fbl_data[0]);
	state.fbl_ind_curr= state.fbl_ind_start;
}

static void alloc_setup(void)
{
	unsigned block_size, bits_per_block;
	uint64_T bitmap_blocks, bc, block;

	/* We get called in three cases:
	 * 1) Just after start up
	 * 2) After a checkpoint
	 * 3) When the current block is full
	 *
	 * After a checkpoint, check if we can continue with the current
	 * block. When the current block is full, we should find a new one.
	 * Use the value of alloc_next to distiguish the two cases.
	 * If alloc_next is greather or equal to the number of bits in a
	 * block then the current block is full.
	 * During start up, have the init code also set alloc_next to 
	 * the number of bits in a block and select a random bitmap block as
	 * starting point.
	 */

	block_size= state.super->ses_block_size;
	bits_per_block= block_size * 8;
	bitmap_blocks= state.super->ses_last_data_block/bits_per_block + 1;
	for (bc= 0; bc<bitmap_blocks; bc++)
	{
		if (state.alloc_next < state.super->ses_block_size * 8)
		{
			fatal("alloc_setup: should revalidate existing block");
		}

		block= (state.alloc_block+1+bc) % bitmap_blocks;

		if (alloc_check_block(block))
			break;
	}

	if (bc >= bitmap_blocks)
		fatal("alloc_setup: cannot find suitable bitmap block");

	/* Alloc check sets up the allocator, but we have to make the
	 * block writable.
	 */
	make_writable(state.c_alloc_buf, NULL);
}

static int alloc_check_block(uint64_T block)
{
	unsigned block_size, bits_per_block, next, bit, ind, found;
	buf_T *c_buf, *p_buf;
	uint32_T *c_words, *p_words;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	lbptr= lbuf_mkptr(LT_BITMAP, LS_LATEST_CHECKPOINT, 0, 0, block);
	p_buf= read_block(lbptr, block_size);

	lbptr= lbuf_mkptr(LT_BITMAP, 0, 0, 0, block);
	c_buf= read_block(lbptr, block_size);

	p_words= (uint32_T *)buf_data_ptr(p_buf);
	c_words= (uint32_T *)buf_data_ptr(c_buf);

	bits_per_block= state.super->ses_block_size * 8;
	next= 0;
	found= 0;
	while (next < bits_per_block)
	{
		bit= next % 32;
		ind= next / 32;
		if (!(c_words[ind] & (1 << bit)))
		{
			next++;
			continue;
		}
		if (!(p_words[ind] & (1 << bit)))
		{
			next++;
			continue;
		}
		found++;
		if (found >= 32)
			break;
		next++;
	}

	if (next >= bits_per_block)
	{
		printf(
	"alloc_check_block: failed for block %llu, found %d free blocks\n",
			(unsigned long long)block, found);

		/* Not enough free space in this block */
		c_words= NULL;
		p_words= NULL;
		buf_release(c_buf);
		buf_release(p_buf);
		c_buf= NULL;
		p_buf= NULL;
		return 0;
	}

	/* It is easier to set up buffers here. */
	state.alloc_block= block;
	state.alloc_next= 0;

	buf_lock(c_buf);
	buf_release(c_buf);	/* No need to keep the read reference */
	state.c_alloc_buf= c_buf;
	state.c_alloc_data= (uint32_T *)buf_data_ptr(c_buf);

	buf_lock(p_buf);
	buf_release(p_buf);	/* No need to keep the read reference */
	state.p_alloc_buf= p_buf;
	state.p_alloc_data= (uint32_T *)buf_data_ptr(p_buf);

	return 1;
}

static void alloc_stop(void)
{
	buf_T *buf;

	buf= state.c_alloc_buf;
	state.c_alloc_buf= NULL;
	state.c_alloc_data= NULL;

	/* For the current buffer, we have a lock and a write ref */
	buf_unlock(buf);
	buf_release_write(buf);
	buf= NULL;

	buf= state.p_alloc_buf;
	state.p_alloc_buf= NULL;
	state.p_alloc_data= NULL;

	/* For the previous buffer, we have only a lock */
	buf_unlock(buf);
	buf= NULL;
}

static void alloc_special(void)
{
	unsigned bits_per_block, next, bit, ind;

	/* Special alloc for fbl_block. Just get the first free block in the
	 * current allocation block. That is least likely to interfere with 
	 * normal block allocation.
	 */
	if (state.fbl_block)
		return;

	for (;;)
	{
		if (!state.c_alloc_data)
		{
			alloc_setup();
			assert(state.c_alloc_data);
		}

		bits_per_block= state.super->ses_block_size * 8;
		next= 0;
		while (next < bits_per_block)
		{
			bit= next % 32;
			ind= next / 32;
			if (!(state.c_alloc_data[ind] & (1 << bit)))
			{
				next++;
				continue;
			}
			if (!(state.p_alloc_data[ind] & (1 << bit)))
			{
				next++;
				continue;
			}
			state.c_alloc_data[ind] &=  ~(((uint32_T)1) << bit);
			state.checkpoint->secp_free_blocks--;
			state.fbl_block= state.alloc_block*bits_per_block + next;
			return;
		}

		alloc_stop();

		/* Move to next block */
		state.alloc_next= state.super->ses_block_size * 8;

		/* And try again */
	}
}

static uint64_T alloc_block(void)
{
	unsigned bits_per_block, next, bit, ind;

	for (;;)
	{
		if (!state.c_alloc_data)
		{
			alloc_setup();
			assert(state.c_alloc_data);
		}

		bits_per_block= state.super->ses_block_size * 8;
		next= state.alloc_next;
		while (next < bits_per_block)
		{
			bit= next % 32;
			ind= next / 32;
			if (!(state.c_alloc_data[ind] & (1 << bit)))
			{
				next++;
				continue;
			}
			if (!(state.p_alloc_data[ind] & (1 << bit)))
			{
				next++;
				continue;
			}
			state.c_alloc_data[ind] &=  ~(((uint32_T)1) << bit);
			state.checkpoint->secp_free_blocks--;
			state.alloc_next= next+1;
			return state.alloc_block*bits_per_block + next;
		}

		alloc_stop();

		/* Move to next block */
		state.alloc_next= state.super->ses_block_size * 8;

		/* And try again */
	}

	fatal("alloc_block: not implemented");
}

static void free_block(uint64_T block)
{
	unsigned block_size, bits_per_block, ind;
	uint32_T bit;
	uint64_T bm_block;

	block_size= state.super->ses_block_size;
	bits_per_block= block_size*8;

	bm_block= block/bits_per_block;

	if (bm_block == state.alloc_block && state.c_alloc_buf != NULL)
	{
		ind= (block % bits_per_block)/32;
		bit= 1 << (block % 32);

		assert(!(state.c_alloc_data[ind] & bit));
		state.c_alloc_data[ind] |= bit;
		state.checkpoint->secp_free_blocks++;

		if (!(state.p_alloc_data[ind] & bit))
		{
			printf(
			"free_block: should increase checkpoint bonus\n");
		}

	}
	else
	{
		if (state.fbl_ind_curr >= state.fbl_ind_end)
			fbl_new_head();
		state.fbl_data[state.fbl_ind_curr]= block;
		state.fbl_ind_curr++;
	}
}

static void fbl_new_head(void)
{
	unsigned block_size;
	buf_T *buf, *prev_buf;
	sef_blkptr_T *blkptr;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	assert(state.fbl_block);

	state.fbl_data= NULL;

	/* Get reference to head */
	lbptr= lbuf_mkptr(LT_FBL, 0, 0, 0, 0);
	buf= lbuf_lookup(lbptr);
	assert(buf);
	buf_release(buf);	/* We have a lock left */

	lbptr= lbuf_mkptr(LT_FBL, 0, 0, 0, 1);
	lbuf_rename(buf, lbptr);
	prev_buf= buf; buf= NULL;

	lbptr= lbuf_mkptr(LT_FBL, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	state.fbl_data= buf_data_ptr(buf);
	memset(state.fbl_data, '\0', block_size);
	buf_setvalid(buf);
	state.fbl_ind_curr= state.fbl_ind_start;

	blkptr= (sef_blkptr_T *)buf_data_ptr(buf);
	blkptr->sebp_block= state.fbl_block;
	state.fbl_block= 0;

	buf_setwritable(buf);
	buf_write_ref(buf);

	buf_setwritable(prev_buf);
	buf_unlock(prev_buf);

	/* It is easiest with this buffer cache to write out the block
	 * now. Assume that most transactions are small so this 
	 * situation will be rare.
	 */
	lbuf_sync_buf(prev_buf);

	/* Clear writable for head. That causes confusion and we never write
	 * head anyhow.
	 */
	buf_setclean(buf);

	assert(!buf_is_writable(prev_buf));
	assert(!buf_is_writable(buf));

	alloc_special();
}

static void fbl_flush_head(void)
{
	if (!state.fbt0_data)
		fbt_setup();

	while (state.fbl_ind_curr > state.fbl_ind_start)
	{
		/* Find a free spot in fbt0 */
		while (state.fbt_ind_curr < state.fbt_ind_end)
		{
			if (state.fbt0_data[state.fbt_ind_curr] == 0)
				break;
			state.fbt_ind_curr++;
		}
		if (state.fbt_ind_curr >= state.fbt_ind_end)
		{
			fbt_flush();
			assert(state.fbt_ind_curr < state.fbt_ind_end);
			assert(state.fbt0_data[state.fbt_ind_curr] == 0);
		}

		state.fbl_ind_curr--;
		state.fbt0_data[state.fbt_ind_curr]=
			state.fbl_data[state.fbl_ind_curr];
		state.fbl_data[state.fbl_ind_curr]= 0;
		state.fbt_ind_curr++;
	}
}

static void fbl_flush_tail(void)
{
	unsigned block_size, ind;
	sef_blkptr_T *blkptr, *tmp_blkptr;
	buf_T *buf;
	uint64_T *tmp_data;
	uint64_T block;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	if (!state.fbt0_data)
		fbt_setup();

	blkptr= (sef_blkptr_T *)state.fbl_data;

	while(blkptr->sebp_block != 0)
	{
		lbptr= lbuf_mkptr(LT_FBL, 0, 0, 0, 1);
		buf= read_block(lbptr, block_size);

		/* Use inode 1 for temporary storage */
		lbptr= lbuf_mkptr(LT_FBL, 0, 1, 0, 0);
		lbuf_rename(buf, lbptr);

		buf_lock(buf);
		buf_release(buf);

		tmp_data= buf_data_ptr(buf);
		tmp_blkptr= (sef_blkptr_T *)tmp_data;

		/* Save block number */
		block= blkptr->sebp_block;

		/* Remove this block from the list */
		*blkptr= *tmp_blkptr;

		/* Move block to fbt */
		for (ind= state.fbl_ind_start; ind < state.fbl_ind_end; ind++)
		{
			/* Find a free spot in fbt0 */
			while (state.fbt_ind_curr < state.fbt_ind_end)
			{
				if (state.fbt0_data[state.fbt_ind_curr] == 0)
					break;
				state.fbt_ind_curr++;
			}
			if (state.fbt_ind_curr >= state.fbt_ind_end)
			{
				fbt_flush();
				assert(state.fbt_ind_curr < state.fbt_ind_end);
				assert(state.fbt0_data[state.fbt_ind_curr] ==
					0);
			}

			state.fbt0_data[state.fbt_ind_curr]= tmp_data[ind];
			tmp_data[ind]= 0;
			state.fbt_ind_curr++;
		}

		buf_unlock(buf); buf= NULL;

		/* It is likely that this FBL block was allocated from the
		 * current allocation block. Just call the normal
		 * free_block function.
		 */
		free_block(block); block= 0;
	}
}

static void fbl_unload(void)
{
	unsigned block_size;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	if (((sef_blkptr_T *)state.fbl_data)->sebp_block != 0)
		fatal("fbl_unload: fbl has tail");
	if (state.fbl_ind_curr != state.fbl_ind_start)
		fatal("fbl_unload: fbl not empty");

	state.fbl_data= NULL;

	lbptr= lbuf_mkptr(LT_FBL, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);

	buf_release(buf);
	buf_unlock(buf);
	buf= NULL;
}

static void fbt_setup(void)
{
	unsigned block_size;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	assert(state.fbt0_data == NULL);
	lbptr= lbuf_mkptr(LT_FBT, 0, 0, 0, 0);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	make_writable(buf, NULL);

	state.fbt0_data= buf_data_ptr(buf);
	state.fbt_ind_end= block_size/sizeof(state.fbt0_data[0]);
	state.fbt_ind_curr= 0;
}

static void fbt_flush(void)
{
	lbptr_T lbptr;

	lbptr= lbuf_mkptr(LT_FBT, 0, 0, 0, 0);
	fbt_flush_block(lbptr);
	state.fbt_ind_curr= 0;
	assert(state.fbt0_data[state.fbt_ind_curr] == 0);
}

static void fbt_flush_block(lbptr_T lbptr)
{
	int i;
	unsigned block_size, bits_per_block, fbt_ind, c_ind, index_height,
		ptrs_per_block;
	uint32_T bit;
	buf_T *buf, *c_buf, *p_buf;
	uint64_T *data, *n_data;
	uint32_T *c_data, *p_data;
	uint64_T block, offset, curr_offset, no_blocks, space_per_block;
	lbptr_T c_lbptr;

	block_size= state.super->ses_block_size;

	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	make_writable(buf, NULL);

	data= buf_data_ptr(buf);

	qsort(data, state.fbt_ind_end, sizeof(data[0]), cmp_u64);

	/* Are there more trees, or do we update the bitmap? */
	if (lbptr.lbp_inode+1 < state.super->ses_bm_ind_levels)
	{
		ptrs_per_block= block_size / sizeof(sef_blkptr_T);

		index_height= lbptr.lbp_inode+1;

		/* Compute number of leaf blocks in the next tree. */
		no_blocks= 1;
		for (i= 0; i<index_height; i++)
			no_blocks *= ptrs_per_block;

		/* Compute the block number space per leaf block. */
		space_per_block= state.super->ses_last_data_block /
			no_blocks + 1;

		printf(
"fbt_flush_block: index height %u, leaf blocks %llu, space per block %llu\n",
			index_height, (unsigned long long)no_blocks,
			(unsigned long long)space_per_block);

		c_buf= NULL;		/* lint */
		n_data= NULL;		/* lint */
		curr_offset= -1;	/* lint */
		c_ind= 0;		/* lint */
		for (fbt_ind= 0; fbt_ind < state.fbt_ind_end; fbt_ind++)
		{
			block= data[fbt_ind];
			if (!block)
				continue;
			data[fbt_ind]= 0;

			offset= block/space_per_block;

			if (c_buf == NULL || offset != curr_offset)
			{
				if (c_buf)
				{
					n_data= NULL;
					buf_release_write(c_buf);
					buf_unlock(c_buf);
					c_buf= NULL;
				}
				c_lbptr= lbuf_mkptr(lbptr.lbp_type, 
					lbptr.lbp_space, lbptr.lbp_inode+1,
					0, offset);
				c_buf= read_block(c_lbptr, block_size);
				buf_lock(c_buf);
				buf_release(c_buf);
				make_writable(c_buf, NULL);
				n_data= buf_data_ptr(c_buf);
				curr_offset= offset;
				c_ind= 0;
			}

			for (; c_ind < state.fbt_ind_end; c_ind++)
			{
				if (n_data[c_ind] == 0)
					break;
			}
			if (c_ind >= state.fbt_ind_end)
			{
				fbt_flush_block(c_lbptr);
				c_ind= 0;
				assert(n_data[c_ind] == 0);
			}
			n_data[c_ind++]= block;
		}

		if (c_buf)
		{
			n_data= NULL;
			buf_release_write(c_buf);
			buf_unlock(c_buf);
			c_buf= NULL;
		}
	}
	else
	{
		bits_per_block= block_size*8;

		c_buf= NULL;		/* lint */
		c_data= NULL;		/* lint */
		p_buf= NULL;		/* lint */
		p_data= NULL;		/* lint */
		curr_offset= -1;	/* lint */
		for (fbt_ind= 0; fbt_ind < state.fbt_ind_end; fbt_ind++)
		{
			block= data[fbt_ind];
			if (!block)
				continue;
			data[fbt_ind]= 0;

			offset= block/bits_per_block;

			if (c_buf == NULL || offset != curr_offset)
			{
				if (c_buf)
				{
					c_data= NULL;
					buf_release_write(c_buf);
					buf_unlock(c_buf);
					c_buf= NULL;
					p_data= NULL;
					buf_unlock(p_buf);
					p_buf= NULL;
				}
				c_lbptr= lbuf_mkptr(LT_BITMAP, 0, 0, 0,
					offset);
				c_buf= read_block(c_lbptr, block_size);
				buf_lock(c_buf);
				buf_release(c_buf);
				make_writable(c_buf, NULL);
				c_data= buf_data_ptr(c_buf);
				c_lbptr= lbuf_mkptr(LT_BITMAP,
					LS_LATEST_CHECKPOINT, 0, 0,
					offset);
				p_buf= read_block(c_lbptr, block_size);
				buf_lock(p_buf);
				buf_release(p_buf);
				p_data= buf_data_ptr(p_buf);
				curr_offset= offset;

			}

			c_ind= (block % bits_per_block)/32;
			bit= 1 << (block % 32);

			assert(!(c_data[c_ind] & bit));
			c_data[c_ind] |= bit;
			state.checkpoint->secp_free_blocks++;

			if (!(p_data[c_ind] & bit))
			{
				printf(
			"fbt_flush_block: should increase checkpoint bonus\n");
			}
		}

		if (c_buf)
		{
			c_data= NULL;
			buf_release_write(c_buf);
			buf_unlock(c_buf);
			c_buf= NULL;
			p_data= NULL;
			buf_unlock(p_buf);
			p_buf= NULL;
		}
	}

	data= NULL;
	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;
}

static void fbt_unload(void)
{
	unsigned block_size;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	if (!state.fbt0_data)
		return;

	state.fbt0_data= NULL;

	lbptr= lbuf_mkptr(LT_FBT, 0, 0, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);
	buf_release(buf);
	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;
}

static void inode_alloc(uint64_T prev_inode, uint64_T *new_inodep,
	sef_inode_T **new_inop, buf_T **new_bufp, int is_dir)
{
	int i;
	unsigned block_size, inodes_per_block, start_ind;
	uint64_T inode_blocks, start_block, new_inode, block;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	/* Compute the number of inode blocks */
	inode_blocks= state.checkpoint->secp_inodes*2/inodes_per_block + 1;
	printf("inode_alloc: inode_blocks = %llu\n",
		(unsigned long long)inode_blocks);

	start_block= prev_inode/inodes_per_block;
	start_ind= prev_inode % inodes_per_block;

	if (start_block < inode_blocks)
	{
		printf("inode_alloc: trying block %llu, ind %d\n", 
			(unsigned long long)start_block, start_ind);
		new_inode= inode_alloc_in_block(start_block, start_ind,
			new_inop, new_bufp, is_dir, 0/*!check_free*/);
		if (new_inode)
		{
			*new_inodep= new_inode;
			return;
		}
	}

	/* Try the next block as well, unless it is a directory */
	start_block++;
	if (!is_dir && start_block < inode_blocks)
	{
		printf("inode_alloc: trying block %llu\n",
			(unsigned long long)start_block);
		new_inode= inode_alloc_in_block(start_block, 0, new_inop,
			new_bufp, is_dir, 0/*!check_free*/);
		if (new_inode)
		{
			*new_inodep= new_inode;
			return;
		}
	}

	for (i= 0; i<64; i++)
	{
		os_random(&block, sizeof(block));
		block %= inode_blocks;

		printf("inode_alloc: trying random block %llu\n",
			(unsigned long long)block);
		new_inode= inode_alloc_in_block(block, 0, new_inop,
			new_bufp, is_dir, 1/*check_free*/);
		if (new_inode)
		{
			*new_inodep= new_inode;
			return;
		}
	}

	fatal("inode_alloc: not implemented");
}

static uint64_T inode_alloc_in_block(uint64_T block, unsigned ind,
	sef_inode_T **new_inop, buf_T **new_bufp, int is_dir, int check_free)
{
	int i;
	unsigned block_size, inodes_per_block, min_free, free_count;
	uint64_T res_inode;
	buf_T *buf;
	sef_inode_T *inop;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	inop= (sef_inode_T *)buf_data_ptr(buf);

	res_inode= 0;
	*new_inop= NULL;	/* Just in case */
	*new_bufp= NULL;	/* Just in case */

	if (check_free)
	{
		min_free= inodes_per_block/2;

		for (i= 0, free_count=0;
			i<inodes_per_block && free_count<min_free; i++)
		{
			if (inop[i].sei_nlink == 0)
				free_count++;
		}
		if (free_count < min_free)
			goto bail;
	}

	for (; ind < inodes_per_block; ind++, inop++)
	{
		if (inop->sei_nlink == 0)
		{
			/* Found one. */
			res_inode= block*inodes_per_block + ind;
			printf(
			"inode_alloc_in_block: found unused inode %llu\n",
				(unsigned long long)res_inode);

			/* Claim the inode */
			make_writable(buf, NULL);
			memset(inop, '\0', sizeof(*inop));
			inop->sei_nlink= 1;
			inop->sei_mode= is_dir ? SIM_DIRECTORY : SIM_REGULAR;
			*new_inop= inop; inop= NULL;
			*new_bufp= buf; buf= NULL;

			state.checkpoint->secp_inodes++;

			break;
		}
	}

bail:
	if (buf)
	{
		/* Nothing found */
		buf_unlock(buf);
	}

	/* res_inode has the result */
	return res_inode;
}

static void link_file(int argc, char *argv[])
{
	int r;
	uint64_T inode, dir_inode;
	char *name, *new_name;
	sef_inode_T *inop;

	buf_T *buf= NULL;
	int in_transaction= 0;
	char *last_name= NULL;

	if (argc != 3)
	{
		printf("Usage: link <file> <new file>\n");
		goto fail;
	}

	name= argv[1];
	new_name= argv[2];

	r= resolve_path(state.cwd, name, &inode);
	if (r != 0)
		goto fail;

	get_inode(inode, &inop, &buf);
	if ((inop->sei_mode & SIM_TYPE) != SIM_REGULAR)
	{
		printf("trunc: not a file\n");

		inop= NULL;
		goto fail;
	}

	r= last_dir(state.cwd, new_name, &dir_inode, &last_name);
	if (r != 0)
		goto fail;

	transaction_start();
	in_transaction= 1;

	r= dir_insert(dir_inode, last_name, inode);
	if (r != 0)
		goto fail;

	/* Increment link count */
	make_writable(buf, NULL);
	inop->sei_nlink++;

	inop= NULL;
	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;

	free(last_name);
	last_name= NULL;

	transaction_end();
	in_transaction= 0;

	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
	if (buf)
	{
		buf_unlock(buf);
		buf= NULL;
	}
	if (last_name)
	{
		free(last_name);
		last_name= NULL;
	}
}

static void write_file(int argc, char *argv[])
{
	int r, got_eof;
	unsigned block_size, inodes_per_block, boff;
	uint64_T b, dir_inode, file_inode, size;
	char *in_name, *out_name;
	uint8_T *cp;
	buf_T *inode_buf, *block_buf;
	sef_inode_T *file_inop;
	lbptr_T lbptr;

	int in_transaction= 0;
	FILE *fp= NULL;
	char *name= NULL;

	if (argc != 3)
	{
		printf("Usage: write <local file> <SEF file>\n");
		goto fail;
	}

	in_name= argv[1];
	out_name= argv[2];

	fp= fopen(in_name, "rb");
	if (fp == NULL)
	{
		printf("write_file: unable to open '%s'\n", in_name);
		goto fail;
	}

	r= last_dir(state.cwd, out_name, &dir_inode, &name);
	if (r != 0)
		goto fail;

	transaction_start();
	in_transaction= 1;

	/* insert_name returns a locked, write buf */
	r= insert_name(dir_inode, name, &file_inode, &file_inop, &inode_buf,
		0/*!is_dir*/);
	if (r != 0)
	{
		printf("write_file: unable to insert '%s'\n", out_name);
		goto fail;
	}

	free(name); name= NULL;

	printf("write_file: file_inode = %llu\n",
		(unsigned long long)file_inode);

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	got_eof= 0;
	for (b= 0;; b++)
	{
		lbptr= lbuf_mkptr(LT_DATA, 0, file_inode, 0, b);
		block_buf= lbuf_alloc(lbptr, block_size);
		buf_lock(block_buf);

		boff= 0;
		cp= buf_data_ptr(block_buf);
		while(boff < block_size)
		{
			r= fread(cp+boff, 1, block_size-boff, fp);
			if (r != 0)
			{
				assert(r > 0);
				assert(r <= block_size-boff);
				boff += r;
				continue;
			}

			if (ferror(fp))
			{
				fatal("error reading from local file '%s': %s",
					in_name, strerror(errno));
			}
			assert(feof(fp));
			got_eof= 1;
			break;
		}
		cp= NULL;

		if (got_eof)
		{
			size= b*block_size + boff;
			break;
		}

		buf_setvalid(block_buf);
		make_writable(block_buf, file_inop);
		buf_unlock(block_buf);
		buf_release(block_buf);
		buf_release_write(block_buf);
		block_buf= NULL;
	}

	fclose(fp);
	fp= NULL;

	if (size <= sizeof(file_inop->sei_blkptrs))
	{
		if (size)
		{
		    memcpy(file_inop->sei_blkptrs, buf_data_ptr(block_buf),
			size);
		    printf("write_file(imm): got bytes:");
		    { int i; for(i= 0; i<size; i++)
			printf(" %02x",
				((unsigned char *)file_inop->sei_blkptrs)[i]);
		    }
		    printf("\n");
		}
		file_inop->sei_flags |= SIF_IMMEDIATE;
	}
	else
	{
		if (boff < block_size)
		{
			/* Wipe rest of block */
			memset(buf_data_ptr(block_buf) + boff, '\0',
				block_size-boff);
		}
		buf_setvalid(block_buf);
		make_writable(block_buf, file_inop);
		buf_release_write(block_buf);
	}

	file_inop->sei_size= size;
	file_inop= NULL;

	buf_release_write(inode_buf);
	buf_unlock(inode_buf);
	inode_buf= NULL;

	buf_unlock(block_buf);
	buf_release(block_buf);
	block_buf= NULL;
	transaction_end();
	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
	if (fp)
	{
		fclose(fp);
		fp= NULL;
	}
	if (name)
	{
		free(name);
		name= NULL;
	}
}

static void remove_file(int argc, char *argv[])
{
	int r;
	uint64_T dir_inode, file_inode;
	char *name;
	sef_inode_T *inop;

	char *last_name= NULL;
	buf_T *buf= NULL;
	int in_transaction= 0;

	if (argc != 2)
	{
		printf("Usage: rm <file>\n");
		goto fail;
	}

	name= argv[1];

	r= last_dir(state.cwd, name, &dir_inode, &last_name);
	if (r != 0)
		goto fail;

	r= dir_lookup(dir_inode, last_name, &file_inode);
	if (r != 0)
		goto fail;

	get_inode(file_inode, &inop, &buf);
	if ((inop->sei_mode & SIM_TYPE) != SIM_REGULAR)
	{
		printf("rm: not a file\n");

		inop= NULL;
		buf_unlock(buf);
		buf= NULL;
		goto fail;
	}

	transaction_start();
	in_transaction= 1;

	r= dir_remove(dir_inode, last_name);
	assert (r == 0);

	make_writable(buf, NULL);
	if (inop->sei_nlink > 1)
		inop->sei_nlink--;
	else
	{
		truncate_inode(file_inode, inop, buf);
		memset(inop, '\0', sizeof(*inop));
		state.checkpoint->secp_inodes--;
	}
	buf_release_write(buf);

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;

	free(last_name);
	last_name= NULL;

	transaction_end();

	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
	if (last_name)
	{
		free(last_name);
		last_name= NULL;
	}
	if (buf)
	{
		buf_unlock(buf);
		buf= NULL;
	}
}

static void truncate_file(int argc, char *argv[])
{
	int r;
	uint64_T inode;
	char *name;
	buf_T *buf;
	sef_inode_T *inop;

	int in_transaction= 0;

	if (argc != 2)
	{
		printf("Usage: trunc <file>\n");
		goto fail;
	}

	name= argv[1];

	r= resolve_path(state.cwd, name, &inode);
	if (r != 0)
		goto fail;

	get_inode(inode, &inop, &buf);
	if ((inop->sei_mode & SIM_TYPE) != SIM_REGULAR)
	{
		printf("trunc: not a file\n");

		inop= NULL;
		buf_unlock(buf);
		buf= NULL;
		goto fail;
	}

	transaction_start();
	in_transaction= 1;

	truncate_inode(inode, inop, buf);

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;

	transaction_end();
	in_transaction= 0;

	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
}

static void unlink_file(int argc, char *argv[])
{
	int r;
	uint64_T dir_inode, file_inode;
	char *name;
	sef_inode_T *inop;

	char *last_name= NULL;
	buf_T *buf= NULL;
	int in_transaction= 0;

	/* Unlink is almost like remove, except instead of actually deleting
	 * the it links it from the UNREF inode.
	 */

	if (argc != 2)
	{
		printf("Usage: unlink <file>\n");
		goto fail;
	}

	name= argv[1];

	r= last_dir(state.cwd, name, &dir_inode, &last_name);
	if (r != 0)
		goto fail;

	r= dir_lookup(dir_inode, last_name, &file_inode);
	if (r != 0)
		goto fail;

	get_inode(file_inode, &inop, &buf);
	if ((inop->sei_mode & SIM_TYPE) != SIM_REGULAR)
	{
		printf("unlink: not a file\n");

		inop= NULL;
		buf_unlock(buf);
		buf= NULL;
		goto fail;
	}

	transaction_start();
	in_transaction= 1;

	r= dir_remove(dir_inode, last_name);
	assert (r == 0);

	if (inop->sei_nlink > 1)
	{
		make_writable(buf, NULL);
		inop->sei_nlink--;
		buf_release_write(buf);
	}
	else
		unref_add(file_inode);

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;

	free(last_name);
	last_name= NULL;

	transaction_end();

	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
	if (last_name)
	{
		free(last_name);
		last_name= NULL;
	}
	if (buf)
	{
		buf_unlock(buf);
		buf= NULL;
	}
}

static void unref_clean(int argc, char *argv[])
{
	int i, j, level, type;
	uint64_T offset;
	buf_T *buf;
	sef_inode_T *inop;
	uint8_T *cp;
	uint64_T *p;
	lbptr_T lbptr;

	int in_transaction= 0;

	if (argc != 1)
	{
		printf("Usage: clean-unref\n");
		goto fail;
	}

	get_inode(SEF_UNREF_INODE, &inop, &buf);

	transaction_start();
	in_transaction= 1;

	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		make_writable(buf, NULL);

		cp= (uint8_T *)inop->sei_blkptrs;
		for (offset= 0; offset < inop->sei_size; offset += sizeof(*p))
		{
			p= (uint64_T *)(cp+offset);
			if (!*p)
				continue;
			unref_clean_inode(*p);
			*p= 0;
		}

		buf_release_write(buf);
	}
	else
	{
		for (i= 0; i<SEF_INODE_BLKPTRS; i++)
		{
			if (inop->sei_blkptrs[i].sebp_block == 0)
				continue;	/* Nothing here */

			/* Compute logical block pointer */
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
			lbptr= lbuf_mkptr(type, 0, SEF_UNREF_INODE, level,
				offset);

			if (level > 0)
				unref_clean_index_block(lbptr, inop);
			else
				unref_clean_data_block(lbptr, inop);
		}
	}

	truncate_inode(SEF_UNREF_INODE, inop, buf);

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;

	transaction_end();
	in_transaction= 0;

	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
}

static void make_dir(int argc, char *argv[])
{
	int r;
	unsigned space;
	uint64_T dir_inode, new_inode, size;
	char *name;
	buf_T *new_inode_buf, *dir_inode_buf;
	sef_inode_T *new_inop, *dir_inop;
	sef_dirent_T dot_dotdot[2];

	int in_transaction= 0;

	if (argc != 2)
	{
		printf("Usage: mkdir <dir>\n");
		goto fail;
	}

	name= argv[1];

	printf("make_dir: before do_path:\n");
	buf_print_lbptr(lbuf_mkptr(LT_INODE, 0, 0, 0, 2));
	printf("\n");

	r= do_path(state.cwd, &dir_inode, &name);
	if (r != 0)
		goto fail;

	printf("make_dir: after do_path:\n");
	buf_print_lbptr(lbuf_mkptr(LT_INODE, 0, 0, 0, 2));
	printf("\n");

	transaction_start();
	in_transaction= 1;

	printf("make_dir: before insert_name:\n");
	buf_print_lbptr(lbuf_mkptr(LT_INODE, 0, 0, 0, 2));
	printf("\n");

	/* insert_name returns a locked, writable buf */
	r= insert_name(dir_inode, name, &new_inode, &new_inop, &new_inode_buf,
		1 /*is_dir*/);
	if (r != 0)
	{
		printf("mkdir: unable to insert '%s'\n", name);
		goto fail;
	}

	printf("make_dir: after insert_name:\n");
	buf_print_lbptr(lbuf_mkptr(LT_INODE, 0, 0, 0, 2));
	printf("\n");

	printf("mkdir: new_inode = %llu\n", (unsigned long long)new_inode);

	/* Insert '.' and '..' in the new directory */
	assert(sizeof(dot_dotdot[0]) == 16);
	dot_dotdot[0].sed_inode= new_inode;
	dot_dotdot[0].sed_extra= 0;
	strlcpy((char *)dot_dotdot[0].sed_name, ".",
		sizeof(dot_dotdot[0].sed_name));
	dot_dotdot[1].sed_inode= dir_inode;
	dot_dotdot[1].sed_extra= 0;
	strlcpy((char *)dot_dotdot[1].sed_name, "..",
		sizeof(dot_dotdot[1].sed_name));

	size= sizeof(dot_dotdot);

	/* Amount of space */
	space= SEF_INODE_SIZE - offsetof(sef_inode_T, sei_blkptrs[0]);

	/* There is enough space */
	assert(size <= space);

	memcpy(new_inop->sei_blkptrs, dot_dotdot, size);

	assert(new_inop->sei_mode == SIM_DIRECTORY);
	new_inop->sei_nlink++;
	new_inop->sei_size= size;
	new_inop->sei_flags= SIF_IMMEDIATE;

	/* Release the new inode */
	new_inop= NULL;
	buf_release_write(new_inode_buf);
	buf_unlock(new_inode_buf);
	new_inode_buf= NULL;

	/* There is one extra reference to dir_inode */
	get_inode(dir_inode, &dir_inop, &dir_inode_buf);
	make_writable(dir_inode_buf, NULL);
	dir_inop->sei_nlink++;

	dir_inop= NULL;
	buf_release_write(dir_inode_buf);
	buf_unlock(dir_inode_buf);
	dir_inode_buf= NULL;

	transaction_end();
	return;

fail:
	if (in_transaction)
	{
		transaction_end();
		in_transaction= 0;
	}
}

static int do_path(uint64_T curr_inode, uint64_T *dir_inodep, char **name)
{
	if (strchr(*name, '/') == NULL)
	{
		/* Simple case */
		*dir_inodep= curr_inode;
		return 0;
	}
	fatal("do_path: not implemented");
}

static int resolve_path(uint64_T cwd, char *path, uint64_T *inodep)
{
	int r;
	size_t len;
	char *loc_path, *cp, *curr;
	uint64_T curr_dir;

	/* Just in case */
	*inodep= 0;
	loc_path= NULL;

	curr_dir= cwd;

	/* Absolute path or not */
	while (path[0] == '/')
	{
		curr_dir= SEF_ROOT_INODE;
		path++;
	}

	/* Copy path, it is better if we can make modifications */
	loc_path= strdup(path);

	len= strlen(loc_path);

	/* Trim trailing slashes */
	while (len > 0 && loc_path[len-1] == '/')
	{
		len--;
		loc_path[len]= '\0';
	}

	curr= loc_path;
	while (curr[0] != '\0')
	{
		cp= strchr(curr, '/');
		if (cp)
			*cp= '\0';
		r= dir_lookup(curr_dir, curr, &curr_dir);
		if (r != 0)
		{
			/* Something is wrong */
			free(loc_path); loc_path= NULL;
			return r;
		}

		if (!cp)
			break;
		curr= cp+1;
		while(curr[0] == '/')
			curr++;
	}

	*inodep= curr_dir;
	free(loc_path); loc_path= NULL;

	return 0;
}

static int last_dir(uint64_T cwd, char *path, uint64_T *dir_inodep,
	char **filenamep)
{
	int r;
	size_t len;
	char *loc_path, *cp, *curr;
	uint64_T curr_dir;

	/* Just in case */
	*dir_inodep= 0;
	*filenamep= NULL;
	loc_path= NULL;

	curr_dir= cwd;

	/* Absolute path or not */
	while (path[0] == '/')
	{
		curr_dir= SEF_ROOT_INODE;
		path++;
	}

	/* Copy path, it is better if we can make modifications */
	loc_path= strdup(path);

	len= strlen(loc_path);

	/* Trim trailing slashes */
	while (len > 0 && loc_path[len-1] == '/')
	{
		len--;
		loc_path[len]= '\0';
	}

	/* An empty string is fatal */
	if (len == 0)
	{
		free(loc_path); loc_path= NULL;
		return -1;
	}

	/* Find start of last component */
	cp= strchr(loc_path, '/');
	if (cp == NULL)
	{
		/* Simple case, just one component */
		*filenamep= loc_path;

		*dir_inodep= curr_dir;

		return 0;
	}

	curr= loc_path;
	while(cp)
	{
		*cp= '\0';
		r= dir_lookup(curr_dir, curr, &curr_dir);
		if (r != 0)
		{
			/* Something is wrong */
			free(loc_path); loc_path= NULL;
			return r;
		}
		curr= cp+1;
		while(curr[0] == '/')
			curr++;
		cp= strchr(curr, '/');
	}

	*dir_inodep= curr_dir;
	*filenamep= strdup(curr);
	free(loc_path); loc_path= NULL;

	return 0;
}

static int dir_lookup(uint64_T start_dir, char *name, uint64_T *res_inodep)
{
	int r;
	unsigned dir_chunk_size, offset, len, block_size, start, end;
	uint64_T size, block;
	uint8_T *p;
	sef_dirent_T *direntp;
	sef_inode_T *inop;
	buf_T *buf;
	lbptr_T lbptr;

	get_inode(start_dir, &inop, &buf);
	if ((inop->sei_mode & SIM_TYPE) != SIM_DIRECTORY)
	{
		/* Not what we want */
		inop= NULL;
		buf_unlock(buf); buf= NULL;
		return -1;
	}
	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		size= inop->sei_size;

		dir_chunk_size= sizeof(uint64_T);

		offset= 0;
		p= (uint8_T *)inop->sei_blkptrs;
		direntp= NULL;	/* lint */
		while (offset < size)
		{
			direntp= (sef_dirent_T *)(p+offset);
			printf(
	"dir_lookup(imm): dir %llu, offset %u, name '%s', inode %llu\n",
				(unsigned long long)start_dir,
				offset, direntp->sed_name,
				(unsigned long long)direntp->sed_inode);
			if (strcmp((char *)direntp->sed_name, name) == 0)
				break;

			len= sizeof(*direntp) +
				direntp->sed_extra*dir_chunk_size;
			offset += len;
		}
		if (offset < size)
		{
			*res_inodep= direntp->sed_inode;
			r= 0;
		}
		else
		{
			assert(offset == size);
			r= -1;
			printf(
			"dir_lookup: '%s' not found in directory %llu\n",
				name, (unsigned long long)start_dir);
		}
		direntp= NULL;
		inop= NULL;
		buf_unlock(buf); buf= NULL;
		return r;
	}

	size= inop->sei_size;

	/* Release inode, we only need size */
	inop= NULL;
	buf_unlock(buf); buf= NULL;

	block_size= state.super->ses_block_size;

	for (block= 0; block*block_size < size; block++)
	{
		start= 0;
		if (block == 0)
			start= sizeof(sef_dir_sum_T);
		end= block_size;
		if (block*block_size+end > size)
		{
			end= size - block*block_size;
			assert(end > start && end < block_size);
		}

		lbptr= lbuf_mkptr(LT_DATA, 0, start_dir, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		p= buf_data_ptr(buf);

		for (offset= start; offset < end;
			offset += sizeof(sef_dirent_T) + direntp->sed_extra*8)
		{
			direntp= (sef_dirent_T *)(p+offset);
			if (direntp->sed_inode == 0)
				continue;
			if (strcmp((char *)direntp->sed_name, name) == 0)
			{
				*res_inodep= direntp->sed_inode;

				direntp= NULL;
				buf_unlock(buf); buf= NULL;

				return 0;
			}
		}

		direntp= NULL;
		buf_unlock(buf); buf= NULL;
	}
	printf("dir_lookup: '%s' not found in directory %llu\n",
		name, (unsigned long long)start_dir);
	return -1;
}

static int dir_insert(uint64_T dir_inode, char *name, uint64_T new_inode)
{
	unsigned block_size, inodes_per_block, ind, req_len, req_extra,
		start, end, offset, len, rem_len;
	uint64_T block, empty_offset;
	uint8_T *cp;
	buf_T *ino_buf, *buf;
	sef_inode_T *inop;
	sef_dirent_T *dirp, *rem_dirp;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	block= dir_inode / inodes_per_block;
	ind= dir_inode % inodes_per_block;

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
	ino_buf= read_block(lbptr, block_size);
	buf_lock(ino_buf);
	buf_release(ino_buf);
	inop= (sef_inode_T *)buf_data_ptr(ino_buf);

	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		/* Special version for immediate data */
		/* Note, insert_name_imm gets the read reference */
		return dir_insert_imm(ino_buf, dir_inode, name, new_inode);
	}

	/* Compute size requirements */
	req_len= offsetof(sef_dirent_T, sed_name) + strlen(name) + 1;
	if (req_len % 8)
		req_len += 8-(req_len%8);
	req_extra= (req_len-sizeof(sef_dirent_T))/8;

	empty_offset= 0;

	/* Find space and check if name already exists */
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

		lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		cp= buf_data_ptr(buf);

		for (offset= start; offset < end;
			offset += sizeof(sef_dirent_T) + dirp->sed_extra*8)
		{
			dirp= (sef_dirent_T *)(cp+offset);
			if (dirp->sed_extra < req_extra)
			{
				/* Too small to be of interest. */
				continue;
			}
			if (dirp->sed_inode == 0)
			{
				if (empty_offset == 0)
				{
					/* Take the first empty slot */
					empty_offset= block*block_size+offset;
					assert(empty_offset != 0);
				}
				continue;
			}
			if (strcmp((char *)dirp->sed_name, name) == 0)
			{
				dirp= NULL;
				buf_unlock(buf);
				buf= NULL;

				buf_unlock(ino_buf);
				ino_buf= NULL;

				return -1;
			}
		}

		dirp= NULL;
		buf_unlock(buf);
		buf= NULL;
	}

	if (empty_offset != 0)
	{
		block= empty_offset / block_size;
		offset= empty_offset % block_size;

		lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		make_writable(buf, inop);

		cp= buf_data_ptr(buf);
		dirp= (sef_dirent_T *)(cp+offset);
		if (dirp->sed_extra >= req_extra+2)
		{
			rem_len= 8*(dirp->sed_extra-req_extra);
			rem_dirp= (sef_dirent_T *)(cp+offset+req_len);
			memset(rem_dirp, '\0', rem_len);
			rem_dirp->sed_extra= (rem_len-sizeof(sef_dirent_T))/8;
		}

		memset(dirp, '\0', req_len);
		dirp->sed_inode= new_inode;
		dirp->sed_extra= req_extra;
		strcpy((char *)dirp->sed_name, name);

		cp= NULL;
		dirp= NULL;
		buf_release_write(buf);
		buf_unlock(buf);
		buf= NULL;

		inop= NULL;
		buf_unlock(ino_buf);
		ino_buf= NULL;

		return 0;
	}

	/* Try to extend the last block */
	block= inop->sei_size / block_size;
	offset= inop->sei_size % block_size;

	lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	make_writable(buf, inop);

	if (offset + req_len > block_size)
	{
		/* Create empty entry that fills up the current block */
		len= block_size-offset;
		assert(len >= sizeof(sef_dirent_T));
		assert(len % 8 == 0);

		cp= buf_data_ptr(buf);
		dirp= (sef_dirent_T *)(cp+offset);
		memset(dirp, '\0', len);
		dirp->sed_inode= 0;
		dirp->sed_extra= (len-sizeof(sef_dirent_T))/8;

		inop->sei_size += len;

		cp= NULL;
		dirp= NULL;
		buf_release_write(buf);
		buf_unlock(buf);
		buf= NULL;

		/* Move on to the next block */
		block= inop->sei_size / block_size;
		offset= inop->sei_size % block_size;

		lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		make_writable(buf, inop);
	}

	if (offset + req_len + sizeof(sef_dirent_T) > block_size)
	{
		req_len= block_size-offset;
		assert(req_len % 8 == 0);
		req_extra= (req_len-sizeof(sef_dirent_T))/8;
	}

	cp= buf_data_ptr(buf);
	dirp= (sef_dirent_T *)(cp+offset);
	memset(dirp, '\0', req_len);
	dirp->sed_inode= new_inode;
	dirp->sed_extra= req_extra;
	strcpy((char *)dirp->sed_name, name);

	cp= NULL;
	dirp= NULL;
	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;

	make_writable(ino_buf, NULL);

	inop->sei_size += req_len;

	inop= NULL;
	buf_release_write(ino_buf);
	buf_unlock(ino_buf);
	ino_buf= NULL;

	return 0;
}

static int dir_insert_imm(buf_T *buf, uint64_T dir_inode, char *name,
	uint64_T new_inode)
{
	unsigned size, offset, len, dir_chunk_size, totspace, ind,
		block_size, inodes_per_block;
	uint8_T *p;
	sef_inode_T *inoptrs, *inop;
	sef_dirent_T *direntp;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	ind= dir_inode % inodes_per_block;

	inoptrs= (sef_inode_T *)buf_data_ptr(buf);
	inop= &inoptrs[ind];

	assert(inop->sei_flags & SIF_IMMEDIATE);
	size= inop->sei_size;
	if (size == 0)
	{
		/* A deleted directory that is still CWD */
		goto fail;
	}

	dir_chunk_size= sizeof(uint64_T);

	offset= 0;
	p= (uint8_T *)inop->sei_blkptrs;
	while (offset < size)
	{
		direntp= (sef_dirent_T *)(p+offset);
		if (strcmp((char *)direntp->sed_name, name) == 0)
		{
			/* Name already exists */
			goto fail;
		}

		len= sizeof(*direntp) + direntp->sed_extra*dir_chunk_size;
		offset += len;
	}

	assert(offset == size);

	/* Is there space for the new entry */
	len= offsetof(sef_dirent_T, sed_name) + strlen(name) + 1;
	if (len % dir_chunk_size)
		len += dir_chunk_size - (len % dir_chunk_size);

	totspace= sizeof(inop->sei_blkptrs);
	if (offset + len > totspace)
	{
		/* Move existing entries to a block and try a regular 
		 * insert.
		 */
		make_writable(buf, NULL);
		dir_imm2block(dir_inode, inop);
		buf_unlock(buf);
		buf_release_write(buf);
		buf= NULL;

		/* Try insert_name again */
		return dir_insert(dir_inode, name, new_inode);
	}

	/* Make block writable before allocating the new inode. */
	make_writable(buf, NULL);

	direntp= (sef_dirent_T *)(p+offset);
	memset(direntp, '\0', len);	/* Can't hurt */
	direntp->sed_inode= new_inode;
	direntp->sed_extra= len/dir_chunk_size-2;
	strcpy((char *)direntp->sed_name, name);
	inop->sei_size += len;

	buf_unlock(buf);
	buf_release_write(buf);

	return 0;

fail:
	inop= inoptrs= NULL;
	buf_unlock(buf);
	buf= NULL;
	return -1;
}

static int insert_name(uint64_T dir_inode, char *name,
	uint64_T *new_inodep, sef_inode_T **new_inop,
	buf_T **new_bufp, int is_dir)
{
	unsigned block_size, inodes_per_block, ind, req_len, req_extra,
		start, end, offset, len, rem_len;
	uint64_T block, prev_ino, empty_offset, empty_prev;
	uint8_T *cp;
	buf_T *ino_buf, *buf;
	sef_inode_T *inop;
	sef_dirent_T *dirp, *rem_dirp;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	block= dir_inode / inodes_per_block;
	ind= dir_inode % inodes_per_block;

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
	ino_buf= read_block(lbptr, block_size);
	buf_lock(ino_buf);
	buf_release(ino_buf);
	inop= (sef_inode_T *)buf_data_ptr(ino_buf);

	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		/* Special version for immediate data */
		/* Note, insert_name_imm gets the read reference */
		return insert_name_imm(ino_buf, dir_inode, name, new_inodep,
			new_inop, new_bufp, is_dir);
	}

	/* Compute size requirements */
	req_len= offsetof(sef_dirent_T, sed_name) + strlen(name) + 1;
	if (req_len % 8)
		req_len += 8-(req_len%8);
	req_extra= (req_len-sizeof(sef_dirent_T))/8;

	prev_ino= 0;	/* lint */
	empty_offset= 0;
	empty_prev= 0;

	/* Find space and check if name already exists */
	for (block= 0; block*block_size < inop->sei_size; block++)
	{
		start= 0;
		if (block == 0)
			start= sizeof(sef_dir_sum_T);
		end= block_size;
		if (block*block_size+end > inop->sei_size)
		{
			end= inop->sei_size - block*block_size;
			printf("insert_name: adjusted end: start %u, end %u, block_size %u, block %llu, size %llu\n",
				start, end, block_size,
				(unsigned long long)block,
				(unsigned long long)inop->sei_size);
			assert(end > start && end < block_size);
		}

		lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		cp= buf_data_ptr(buf);

		for (offset= start; offset < end;
			offset += sizeof(sef_dirent_T) + dirp->sed_extra*8)
		{
			dirp= (sef_dirent_T *)(cp+offset);
			if (dirp->sed_inode != 0 &&
				strcmp((char *)dirp->sed_name, "..") != 0)
			{
				prev_ino= dirp->sed_inode;
			}
			if (dirp->sed_extra < req_extra)
			{
				/* Too small to be of interest. */
				continue;
			}
			if (dirp->sed_inode == 0)
			{
				if (empty_offset == 0)
				{
					/* Take the first empty slot */
					empty_offset= block*block_size+offset;
					assert(empty_offset != 0);
					empty_prev= prev_ino;
					assert(empty_prev != 0);
				}
				continue;
			}
			if (strcmp((char *)dirp->sed_name, name) == 0)
			{
				dirp= NULL;
				buf_unlock(buf);
				buf= NULL;

				buf_unlock(ino_buf);
				ino_buf= NULL;

				return -1;
			}
		}

		dirp= NULL;
		buf_unlock(buf);
		buf= NULL;
	}

	if (empty_offset != 0)
	{
		block= empty_offset / block_size;
		offset= empty_offset % block_size;

		lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		make_writable(buf, inop);

		cp= buf_data_ptr(buf);
		dirp= (sef_dirent_T *)(cp+offset);
		if (dirp->sed_extra >= req_extra+2)
		{
			rem_len= 8*(dirp->sed_extra-req_extra);
			rem_dirp= (sef_dirent_T *)(cp+offset+req_len);
			memset(rem_dirp, '\0', rem_len);
			rem_dirp->sed_extra= (rem_len-sizeof(sef_dirent_T))/8;
		}

		inode_alloc(empty_prev, new_inodep, new_inop, new_bufp, is_dir);

		memset(dirp, '\0', req_len);
		dirp->sed_inode= *new_inodep;
		dirp->sed_extra= req_extra;
		strcpy((char *)dirp->sed_name, name);

		cp= NULL;
		dirp= NULL;
		buf_release_write(buf);
		buf_unlock(buf);
		buf= NULL;

		inop= NULL;
		buf_unlock(ino_buf);
		ino_buf= NULL;

		return 0;
	}

	/* Try to extend the last block */
	block= inop->sei_size / block_size;
	offset= inop->sei_size % block_size;

	lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	make_writable(buf, inop);

	if (offset + req_len > block_size)
	{
		/* Create empty entry that fills up the current block */
		len= block_size-offset;
		assert(len >= sizeof(sef_dirent_T));
		assert(len % 8 == 0);

		cp= buf_data_ptr(buf);
		dirp= (sef_dirent_T *)(cp+offset);
		memset(dirp, '\0', len);
		dirp->sed_inode= 0;
		dirp->sed_extra= (len-sizeof(sef_dirent_T))/8;

		inop->sei_size += len;

		cp= NULL;
		dirp= NULL;
		buf_release_write(buf);
		buf_unlock(buf);
		buf= NULL;

		/* Move on to the next block */
		block= inop->sei_size / block_size;
		offset= inop->sei_size % block_size;

		lbptr= lbuf_mkptr(LT_DATA, 0, dir_inode, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		make_writable(buf, inop);
	}

	if (offset + req_len + sizeof(sef_dirent_T) > block_size)
	{
		req_len= block_size-offset;
		assert(req_len % 8 == 0);
		req_extra= (req_len-sizeof(sef_dirent_T))/8;
	}

	inode_alloc(prev_ino, new_inodep, new_inop, new_bufp, is_dir);

	cp= buf_data_ptr(buf);
	dirp= (sef_dirent_T *)(cp+offset);
	memset(dirp, '\0', req_len);
	dirp->sed_inode= *new_inodep;
	dirp->sed_extra= req_extra;
	strcpy((char *)dirp->sed_name, name);

	cp= NULL;
	dirp= NULL;
	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;

	make_writable(ino_buf, NULL);

	inop->sei_size += req_len;

	inop= NULL;
	buf_release_write(ino_buf);
	buf_unlock(ino_buf);
	ino_buf= NULL;

	return 0;
}

static int insert_name_imm(buf_T *buf, uint64_T dir_inode, char *name,
	uint64_T *new_inodep, sef_inode_T **new_inop, buf_T **new_bufp,
	int is_dir)
{
	unsigned size, offset, len, dir_chunk_size, totspace, ind,
		block_size, inodes_per_block;
	uint8_T *p;
	sef_inode_T *inoptrs, *inop;
	sef_dirent_T *direntp;
	uint64_T prev_ino;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	ind= dir_inode % inodes_per_block;

	inoptrs= (sef_inode_T *)buf_data_ptr(buf);
	inop= &inoptrs[ind];

	assert(inop->sei_flags & SIF_IMMEDIATE);
	size= inop->sei_size;
	if (size == 0)
	{
		/* A deleted directory that is still CWD */
		goto fail;
	}

	dir_chunk_size= sizeof(uint64_T);

	offset= 0;
	p= (uint8_T *)inop->sei_blkptrs;
	prev_ino= 0;
	while (offset < size)
	{
		direntp= (sef_dirent_T *)(p+offset);
		if (strcmp((char *)direntp->sed_name, name) == 0)
		{
			/* Name already exists */
			goto fail;
		}

		/* Keep track of the last inode to have a starting point
		 * for allocating the new one. Skip '..'.
		 */
		if (strcmp((char *)direntp->sed_name, "..") != 0)
			prev_ino= direntp->sed_inode;

		len= sizeof(*direntp) + direntp->sed_extra*dir_chunk_size;
		offset += len;
	}

	assert(offset == size);
	assert(prev_ino != 0);

	/* Is there space for the new entry */
	len= offsetof(sef_dirent_T, sed_name) + strlen(name) + 1;
	if (len % dir_chunk_size)
		len += dir_chunk_size - (len % dir_chunk_size);

	totspace= sizeof(inop->sei_blkptrs);
	if (offset + len > totspace)
	{
		/* Move existing entries to a block and try a regular 
		 * insert.
		 */
		make_writable(buf, NULL);
		dir_imm2block(dir_inode, inop);
		buf_unlock(buf);
		buf_release_write(buf);
		buf= NULL;

		/* Try insert_name again */
		return insert_name(dir_inode, name, new_inodep,
			new_inop, new_bufp, is_dir);
	}

	/* Make block writable before allocating the new inode. */
	make_writable(buf, NULL);

	printf("insert_name_imm: should allocate near inode %llu\n",
		(unsigned long long)prev_ino);

	inode_alloc(prev_ino, new_inodep, new_inop, new_bufp, is_dir);

	direntp= (sef_dirent_T *)(p+offset);
	memset(direntp, '\0', len);	/* Can't hurt */
	direntp->sed_inode= *new_inodep;
	direntp->sed_extra= len/dir_chunk_size-2;
	strcpy((char *)direntp->sed_name, name);
	inop->sei_size += len;

	buf_unlock(buf);
	buf_release_write(buf);

	return 0;

fail:
	inop= inoptrs= NULL;
	buf_unlock(buf);
	buf= NULL;
	return -1;
}

static void dir_imm2block(uint64_T inode, sef_inode_T *inop)
{
	unsigned block_size, offset;
	uint8_T *cp;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	lbptr= lbuf_mkptr(LT_DATA, 0, inode, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);

	/* assert that it fits */
	assert(sizeof(sef_dir_sum_T) + inop->sei_size + 2*sizeof(uint64_T) <=
		block_size);

	cp= buf_data_ptr(buf);
	memset(cp, '\0', block_size);
	offset= sizeof(sef_dir_sum_T);
	memcpy(cp+offset, inop->sei_blkptrs, inop->sei_size);

	memset(inop->sei_blkptrs, '\0', sizeof(inop->sei_blkptrs));
	inop->sei_flags &= ~SIF_IMMEDIATE;

	buf_setvalid(buf);
	make_writable(buf, inop);

	inop->sei_size += sizeof(sef_dir_sum_T);

	buf_release_write(buf);
	buf_unlock(buf);
}

static int dir_remove(uint64_T start_dir, char *name)
{
	int r;
	unsigned dir_chunk_size, offset, prev_offset, len, prev_len,
		block_size, start, end, remlen;
	uint64_T size, block;
	uint8_T *p;
	sef_dirent_T *direntp, *prev_direntp, *next_direntp;
	sef_inode_T *inop;
	buf_T *buf;
	lbptr_T lbptr;

	get_inode(start_dir, &inop, &buf);
	if ((inop->sei_mode & SIM_TYPE) != SIM_DIRECTORY)
	{
		/* Not what we want */
		inop= NULL;
		buf_unlock(buf); buf= NULL;
		return -1;
	}
	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		size= inop->sei_size;

		dir_chunk_size= sizeof(uint64_T);

		offset= 0;
		p= (uint8_T *)inop->sei_blkptrs;
		direntp= NULL;	/* lint */
		while (offset < size)
		{
			direntp= (sef_dirent_T *)(p+offset);
			printf(
	"dir_remove(imm): dir %llu, offset %u, name '%s', inode %llu\n",
				(unsigned long long)start_dir,
				offset, direntp->sed_name,
				(unsigned long long)direntp->sed_inode);
			if (strcmp((char *)direntp->sed_name, name) == 0)
				break;

			len= sizeof(*direntp) +
				direntp->sed_extra*dir_chunk_size;
			offset += len;
		}
		if (offset >= size)
		{
			assert(offset == size);
			r= -1;
			printf(
			"dir_remove: '%s' not found in directory %llu\n",
				name, (unsigned long long)start_dir);
		}
		else
		{
			len= sizeof(*direntp) +
				direntp->sed_extra*dir_chunk_size;

			make_writable(buf, NULL);

			if (offset + len >= size)
			{
				assert(offset+len == size);
				memset(p+offset, '\0', len);
			}
			else
			{
				remlen= size - (offset + len);
				memmove(p+offset, p+offset+len, remlen);
				memset(p+offset+remlen, '\0', len);
			}

			inop->sei_size -= len;
			buf_release_write(buf);
			r= 0;
		}
		direntp= NULL;
		inop= NULL;
		buf_unlock(buf); buf= NULL;
		return r;
	}

	size= inop->sei_size;

	/* Release inode, we only need size */
	inop= NULL;
	buf_unlock(buf); buf= NULL;

	block_size= state.super->ses_block_size;

	p= NULL;	/* lint */
	direntp= NULL;	/* lint */
	offset= 0;	/* lint */
	end= 0;		/* lint */
	for (block= 0; block*block_size < size; block++)
	{
		start= 0;
		if (block == 0)
			start= sizeof(sef_dir_sum_T);
		end= block_size;
		if (block*block_size+end > size)
		{
			end= size - block*block_size;
			assert(end > start && end < block_size);
		}

		lbptr= lbuf_mkptr(LT_DATA, 0, start_dir, 0, block);
		buf= read_block(lbptr, block_size);
		buf_lock(buf);
		buf_release(buf);
		p= buf_data_ptr(buf);

		for (offset= start; offset < end;
			offset += sizeof(sef_dirent_T) + direntp->sed_extra*8)
		{
			direntp= (sef_dirent_T *)(p+offset);
			if (direntp->sed_inode == 0)
				continue;
			if (strcmp((char *)direntp->sed_name, name) == 0)
				break;
		}
		if (offset < end)
			break;

		direntp= NULL;
		buf_unlock(buf); buf= NULL;
	}

	if (block*block_size >= size)
	{
		printf("dir_remove: '%s' not found in directory %llu\n",
			name, (unsigned long long)start_dir);
		return -1;
	}

	make_writable(buf, NULL);

	direntp->sed_inode= 0;
	memset(direntp->sed_name, '\0', strlen(name));

	len= sizeof(sef_dirent_T) + direntp->sed_extra*8;
	next_direntp= (sef_dirent_T *)(p+offset+len);
	if (offset+len < end && next_direntp->sed_inode == 0)
		direntp->sed_extra += 2+next_direntp->sed_extra;

	start= 0;
	if (block == 0)
		start= sizeof(sef_dir_sum_T);
	end= offset;

	prev_len= 1;		/* lint */
	prev_direntp= NULL;	/* lint */
	for (prev_offset= start; prev_offset < end;
		prev_offset += prev_len)
	{
		prev_direntp= (sef_dirent_T *)(p+prev_offset);
		prev_len= sizeof(sef_dirent_T) + prev_direntp->sed_extra*8;
		if (prev_offset+prev_len == offset)
			break;
	}

	if (prev_offset+prev_len == offset)
	{
		if (prev_direntp->sed_inode == 0)
			prev_direntp->sed_extra += 2+direntp->sed_extra;
	}
	else
	{
		/* No previous entry, then we must at the start of a
		 * block.
		 */
		assert(offset == start);
	}

	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;

	return 0;
}

static void unref_add(uint64_T inode)
{
	unsigned block_size, totspace, offset, end;
	uint64_T block, size;
	sef_inode_T *inop;
	buf_T *dbuf, *ino_buf;
	uint8_T *cp;
	uint64_T *p;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	get_inode(SEF_UNREF_INODE, &inop, &ino_buf);

	if (inop->sei_size == 0 || (inop->sei_flags & SIF_IMMEDIATE))
	{
		size= inop->sei_size;

		/* Is there space for the new entry */
		totspace= sizeof(inop->sei_blkptrs);
		if (size + sizeof(*p) <= totspace)
		{
			/* Just add the inode number */
			p= (uint64_T *)(((uint8_T *)inop->sei_blkptrs)+size);
			*p= inode;
			make_writable(ino_buf, NULL);
			inop->sei_size += sizeof(*p);
			inop->sei_flags |= SIF_IMMEDIATE;
			buf_release_write(ino_buf);
			buf_unlock(ino_buf);

			return;
		}

		/* Move existing entries to a block and try a regular 
		 * insert.
		 */
		make_writable(ino_buf, NULL);
		unref_imm2block(inop);
		buf_release_write(ino_buf);
	}

	for (block= 0; block*block_size < inop->sei_size; block++)
	{
		end= block_size;
		if (block*block_size+end > inop->sei_size)
		{
			end= inop->sei_size - block*block_size;
			assert(end > 0 && end < block_size);
		}

		lbptr= lbuf_mkptr(LT_DATA, 0, SEF_UNREF_INODE, 0, block);
		dbuf= read_block(lbptr, block_size);
		buf_lock(dbuf);
		buf_release(dbuf);
		cp= buf_data_ptr(dbuf);

		for (offset= 0; offset < end; offset += sizeof(*p))
		{
			p= (uint64_T *)(cp+offset);
			if (*p != 0)
				continue;

			make_writable(dbuf, inop);

			*p= inode;

			buf_release_write(dbuf);
			buf_unlock(dbuf);
			dbuf= NULL;

			buf_unlock(ino_buf);
			ino_buf= NULL;

			return;
		}

		buf_unlock(dbuf);
		dbuf= NULL;
	}

	/* Try to extend the last block */
	block= inop->sei_size / block_size;
	offset= inop->sei_size % block_size;

	lbptr= lbuf_mkptr(LT_DATA, 0, SEF_UNREF_INODE, 0, block);
	dbuf= read_block(lbptr, block_size);
	buf_lock(dbuf);
	buf_release(dbuf);
	make_writable(dbuf, inop);

	cp= buf_data_ptr(dbuf);
	p= (uint64_T *)(cp+offset);
	*p= inode;

	cp= NULL;
	p= NULL;
	buf_release_write(dbuf);
	buf_unlock(dbuf);
	dbuf= NULL;

	make_writable(ino_buf, NULL);

	inop->sei_size += sizeof(*p);

	inop= NULL;
	buf_release_write(ino_buf);
	buf_unlock(ino_buf);
	ino_buf= NULL;
}

static void unref_imm2block(sef_inode_T *inop)
{
	unsigned block_size;
	uint8_T *cp;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;

	lbptr= lbuf_mkptr(LT_DATA, 0, SEF_UNREF_INODE, 0, 0);
	buf= lbuf_alloc(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);

	/* assert that it fits */
	assert(inop->sei_size <= block_size);

	cp= buf_data_ptr(buf);
	memset(cp, '\0', block_size);
	memcpy(cp, inop->sei_blkptrs, inop->sei_size);

	memset(inop->sei_blkptrs, '\0', sizeof(inop->sei_blkptrs));
	inop->sei_flags &= ~SIF_IMMEDIATE;

	buf_setvalid(buf);
	make_writable(buf, inop);

	buf_release_write(buf);
	buf_unlock(buf);
}

static void unref_clean_inode(uint64_T inode)
{
	sef_inode_T *inop;
	buf_T *buf;

	get_inode(inode, &inop, &buf);

	make_writable(buf, NULL);

	truncate_inode(inode, inop, buf);
	memset(inop, '\0', sizeof(*inop));
	state.checkpoint->secp_inodes--;

	buf_release_write(buf);

	inop= NULL;
	buf_unlock(buf);
	buf= NULL;
}

static void unref_clean_index_block(lbptr_T lbptr, sef_inode_T *inop)
{
	int i;
	unsigned block_size, ptrs_per_block;
	buf_T *buf;
	sef_blkptr_T *bp;
	lbptr_T child_lbptr;

	block_size= state.super->ses_block_size;
	ptrs_per_block= block_size / sizeof(sef_blkptr_T);

	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);

	assert(lbptr.lbp_level > 0);	/* Just to be sure */

	for (i= 0, bp= (sef_blkptr_T *)buf_data_ptr(buf); i< ptrs_per_block;
		i++, bp++)
	{
		if (!bp->sebp_block)
			continue;	/* Nothing here */

		if (lbptr.lbp_level > 1)
		{
			child_lbptr= lbuf_mkptr(LT_DATA_INDEX, 
				lbptr.lbp_space, lbptr.lbp_inode,
				lbptr.lbp_level-1,
				lbptr.lbp_offset*ptrs_per_block+i);
			unref_clean_index_block(child_lbptr, inop);
		}
		else
		{
			child_lbptr= lbuf_mkptr(LT_DATA, 
				lbptr.lbp_space, lbptr.lbp_inode,
				lbptr.lbp_level-1,
				lbptr.lbp_offset*ptrs_per_block+i);
			unref_clean_data_block(child_lbptr, inop);
		}
	}

	bp= NULL;
	buf_unlock(buf); buf= NULL;
}

static void unref_clean_data_block(lbptr_T lbptr, sef_inode_T *inop)
{
	unsigned block_size, offset;
	buf_T *buf;
	uint8_T *cp;
	uint64_T *p;

	block_size= state.super->ses_block_size;

	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);

	make_writable(buf, inop);

	cp= (uint8_T *)buf_data_ptr(buf);
	for (offset= 0; offset < block_size; offset += sizeof(*p))
	{
		p= (uint64_T *)(cp+offset);
		if (!*p)
			continue;
		unref_clean_inode(*p);
		*p= 0;
	}

	buf_release_write(buf);
	buf_unlock(buf);
	buf= NULL;
}

static void truncate_inode(uint64_T inode, sef_inode_T *inop, buf_T *inode_buf)
{
	int i, j, level, type, do_flush;
	uint64_T offset;
	buf_T *buf;
	lbptr_T lbptr;

	printf("truncate_inode: inode %llu, size %llu\n",
		(unsigned long long)inode,
		(unsigned long long)inop->sei_size);

	if (inop->sei_size == 0)
		return;		/* Nothing to do */

	if (inop->sei_flags & SIF_IMMEDIATE)
	{
		make_writable(inode_buf, NULL);

		/* Wipe space */
		memset(inop->sei_blkptrs, '\0', inop->sei_size);
		inop->sei_size= 0;

		buf_release_write(inode_buf);
		return;
	}

	/* We will need to write to the inode buffer */
	make_writable(inode_buf, NULL);

	/* Flush per block. For large files, scanning the buffer cache is
	 * more efficient.
	 */
	do_flush= 1;

	for (i= 0; i<SEF_INODE_BLKPTRS; i++)
	{
		if (inop->sei_blkptrs[i].sebp_block == 0)
			continue;	/* Nothing here */

		/* Compute logical block pointer */
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

		printf("truncate_inode: [%d]: ", i);
		print_ptr(lbptr);
		printf("\n");

		if (level > 0)
		{
			wipe_index_block(lbptr, inop, do_flush);
			assert(inop->sei_blkptrs[i].sebp_block == 0);
			continue;
		}

		buf= lbuf_lookup(lbptr);
		if (buf)
		{
			if (buf_is_writable(buf))
			{
				buf_setclean(buf);
				buf_release_write(inode_buf);
			}
			buf_setinvalid(buf);
			buf_release(buf);

		}

		free_block(inop->sei_blkptrs[i].sebp_block);
		inop->sei_blocks--;
		memset(&inop->sei_blkptrs[i], '\0',
			sizeof(inop->sei_blkptrs[i]));
	}

	inop->sei_size= 0;

	inop= NULL;
	buf_release_write(inode_buf); inode_buf= NULL;
}

static void wipe_index_block(lbptr_T lbptr, sef_inode_T *inop, int do_flush)
{
	int i, writable;
	unsigned block_size, ptrs_per_block, bpoff;
	buf_T *buf, *child_buf, *parent_buf;
	sef_blkptr_T *bp;
	lbptr_T child_lbptr, parent_lbptr;

	block_size= state.super->ses_block_size;
	ptrs_per_block= block_size / sizeof(sef_blkptr_T);

	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);

	writable= 0;	/* lint */

	assert(lbptr.lbp_level > 0);	/* Just to be sure */
	if (lbptr.lbp_level == 1)
	{
		writable= buf_is_writable(buf);

		/* If our buffer is writable then there may be child buffers
		 * that are also writable. Look at all child buffers. On
		 * the other hand, if this buffer is not writable then there
		 * are no writable child buffers.
		 */

		/* Also get a write reference of our own */
		make_writable(buf, NULL);
	}

	for (i= 0, bp= (sef_blkptr_T *)buf_data_ptr(buf); i< ptrs_per_block;
		i++, bp++)
	{
		if (!bp->sebp_block)
			continue;	/* Nothing here */

		if (lbptr.lbp_level > 1)
		{
			child_lbptr= lbuf_mkptr(LT_DATA_INDEX, 
				lbptr.lbp_space, lbptr.lbp_inode,
				lbptr.lbp_level-1,
				lbptr.lbp_offset*ptrs_per_block+i);
			wipe_index_block(child_lbptr, inop, do_flush);

			/* Block is now done */
			assert(bp->sebp_block == 0);
			continue;
		}

		if (writable || do_flush)
		{
			/* We need to take a look at the child buffer */
			child_lbptr= lbuf_mkptr(LT_DATA, 
				lbptr.lbp_space, lbptr.lbp_inode, 0,
				lbptr.lbp_offset*ptrs_per_block+i);
			child_buf= lbuf_lookup(child_lbptr);

			if (child_buf)
			{
				if (buf_is_writable(child_buf))
				{
					buf_setclean(child_buf);
					buf_release_write(buf);
				}
				buf_setinvalid(child_buf);
				buf_release(child_buf); child_buf= NULL;
			}
		}

		free_block(bp->sebp_block);
		inop->sei_blocks--;
		memset(bp, '\0', sizeof(&bp));
	}

	if (lbptr.lbp_level == 1)
	{
		/* Release the write reference we got */
		buf_release_write(buf);
	}

	/* Get the parent */
	parent_lbptr= get_parent(lbptr, &bpoff);
	parent_buf= read_block(parent_lbptr, block_size);
	buf_lock(parent_buf);
	buf_release(parent_buf);

	if (buf_is_writable(buf))
	{
		/* Mark our buffer as clean and drop the write ref on the
		 * parent.
		 */
		buf_setclean(buf);
		buf_release_write(parent_buf);
	}

	/* Mark the buffer as invalid, just in case */
	buf_setinvalid(buf);

	bp= NULL;
	buf_unlock(buf); buf= NULL;

	/* Make parent writable to clear block pointer */
	make_writable(parent_buf, NULL);

	bp= (sef_blkptr_T *)(((uint8_T *)buf_data_ptr(parent_buf))+bpoff);

	free_block(bp->sebp_block);
	inop->sei_blocks--;
	memset(bp, '\0', sizeof(*bp));

	buf_release_write(parent_buf);
	buf_unlock(parent_buf); parent_buf= NULL;
}

static void get_inode(uint64_T inode, sef_inode_T **inop, buf_T **bufp)
{
	unsigned block_size, inodes_per_block, ind;
	uint64_T block;
	buf_T *buf;
	lbptr_T lbptr;

	block_size= state.super->ses_block_size;
	inodes_per_block= block_size / SEF_INODE_SIZE;

	block= inode / inodes_per_block;
	ind= inode % inodes_per_block;

	lbptr= lbuf_mkptr(LT_INODE, 0, 0, 0, block);
	buf= read_block(lbptr, block_size);
	buf_lock(buf);
	buf_release(buf);
	*bufp= buf;
	*inop= &((sef_inode_T *)buf_data_ptr(buf))[ind];

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

static int cmp_u64(const void *v1, const void *v2)
{
	const uint64_T *p1, *p2;
	uint64_T u1, u2;

	p1= v1;
	p2= v2;

	u1= *p1;
	u2= *p2;

	if (u1 < u2)
		return -1;
	if (u1 > u2)
		return 1;
	return 0;
}

static char *fatal(char *fmt, ...)
{
	va_list ap;

	fflush(stdout);

	va_start(ap, fmt);
	fprintf(stderr, "sefc: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: sefc [ options ] <device>\n");
	exit(2);
}
