/*
sef/super.h

Created:        December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Super block definition
*/

#include <sef/blkptr.h>
#include <sef/inode.h>

typedef struct ses_argon2_params
{
	uint8_T sap_endian;	/* 0 for little endian, 1 for big endian */
	uint8_T sap_reserved1[3];
	uint32_T sap_parallelism;	/* [1..2^24-1] */
	uint32_T sap_iterations;	/* [1..2^32-1] */
	uint32_T sap_mem;		/* log2 of mem in kibibytes, at least
					 * 8*parallelism kibibytes, max
					 * 2^32-1 kibibytes.
				 	 */
	uint32_T sap_reserved2[4];
} ses_argon2_params_T;

typedef struct sef_super
{
	/* We store the argon2 salt directly. Then we 'encrypt' the
	 * argon2 paramters with AES in CBC mode with a zero IV just to
	 * scramble the data.
	 */
	uint8_T ses_argon2_salt[256 / 8];
	ses_argon2_params_T ses_argon2_params;

	/* Note that this hash is stored unencrypted, just signed */
	sef_hash_T ses_signed_hash;

	/* Encrypted data starts here */
	sef_iv_T ses_iv;
	sef_ptr_flags_T ses_flags;
	uint64_T ses_block;

	uint64_T ses_first_super_block;
	uint64_T ses_second_super_block;

	uint64_T ses_first_checkpoint_block;
	uint64_T ses_second_checkpoint_block;

	uint64_T ses_first_data_block;
	uint64_T ses_last_data_block;

	uint32_T ses_block_size;

	/* Height of the bitmap index */
	uint8_T	ses_bm_ind_levels;

	uint8_T ses_reserved1[3];

	/* For each blkptr in an inode, what is the index level. 0 for
	 * a direct block.
	 */
	uint8_T ses_inode_blkptrs[SEF_INODE_BLKPTRS];

	uint8_T ses_reserved2[3];	/* Pad to multiple of 8 bytes */

	uint8_T ses_disk_key[256 / 8];

	uint8_T ses_extra[288];
} sef_super_T;

#define SEF_SUPER_BLOCK_SIZE	512
