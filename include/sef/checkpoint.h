/*
sef/checkpoint.h

Created:        December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Checkpoint block definition
*/

#include <sef/blkptr.h>
#include <sef/inode.h>

#define SEF_BM_IND_MAX	4

typedef struct sef_checkpoint
{
	/* Note that this hash is stored unencrypted, just signed */
	sef_hash_T secp_signed_hash;

	/* Encrypted data starts here */
	sef_iv_T secp_iv;
	sef_ptr_flags_T secp_flags;
	uint64_T secp_block;

	/* Checkpoint sequence number. Even number use the first 
	 * checkpoint location, odd ones the second.
	 */
	uint64_T secp_seqnr;

	uint64_T secp_free_blocks;
	uint64_T secp_inodes;	/* Number of inodes in use */

	/* Root of the bitmap index. The height is specified in the super block
	 * in ses_bm_ind_levels.
	 */
	sef_blkptr_T secp_bm_index;

	/* Free block trees. The same number of trees as the maximum height
	 * of the bitmap index.
	 */
	sef_blkptr_T secp_fbt[SEF_BM_IND_MAX];

	/* The same number of block pointers as in an inode. So the same
	 * allocation of direct/indirect blocks can be used for storing
	 * the inodes as is used for storing the data in a file.
	 */
	sef_blkptr_T secp_blkptrs[SEF_INODE_BLKPTRS];

	uint8_T secp_extra[294];
} sef_checkpoint_T;

#define SEF_CHECKPOINT_SIZE	1024
