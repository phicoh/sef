/*
sef/inode.h

Created:        December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Inode definition
*/

#ifndef SEF__INODE_H
#define SEF__INODE_H

/* Number of block points in an inode */
#define SEF_INODE_BLKPTRS	5

typedef struct sef_inode
{
	uint32_T sei_mode;
	uint32_T sei_nlink;	/* Or 64-bits? */
	uint32_T sei_flags;
	uint32_T sei_reserved1;

	uint64_T sei_size;
	uint64_T sei_blocks;
	/*
	uid
	gid
	gen?
	modrev?
	*/

	/* Time is encoded as follows: the lower 30 bits contain the
	 * tv_nsec value of a POSIX struct timespec. The upper 34 bits
	 * contain the tv_sec value. A signed 34-bit value will last until
	 * the year 2242.
	 */
	uint64_T sei_atime;
	uint64_T sei_mtime;
	uint64_T sei_ctime;
	uint64_T sei_btime;

	uint64_T sei_extinode;	/* Inode with attributes */

	uint8_T sei_extra[120];
	sef_blkptr_T sei_blkptrs[SEF_INODE_BLKPTRS];
} sef_inode_T;

/* Values for sei_mode */
#define SIM_TYPE	0xff000
#define SIM_DIRECTORY	0x04000
#define SIM_REGULAR	0x08000
#define SIM_UNREF	0x10000
#define SIM_RESERVED	0x20000

#define SIF_IMMEDIATE	1	/* Contents is stored in sei_blkptrs */

#define SEF_INODE_SIZE	512
#define SEF_UNREF_INODE	  1
#define SEF_ROOT_INODE	  2

/* The following a convenience value for implementations. No need to 
 * support a level indirection beyond this value.
 */
#define SEF_INODE_MAX_INDIR	16

#endif /* SEF__INODE_H */
