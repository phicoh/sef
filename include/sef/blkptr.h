/*
sef/blkptr.h

Created:        December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Block pointer definition
*/

#ifndef SEF__BLKPTR_H
#define SEF__BLKPTR_H

typedef struct sef_hash
{
	uint8_T seh_data[256 / 8];
} sef_hash_T;

typedef struct sef_iv
{
	uint8_T sei_data[128 / 8];
} sef_iv_T;

typedef struct sef_ptr_flags
{
	uint8_T sepf_data[64 / 8];
} sef_ptr_flags_T;

typedef struct sef_blkptr
{
	sef_hash_T sebp_hash;
	sef_iv_T sebp_iv;
	sef_ptr_flags_T sebp_flags;
	uint64_T sebp_block;
} sef_blkptr_T;

#define SEF_BLKPTR_SIZE	(512/8)

#endif /* SEF__BLKPTR_H */
