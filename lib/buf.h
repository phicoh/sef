/*
buf.h

Created:	December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Interface to buffer cache
*/

typedef struct lbptr
{
	unsigned lbp_type;
	unsigned lbp_level;
	uint64_T lbp_space;
	uint64_T lbp_inode;
	uint64_T lbp_offset;
} lbptr_T;

typedef struct buf
{
	unsigned b_magic;
	unsigned b_flags;
	lbptr_T b_ptr;
	size_t b_size;
	void *b_data;
	unsigned b_readers;
	unsigned b_writers;
	unsigned b_locks;
	unsigned b_use;
	struct buf *b_next;
} buf_T;

#define B_MAGIC		0xdeadbeef

#define BF_VALID	1
#define BF_WRITABLE	2

#define LT_SUPER	 0	/* Super block */
#define LT_CHECKPOINT	 1	/* Checkpoint block */
#define LT_BM_INDEX	 2	/* Bitmap index block */
#define LT_BITMAP	 3	/* Bitmap block */
#define LT_INODE_INDEX	 4	/* Inode index block */
#define LT_INODE	 5	/* Inode block */
#define LT_DATA_INDEX	 6	/* Data index block */
#define LT_DATA		 7	/* Data block */
#define LT_FBT_INDEX	 8	/* Free block tree index */
#define LT_FBT		 9	/* Free block tree */
#define LT_FBL		10	/* Free block list */

#define LS_LATEST_CHECKPOINT	1	/* Space for most recent checkpoint
					 * on disk.
					 */

typedef void (*write_buf_T)(buf_T *buf);

void buf_init(write_buf_T write_f);
lbptr_T lbuf_mkptr(int type, uint64_T space, uint64_T inode,
	uint64_T level, uint64_T offset);
buf_T *lbuf_lookup(lbptr_T lbptr);
buf_T *lbuf_alloc(lbptr_T lbptr, size_t size);
void lbuf_rename(buf_T *buf, lbptr_T lbptr);
#if 0
buf_T *lbuf_read(lbptr_T lbptr, size_t size);
#endif
void buf_setvalid(buf_T *buf);
void buf_setinvalid(buf_T *buf);
int buf_is_valid(buf_T *buf);
void buf_setwritable(buf_T *buf);
void buf_setclean(buf_T *buf);
int buf_is_writable(buf_T *buf);
void *buf_data_ptr(buf_T *buf);
lbptr_T buf_get_ptr(buf_T *buf);
void buf_release(buf_T *buf);
void buf_write_ref(buf_T *buf);
void buf_release_write(buf_T *buf);
void buf_lock(buf_T *buf);
void buf_unlock(buf_T *buf);
void lbuf_sync(void);
void lbuf_sync_buf(buf_T *buf);
void buf_flush(void);
void lbuf_flush_space(uint64_T space);
void buf_print_lbptr(lbptr_T lbptr);
