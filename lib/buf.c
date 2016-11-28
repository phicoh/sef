/*
buf.c

Created:	December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Buffer cache
*/

#include "os.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "buf.h"

static unsigned max_size= 1024*1024;

static buf_T *head, *tail;
static unsigned curr_size;
static write_buf_T buf_write_f;

static void buf_free_some(void);
static int buf_check(void);

void buf_init(write_buf_T write_f)
{
	head= tail= NULL;
	curr_size= 0;
	buf_write_f= write_f;
}

lbptr_T lbuf_mkptr(int type, uint64_T space, uint64_T inode,
	uint64_T level, uint64_T offset)
{
	lbptr_T ptr;

	ptr.lbp_type= type;
	ptr.lbp_space= space;
	ptr.lbp_inode= inode;
	ptr.lbp_level= level;
	ptr.lbp_offset= offset;
	
	return ptr;
}

buf_T *lbuf_lookup(lbptr_T lbptr)
{
	buf_T *b;

	/* See if we can find an exting one */
	for (b= head; b; b= b->b_next)
	{
		if (b->b_ptr.lbp_type != lbptr.lbp_type ||
		    b->b_ptr.lbp_space != lbptr.lbp_space ||
		    b->b_ptr.lbp_inode != lbptr.lbp_inode ||
		    b->b_ptr.lbp_level != lbptr.lbp_level ||
		    b->b_ptr.lbp_offset != lbptr.lbp_offset)
		{
			continue;
		}

		b->b_readers++;
		b->b_use++;
		return b;
	}


	/* Nothing */
	return NULL;
}

buf_T *lbuf_alloc(lbptr_T lbptr, size_t size)
{
	buf_T *b;

	/* See if we can find an exting one */
	b= lbuf_lookup(lbptr);
	if (b)
		return b;

	if (curr_size > max_size)
		buf_free_some();

	b= malloc(sizeof(*b));
	if (!b)
		return NULL;
	b->b_flags= 0;
	b->b_ptr= lbptr;
	b->b_size= size;
	b->b_data= malloc(size);
	if (!b->b_data)
	{
		free(b); b= NULL;
		return NULL;
	}
	b->b_readers= 0;
	b->b_writers= 0;
	b->b_locks= 0;
	b->b_next= NULL;
	b->b_magic= B_MAGIC;

	if (!head)
	{
		tail= head= b;
	}
	else
	{
		tail->b_next= b;
		tail= b;
	}

	curr_size += size;

	b->b_readers++;
	b->b_use++;
	return b;
}

void lbuf_rename(buf_T *buf, lbptr_T lbptr)
{
	buf_T *b, *prev;

	/* Find the target buffer (if any) */
	for (prev= NULL, b= head; b; prev= b, b= b->b_next)
	{
		if (b->b_ptr.lbp_type != lbptr.lbp_type ||
		    b->b_ptr.lbp_space != lbptr.lbp_space ||
		    b->b_ptr.lbp_inode != lbptr.lbp_inode ||
		    b->b_ptr.lbp_level != lbptr.lbp_level ||
		    b->b_ptr.lbp_offset != lbptr.lbp_offset)
		{
			continue;
		}

		break;
	}

	if (b)
	{
		if (prev)
		{
			prev->b_next= b->b_next;
			if (tail == b)
				tail= prev;
		}
		else
			head= b->b_next;

		curr_size -= b->b_size;

		b->b_magic= 0;
		free(b->b_data); b->b_data= NULL;
		free(b); b= NULL;

		assert(buf_check());
	}

	buf->b_ptr= lbptr;
}

static void buf_free_some(void)
{
	buf_T *buf;

	while (curr_size > max_size)
	{
		/* Check if we can find at least one buffer that can be
		 * freed.
		 */
		for (buf= head; buf; buf= buf->b_next)
		{
			if (buf->b_readers == 0 && buf->b_writers == 0 &&
				buf->b_locks == 0)
			{
				break;
			}
		}
		if (!buf)
		{
			fprintf(stderr,
				"buf_free_some: all buffer are in use\n");
			return;
		}

		for (;;)
		{
			buf= head;
			if (buf->b_use || buf->b_readers || buf->b_writers ||
				buf->b_locks)
			{
				printf("buf_free_some: skipping buf %p\n",
					buf);

				/* Buffer cannot be freed */
				head= head->b_next;
				buf->b_use /= 2;

				/* Assume more than one buffer */
				assert(head);
				buf->b_next= NULL;
				tail->b_next= buf;
				tail= buf;
				continue;
			}

			if (buf->b_flags & BF_WRITABLE)
			{
				(*buf_write_f)(buf);

				/* BF_WRITABLE should be clear now */
				assert(!(buf->b_flags & BF_WRITABLE));
				continue;
			}

			head= head->b_next;
			buf->b_magic= 0;
			free(buf->b_data);
			buf->b_data= NULL;

			curr_size -= buf->b_size;
			free(buf);
			buf= NULL;
			break;
		}
	}
}

static int buf_check(void)
{
	buf_T *buf, *prev;
	unsigned size;

	/* Check if the size of all buffers matches curr_size. Also check
	 * if tail points to the last buffer.
	 */
	if (head == NULL)
	{
		if (curr_size != 0)
		{
			fprintf(stderr,
			"buf_check: wrong curr_size for empty list\n");
		}
		return curr_size == 0;
	}
	size= 0;
	for (buf= head, prev= NULL; size <= 2*curr_size && buf;
		prev= buf, buf= buf->b_next)
	{
		if (buf->b_magic != B_MAGIC)
		{
			fprintf(stderr,
				"buf_check: bad magic in buf %p: 0x%x\n",
				buf, buf->b_magic);
			return 0;
		}
		size += buf->b_size;
	}
	if (size != curr_size)
	{
		fprintf(stderr,
	"buf_check: size doesn't match, found %u, expected %u, buf %p\n",
			size, curr_size, buf);
		return 0;
	}
	if (tail != prev)
	{
		fprintf(stderr, "buf_check: tail doesn't match\n");
		return 0;
	}
	return 1;
}

void buf_setvalid(buf_T *buf)
{
	buf->b_flags |= BF_VALID;
}

void buf_setinvalid(buf_T *buf)
{
	buf->b_flags &= ~BF_VALID;
}

int buf_is_valid(buf_T *buf)
{
	return !!(buf->b_flags & BF_VALID);
}

void buf_setwritable(buf_T *buf)
{
	buf->b_flags |= BF_WRITABLE;
}

void buf_setclean(buf_T *buf)
{
	buf->b_flags &= ~BF_WRITABLE;
}

int buf_is_writable(buf_T *buf)
{
	return !!(buf->b_flags & BF_WRITABLE);
}

void *buf_data_ptr(buf_T *buf)
{
	return buf->b_data;
}

lbptr_T buf_get_ptr(buf_T *buf)
{
	return buf->b_ptr;
}

void buf_lock(buf_T *buf)
{
	buf->b_locks++;
}

void buf_unlock(buf_T *buf)
{
	assert(buf->b_locks > 0);
	buf->b_locks--;
}

void buf_release(buf_T *buf)
{
	assert(buf->b_readers > 0);
	buf->b_readers--;
}

void buf_write_ref(buf_T *buf)
{
	buf->b_writers++;
	buf->b_use++;

	printf(
"buf_write_ref: for (t%u,s%llu,i%llu,l%u,o%llu) r %d, w %d, l %d\n",
		buf->b_ptr.lbp_type,
		(unsigned long long)buf->b_ptr.lbp_space,
		(unsigned long long)buf->b_ptr.lbp_inode,
		buf->b_ptr.lbp_level,
		(unsigned long long)buf->b_ptr.lbp_offset,
		buf->b_readers,
		buf->b_writers,
		buf->b_locks);
}

void buf_release_write(buf_T *buf)
{
	assert(buf->b_writers > 0);
	buf->b_writers--;
}

void lbuf_sync(void)
{
	int found_one;
	buf_T *buf, *list;
  
	for (;;)
	{
		/* Reorder the list such that buffer that we can write
		 * are at the front.
		 */
		list= head;
		head= NULL;

		found_one= 0;
		while (list)
		{
			buf= list;
			list= buf->b_next;

			if ((buf->b_flags & BF_WRITABLE) &&
				buf->b_writers == 0)
			{
				/* Condidate for writing out. */
				found_one= 1;
				if (head == NULL)
				{
					head= buf;
					tail= buf;
					buf->b_next= NULL;
				}
				else
				{
					buf->b_next= head;
					head= buf;
				}

			}
			else
			{
				buf->b_next= NULL;
				if (head == NULL)
				{
					head= buf;
					tail= buf;
				}
				else
				{
					tail->b_next= buf;
					tail= buf;
				}
			}
		}

		if (!found_one)
			break;	/* Done */

		for (;;)
		{
			buf= head;
			if (!buf || !(buf->b_flags & BF_WRITABLE) ||
				buf->b_writers != 0)
			{
				break;	/* Done for this round */
			}

			/* Move buf to the tail. */
			head= buf->b_next;

			buf->b_next= NULL;
			if (head == NULL)
			{
				head= buf;
				tail= buf;
			}
			else
			{
				tail->b_next= buf;
				tail= buf;
			}

			(*buf_write_f)(buf);

			/* BF_WRITABLE should be clear now */
			assert(!(buf->b_flags & BF_WRITABLE));
		}
	}

	/* Report writable buffer, for debugging */
	for (buf= head; buf; buf= buf->b_next)
	{
		if (!(buf->b_flags & BF_WRITABLE))
			continue;
		printf(
"lbuf_sync: writable buffer (t%u,s%llu,i%llu,l%u,o%llu) r %d, w %d, l %d\n",
			buf->b_ptr.lbp_type,
			(unsigned long long)buf->b_ptr.lbp_space,
			(unsigned long long)buf->b_ptr.lbp_inode,
			buf->b_ptr.lbp_level,
			(unsigned long long)buf->b_ptr.lbp_offset,
			buf->b_readers,
			buf->b_writers,
			buf->b_locks);
	}
}

void lbuf_sync_buf(buf_T *buf)
{
	if (!(buf->b_flags & BF_WRITABLE))
	{
		fprintf(stderr, "lbuf_sync_buf: buf not writable\n");
		abort();
	}
	if (buf->b_writers)
	{
		fprintf(stderr, "lbuf_sync_buf: buf has writers\n");
		abort();
	}

	(*buf_write_f)(buf);

	assert(!(buf->b_flags & BF_WRITABLE));
}

void buf_flush(void)
{
	int failed;
	buf_T *buf;

	/* Get rid all buffers. Fail is some buffers are still dirty or
	 * locked.
	 */
	failed= 0;
	while (head)
	{
		buf= head;
		head= head->b_next;
		if ((buf->b_flags & BF_WRITABLE) ||
			buf->b_readers || buf->b_writers ||
			buf->b_locks)
			
		{
			printf("buf_flush: buffer writable or busy\n");
			printf(
"buf_flush: writable/busy buffer (t%u,s%llu,i%llu,l%u,o%llu) r %d, w %d, l %d\n",
				buf->b_ptr.lbp_type,
				(unsigned long long)buf->b_ptr.lbp_space,
				(unsigned long long)buf->b_ptr.lbp_inode,
				buf->b_ptr.lbp_level,
				(unsigned long long)buf->b_ptr.lbp_offset,
				buf->b_readers,
				buf->b_writers,
				buf->b_locks);
			failed= 1;
		}
		free(buf->b_data);
		free(buf);
	}
	if (failed)
	{
		printf("buf_flush: exiting\n");
		exit(1);
	}
}

void lbuf_flush_space(uint64_T space)
{
	buf_T *buf, *next, *prev;

	printf("lbuf_flush_space: flushing space %llu\n",
		(unsigned long long)space);

	/* Get rid all buffers in this space. Ignore dirty or locked buffers.
	 */
	prev= NULL;
	next= NULL;
	for (buf= head; buf; prev= buf, buf= next)
	{
		if (buf->b_ptr.lbp_space != space)
			continue;
		if ((buf->b_flags & BF_WRITABLE) ||
			buf->b_readers || buf->b_writers ||
			buf->b_locks)
			
		{
			printf("lbuf_flush_space: buffer writable or busy\n");
			printf(
"lbuf_flush_space: writable buffer (t%u,s%llu,i%llu,l%u,o%llu) r %d, w %d, l %d\n",
				buf->b_ptr.lbp_type,
				(unsigned long long)buf->b_ptr.lbp_space,
				(unsigned long long)buf->b_ptr.lbp_inode,
				buf->b_ptr.lbp_level,
				(unsigned long long)buf->b_ptr.lbp_offset,
				buf->b_readers,
				buf->b_writers,
				buf->b_locks);
			continue;
		}
		printf("lbuf_flush_space: flushing buf %p\n", buf);
		next= buf->b_next;
		free(buf->b_data);
		free(buf);
	}

	printf("lbuf_flush_space: done flushing space %llu\n",
		(unsigned long long)space);
}

void buf_print_lbptr(lbptr_T lbptr)
{
	buf_T *b;

	/* find buffer */
	for (b= head; b; b= b->b_next)
	{
		if (b->b_ptr.lbp_type != lbptr.lbp_type ||
		    b->b_ptr.lbp_space != lbptr.lbp_space ||
		    b->b_ptr.lbp_inode != lbptr.lbp_inode ||
		    b->b_ptr.lbp_level != lbptr.lbp_level ||
		    b->b_ptr.lbp_offset != lbptr.lbp_offset)
		{
			continue;
		}

		break;
	}
	printf("buffer (t%u,s%llu,i%llu,l%u,o%llu): ",
		lbptr.lbp_type, (unsigned long long)lbptr.lbp_space,
		(unsigned long long)lbptr.lbp_inode,
		lbptr.lbp_level, (unsigned long long)lbptr.lbp_offset);
	if (!b)
	{
		printf("not found");
		return;
	}
	printf("r %d, w %d, l %d",
		b->b_readers, b->b_writers, b->b_locks);
}
