/*
hmac_sha256.c

Message Authentication Code based on the Hash function SHA-256 (RFC-2104)

Created:	Dec 2004 by Philip Homburg <philip@f-mnx.phicoh.com>
*/

#include "os.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "hmac_sha256.h"

/* Do we want a generic HMAC function that can operate on different hash
 * functions or not? There is the risk that the generic function will be
 * much more complex, and that in practice only a few hash functions will
 * be used for HMACs. For the moment, use just a simple, direct
 * implementation.
 */

#define INNER_MASK	0x36
#define OUTER_MASK	0x5c

void hmac_sha256_init(struct hmac_sha256_ctx *ctxp, const void *key,
	size_t len)
{
	uint8_T paddedkey[SHA256_BLOCK_SIZE];
	uint8_T tmpkey[SHA256_DIGEST_LEN];
	const uint8_T *kp;
	int i;

	kp= key;
	if (len > SHA256_BLOCK_SIZE)
	{
		/* Hash the key before use */
		SHA256_Init(&ctxp->curr_ctx);
		SHA256_Update(&ctxp->curr_ctx, key, len);
		SHA256_Final(tmpkey, &ctxp->curr_ctx);
		kp= tmpkey;
		len= SHA256_DIGEST_LEN;
	}

	/* Initialize i_ctx */
	memset(paddedkey, INNER_MASK, SHA256_BLOCK_SIZE);
	for (i= 0; i<len; i++)
		paddedkey[i] ^= kp[i];
	SHA256_Init(&ctxp->i_ctx);
	SHA256_Update(&ctxp->i_ctx, paddedkey, SHA256_BLOCK_SIZE);

	/* Initialize o_ctx */
	memset(paddedkey, OUTER_MASK, SHA256_BLOCK_SIZE);
	for (i= 0; i<len; i++)
		paddedkey[i] ^= kp[i];
	SHA256_Init(&ctxp->o_ctx);
	SHA256_Update(&ctxp->o_ctx, paddedkey, SHA256_BLOCK_SIZE);

	/* curr_ctx starts with i_ctx */
	ctxp->curr_ctx= ctxp->i_ctx;
}

void hmac_sha256_reinit(struct hmac_sha256_ctx *ctxp)
{
	/* curr_ctx starts with i_ctx */
	ctxp->curr_ctx= ctxp->i_ctx;
}

void hmac_sha256_update(struct hmac_sha256_ctx *ctxp, const void *buf,
	size_t len)
{
	/* Nothing more than SHA256_Update */
	SHA256_Update(&ctxp->curr_ctx, buf, len);
}

void hmac_sha256_finish(struct hmac_sha256_ctx *ctxp,
	uint8_T digest[SHA256_DIGEST_LEN])
{
	uint8_T i_digest[SHA256_DIGEST_LEN];

	SHA256_Final(i_digest, &ctxp->curr_ctx);

	/* Continue with o_ctx */
	ctxp->curr_ctx= ctxp->o_ctx;
	SHA256_Update(&ctxp->curr_ctx, i_digest, sizeof(i_digest));
	SHA256_Final(digest, &ctxp->curr_ctx);
}

void hmac_sha256_cleanup(struct hmac_sha256_ctx *ctxp)
{
	/* Re-key with a zero length string */
	hmac_sha256_init(ctxp, NULL, 0);
}

/*
 * $PchId: hmac_sha256.c,v 1.2 2011/12/27 22:25:28 philip Exp $
 */
