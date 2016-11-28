/*
hmac_sha256.h

Message Authentication Code based on the Hash function SHA-256 (RFC-2104)

Created:	Dec 2004 by Philip Homburg <philip@f-mnx.phicoh.com>
*/

#include "sha2.h"

typedef struct hmac_sha256_ctx
{
	SHA256_CTX i_ctx;	/* inner key (pre-computed context) */
	SHA256_CTX o_ctx;	/* outer key (pre-computer context) */
	SHA256_CTX curr_ctx;	/* current working context */
} hmac_sha256_ctx_t;

#define SHA256_BLOCK_SIZE	SHA256_BLOCK_LENGTH
						/* block size in bytes */
#define SHA256_DIGEST_LEN	SHA256_DIGEST_LENGTH	/* Length of result */

/* Initialize an hmac context */
void hmac_sha256_init(struct hmac_sha256_ctx *ctxp, const void *key,
	size_t len);

/* Restart. The state is reset to the start of a message */
void hmac_sha256_reinit(struct hmac_sha256_ctx *ctxp);

/* Add data to the current state */
void hmac_sha256_update(struct hmac_sha256_ctx *ctxp, const void *buf,
	size_t len);

/* Compute the hmac */
void hmac_sha256_finish(struct hmac_sha256_ctx *ctxp,
	uint8_T digest[SHA256_DIGEST_LEN]);

/* Clear the context */
void hmac_sha256_cleanup(struct hmac_sha256_ctx *ctxp);



/*
 * $PchId: hmac_sha256.h,v 1.1 2005/05/03 13:29:52 philip Exp $
 */
