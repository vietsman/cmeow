/* See common.h for license and attribution.
 * Thin wrappers over OpenSSL (libcrypto 3.x) for the primitives whatsmeow
 * takes from Go's standard library / golang.org/x/crypto. */
#ifndef CMEOW_CRYPTO_H
#define CMEOW_CRYPTO_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_SHA256_LEN   32
#define CM_GCM_KEY_LEN  32
#define CM_GCM_IV_LEN   12
#define CM_GCM_TAG_LEN  16
#define CM_X25519_LEN   32

cm_err cm_random(void *out, size_t n);

cm_err cm_sha256(const void *data, size_t len, uint8_t out[CM_SHA256_LEN]);
/* SHA-256 of a || b without the caller having to concatenate. */
cm_err cm_sha256_2(const void *a, size_t alen, const void *b, size_t blen,
                   uint8_t out[CM_SHA256_LEN]);

cm_err cm_hmac_sha256(const void *key, size_t keylen, const void *data, size_t len,
                      uint8_t out[CM_SHA256_LEN]);

/*
 * RFC 5869 HKDF-SHA256, same semantics as golang.org/x/crypto/hkdf with
 * sha256.New: a NULL/empty salt means HashLen zero bytes, `info` may be
 * NULL. out_len may be at most 255*32.
 */
cm_err cm_hkdf_sha256(const void *ikm, size_t ikm_len, const void *salt, size_t salt_len,
                      const void *info, size_t info_len, uint8_t *out, size_t out_len);

/* AES-256-GCM with a 12 byte IV and 16 byte tag appended to the ciphertext,
 * i.e. exactly Go's cipher.AEAD Seal/Open. out must have room for
 * pt_len + 16 (seal) or ct_len - 16 (open). open returns CM_ERR_AUTH when the
 * tag does not verify. `out` may alias the input. */
cm_err cm_aes256gcm_seal(const uint8_t key[CM_GCM_KEY_LEN], const uint8_t iv[CM_GCM_IV_LEN],
                         const void *aad, size_t aad_len,
                         const void *pt, size_t pt_len, uint8_t *out);
cm_err cm_aes256gcm_open(const uint8_t key[CM_GCM_KEY_LEN], const uint8_t iv[CM_GCM_IV_LEN],
                         const void *aad, size_t aad_len,
                         const void *ct, size_t ct_len, uint8_t *out);

/* Constant-time equality (crypto/hmac.Equal). */
int cm_ct_equal(const void *a, const void *b, size_t n);

typedef struct cm_keypair {
    uint8_t priv[CM_X25519_LEN];
    uint8_t pub[CM_X25519_LEN];
} cm_keypair;

/* keys.NewKeyPair: random clamped private key + public key. */
cm_err cm_keypair_generate(cm_keypair *kp);
/* keys.NewKeyPairFromPrivateKey: the private key is used as given (x25519
 * clamps internally). */
cm_err cm_keypair_from_private(cm_keypair *kp, const uint8_t priv[CM_X25519_LEN]);

/* curve25519.X25519: fails with CM_ERR_CRYPTO if the result is all zero
 * (low order point), like Go. */
cm_err cm_x25519(const uint8_t priv[CM_X25519_LEN], const uint8_t pub[CM_X25519_LEN],
                 uint8_t out[CM_X25519_LEN]);

/* Wipe memory in a way the optimiser may not remove. */
void cm_cleanse(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_CRYPTO_H */
