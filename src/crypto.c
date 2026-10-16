/* See include/common.h for license and attribution. */
#include "crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

void cm_cleanse(void *p, size_t n)
{
    OPENSSL_cleanse(p, n);
}

int cm_ct_equal(const void *a, const void *b, size_t n)
{
    return CRYPTO_memcmp(a, b, n) == 0;
}

cm_err cm_random(void *out, size_t n)
{
    unsigned char *p = (unsigned char *)out;

    while (n > 0) {
        int chunk = n > (size_t)INT_MAX ? INT_MAX : (int)n;
        if (RAND_bytes(p, chunk) != 1)
            return CM_ERR_CRYPTO;
        p += chunk;
        n -= (size_t)chunk;
    }
    return CM_OK;
}

cm_err cm_sha256_2(const void *a, size_t alen, const void *b, size_t blen,
                   uint8_t out[CM_SHA256_LEN])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int n = 0;
    int ok;

    if (ctx == NULL)
        return CM_ERR_NOMEM;
    ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
         (alen == 0 || EVP_DigestUpdate(ctx, a, alen) == 1) &&
         (blen == 0 || EVP_DigestUpdate(ctx, b, blen) == 1) &&
         EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == CM_SHA256_LEN;
    EVP_MD_CTX_free(ctx);
    return ok ? CM_OK : CM_ERR_CRYPTO;
}

cm_err cm_sha256(const void *data, size_t len, uint8_t out[CM_SHA256_LEN])
{
    return cm_sha256_2(data, len, NULL, 0, out);
}

cm_err cm_hmac_sha256(const void *key, size_t keylen, const void *data, size_t len,
                      uint8_t out[CM_SHA256_LEN])
{
    unsigned int n = 0;
    static const unsigned char empty[1] = {0};

    if (keylen > (size_t)INT_MAX)
        return CM_ERR_ARG;
    /* OpenSSL rejects NULL key/data pointers even for zero length */
    if (HMAC(EVP_sha256(), key ? key : empty, (int)keylen,
             data ? (const unsigned char *)data : empty, len, out, &n) == NULL ||
        n != CM_SHA256_LEN)
        return CM_ERR_CRYPTO;
    return CM_OK;
}

cm_err cm_hkdf_sha256(const void *ikm, size_t ikm_len, const void *salt, size_t salt_len,
                      const void *info, size_t info_len, uint8_t *out, size_t out_len)
{
    uint8_t prk[CM_SHA256_LEN], t[CM_SHA256_LEN];
    static const uint8_t zero_salt[CM_SHA256_LEN] = {0};
    uint8_t *buf;
    size_t t_len = 0, done = 0;
    unsigned counter = 1;
    cm_err e;

    if (out_len > 255 * CM_SHA256_LEN)
        return CM_ERR_ARG;
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = CM_SHA256_LEN;
    }
    e = cm_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    if (e != CM_OK)
        return e;

    /* T(i) = HMAC(PRK, T(i-1) || info || i) */
    buf = (uint8_t *)malloc(CM_SHA256_LEN + info_len + 1);
    if (buf == NULL) {
        cm_cleanse(prk, sizeof(prk));
        return CM_ERR_NOMEM;
    }
    while (done < out_len) {
        size_t take, blen = 0;

        memcpy(buf, t, t_len);
        blen = t_len;
        if (info_len)
            memcpy(buf + blen, info, info_len);
        blen += info_len;
        buf[blen++] = (uint8_t)counter++;
        e = cm_hmac_sha256(prk, sizeof(prk), buf, blen, t);
        if (e != CM_OK)
            break;
        t_len = CM_SHA256_LEN;
        take = out_len - done < CM_SHA256_LEN ? out_len - done : CM_SHA256_LEN;
        memcpy(out + done, t, take);
        done += take;
    }
    cm_cleanse(prk, sizeof(prk));
    cm_cleanse(t, sizeof(t));
    cm_cleanse(buf, CM_SHA256_LEN + info_len + 1);
    free(buf);
    return e;
}

cm_err cm_aes256gcm_seal(const uint8_t key[CM_GCM_KEY_LEN], const uint8_t iv[CM_GCM_IV_LEN],
                         const void *aad, size_t aad_len,
                         const void *pt, size_t pt_len, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int n = 0, total = 0, ok = 0;
    static const unsigned char empty[1] = {0};

    if (pt_len > (size_t)INT_MAX - 16 || aad_len > (size_t)INT_MAX)
        return CM_ERR_TOO_LARGE;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return CM_ERR_NOMEM;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CM_GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto done;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &n, (const unsigned char *)aad, (int)aad_len) != 1)
        goto done;
    if (pt_len) {
        if (EVP_EncryptUpdate(ctx, out, &n, (const unsigned char *)pt, (int)pt_len) != 1)
            goto done;
        total = n;
    }
    if (EVP_EncryptFinal_ex(ctx, out + total, &n) != 1)
        goto done;
    total += n;
    if ((size_t)total != pt_len ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CM_GCM_TAG_LEN, out + pt_len) != 1)
        goto done;
    ok = 1;
done:
    (void)empty;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? CM_OK : CM_ERR_CRYPTO;
}

cm_err cm_aes256gcm_open(const uint8_t key[CM_GCM_KEY_LEN], const uint8_t iv[CM_GCM_IV_LEN],
                         const void *aad, size_t aad_len,
                         const void *ct, size_t ct_len, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int n = 0, total = 0, ok = 0;
    size_t pt_len;
    uint8_t tag[CM_GCM_TAG_LEN];

    if (ct_len < CM_GCM_TAG_LEN)
        return CM_ERR_AUTH;
    pt_len = ct_len - CM_GCM_TAG_LEN;
    if (pt_len > (size_t)INT_MAX || aad_len > (size_t)INT_MAX)
        return CM_ERR_TOO_LARGE;
    memcpy(tag, (const uint8_t *)ct + pt_len, CM_GCM_TAG_LEN); /* ct may alias out */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return CM_ERR_NOMEM;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CM_GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERR_CRYPTO;
    }
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &n, (const unsigned char *)aad, (int)aad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERR_CRYPTO;
    }
    if (pt_len) {
        if (EVP_DecryptUpdate(ctx, out, &n, (const unsigned char *)ct, (int)pt_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return CM_ERR_CRYPTO;
        }
        total = n;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CM_GCM_TAG_LEN, tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, out + total, &n) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok && pt_len)
        cm_cleanse(out, pt_len); /* never hand back unauthenticated plaintext */
    return ok ? CM_OK : CM_ERR_AUTH;
}

cm_err cm_keypair_from_private(cm_keypair *kp, const uint8_t priv[CM_X25519_LEN])
{
    EVP_PKEY *pk;
    size_t publen = CM_X25519_LEN;
    int ok;

    pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, CM_X25519_LEN);
    if (pk == NULL)
        return CM_ERR_CRYPTO;
    ok = EVP_PKEY_get_raw_public_key(pk, kp->pub, &publen) == 1 && publen == CM_X25519_LEN;
    EVP_PKEY_free(pk);
    if (!ok)
        return CM_ERR_CRYPTO;
    memcpy(kp->priv, priv, CM_X25519_LEN);
    return CM_OK;
}

cm_err cm_keypair_generate(cm_keypair *kp)
{
    uint8_t priv[CM_X25519_LEN];
    cm_err e = cm_random(priv, sizeof(priv));

    if (e != CM_OK)
        return e;
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    e = cm_keypair_from_private(kp, priv);
    cm_cleanse(priv, sizeof(priv));
    return e;
}

cm_err cm_x25519(const uint8_t priv[CM_X25519_LEN], const uint8_t pub[CM_X25519_LEN],
                 uint8_t out[CM_X25519_LEN])
{
    EVP_PKEY *sk, *pk = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen = CM_X25519_LEN;
    uint8_t zero[CM_X25519_LEN];
    int ok = 0;

    sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, CM_X25519_LEN);
    pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, CM_X25519_LEN);
    if (sk == NULL || pk == NULL)
        goto done;
    ctx = EVP_PKEY_CTX_new(sk, NULL);
    if (ctx == NULL)
        goto done;
    if (EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer(ctx, pk) != 1 ||
        EVP_PKEY_derive(ctx, out, &outlen) != 1 || outlen != CM_X25519_LEN)
        goto done;
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(pk);
    if (!ok)
        return CM_ERR_CRYPTO;
    memset(zero, 0, sizeof(zero));
    if (CRYPTO_memcmp(out, zero, sizeof(zero)) == 0) {
        cm_cleanse(out, CM_X25519_LEN);
        return CM_ERR_CRYPTO; /* low order point */
    }
    return CM_OK;
}
