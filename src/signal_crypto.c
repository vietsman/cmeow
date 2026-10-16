/* See include/common.h for license and attribution. */
#include "signal_crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

static int sc_random(uint8_t *data, size_t len, void *user_data)
{
    (void)user_data;
    while (len > 0) {
        int chunk = len > (size_t)INT_MAX ? INT_MAX : (int)len;
        if (RAND_bytes(data, chunk) != 1)
            return SG_ERR_UNKNOWN;
        data += chunk;
        len -= (size_t)chunk;
    }
    return 0;
}

/* ---- HMAC-SHA256 (EVP_MAC) ---- */

struct hmac_state {
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
};

static int sc_hmac_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data)
{
    struct hmac_state *st;
    OSSL_PARAM params[2];
    static const unsigned char empty[1] = {0};

    (void)user_data;
    st = (struct hmac_state *)calloc(1, sizeof(*st));
    if (st == NULL)
        return SG_ERR_NOMEM;
    st->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    st->ctx = st->mac ? EVP_MAC_CTX_new(st->mac) : NULL;
    if (st->ctx == NULL) {
        if (st->mac)
            EVP_MAC_free(st->mac);
        free(st);
        return SG_ERR_NOMEM;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(st->ctx, key_len ? key : empty, key_len, params) != 1) {
        EVP_MAC_CTX_free(st->ctx);
        EVP_MAC_free(st->mac);
        free(st);
        return SG_ERR_UNKNOWN;
    }
    *hmac_context = st;
    return 0;
}

static int sc_hmac_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data)
{
    struct hmac_state *st = (struct hmac_state *)hmac_context;

    (void)user_data;
    if (data_len == 0)
        return 0;
    return EVP_MAC_update(st->ctx, data, data_len) == 1 ? 0 : SG_ERR_UNKNOWN;
}

static int sc_hmac_final(void *hmac_context, signal_buffer **output, void *user_data)
{
    struct hmac_state *st = (struct hmac_state *)hmac_context;
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t len = 0;
    signal_buffer *buf;

    (void)user_data;
    if (EVP_MAC_final(st->ctx, md, &len, sizeof(md)) != 1)
        return SG_ERR_UNKNOWN;
    buf = signal_buffer_create(md, len);
    if (buf == NULL)
        return SG_ERR_NOMEM;
    *output = buf;
    return 0;
}

static void sc_hmac_cleanup(void *hmac_context, void *user_data)
{
    struct hmac_state *st = (struct hmac_state *)hmac_context;

    (void)user_data;
    if (st != NULL) {
        EVP_MAC_CTX_free(st->ctx);
        EVP_MAC_free(st->mac);
        free(st);
    }
}

/* ---- SHA-512 ---- */

static int sc_sha512_init(void **digest_context, void *user_data)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    (void)user_data;
    if (ctx == NULL)
        return SG_ERR_NOMEM;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return SG_ERR_UNKNOWN;
    }
    *digest_context = ctx;
    return 0;
}

static int sc_sha512_update(void *digest_context, const uint8_t *data, size_t data_len, void *user_data)
{
    (void)user_data;
    if (data_len == 0)
        return 0;
    return EVP_DigestUpdate((EVP_MD_CTX *)digest_context, data, data_len) == 1 ? 0 : SG_ERR_UNKNOWN;
}

static int sc_sha512_final(void *digest_context, signal_buffer **output, void *user_data)
{
    EVP_MD_CTX *ctx = (EVP_MD_CTX *)digest_context;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    signal_buffer *buf;

    (void)user_data;
    if (EVP_DigestFinal_ex(ctx, md, &len) != 1)
        return SG_ERR_UNKNOWN;
    /* libsignal may reuse the context for another digest */
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1)
        return SG_ERR_UNKNOWN;
    buf = signal_buffer_create(md, len);
    if (buf == NULL)
        return SG_ERR_NOMEM;
    *output = buf;
    return 0;
}

static void sc_sha512_cleanup(void *digest_context, void *user_data)
{
    (void)user_data;
    EVP_MD_CTX_free((EVP_MD_CTX *)digest_context);
}

/* ---- AES-CBC (PKCS#5/7) and AES-CTR ---- */

static const EVP_CIPHER *aes_cipher(int cipher, size_t key_len)
{
    if (cipher == SG_CIPHER_AES_CBC_PKCS5) {
        if (key_len == 16) return EVP_aes_128_cbc();
        if (key_len == 24) return EVP_aes_192_cbc();
        if (key_len == 32) return EVP_aes_256_cbc();
    } else if (cipher == SG_CIPHER_AES_CTR_NOPADDING) {
        if (key_len == 16) return EVP_aes_128_ctr();
        if (key_len == 24) return EVP_aes_192_ctr();
        if (key_len == 32) return EVP_aes_256_ctr();
    }
    return NULL;
}

static int aes_crypt(int enc, signal_buffer **output, int cipher,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *in, size_t in_len)
{
    const EVP_CIPHER *c = aes_cipher(cipher, key_len);
    EVP_CIPHER_CTX *ctx;
    uint8_t *out;
    int n = 0, total = 0, result = SG_ERR_UNKNOWN;
    signal_buffer *buf;

    if (c == NULL || iv_len != 16 || in_len > (size_t)INT_MAX - 32)
        return SG_ERR_UNKNOWN;
    ctx = EVP_CIPHER_CTX_new();
    out = (uint8_t *)malloc(in_len + 32);
    if (ctx == NULL || out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        free(out);
        return SG_ERR_NOMEM;
    }
    if (EVP_CipherInit_ex(ctx, c, NULL, key, iv, enc) != 1)
        goto done;
    if (cipher == SG_CIPHER_AES_CTR_NOPADDING && EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        goto done;
    if (in_len && EVP_CipherUpdate(ctx, out, &n, in, (int)in_len) != 1)
        goto done;
    total = n;
    if (EVP_CipherFinal_ex(ctx, out + total, &n) != 1)
        goto done; /* includes bad padding on decrypt */
    total += n;
    buf = signal_buffer_create(out, (size_t)total);
    if (buf == NULL) {
        result = SG_ERR_NOMEM;
        goto done;
    }
    *output = buf;
    result = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(out, in_len + 32);
    free(out);
    return result;
}

static int sc_encrypt(signal_buffer **output, int cipher, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *plaintext,
                      size_t plaintext_len, void *user_data)
{
    (void)user_data;
    return aes_crypt(1, output, cipher, key, key_len, iv, iv_len, plaintext, plaintext_len);
}

static int sc_decrypt(signal_buffer **output, int cipher, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *ciphertext,
                      size_t ciphertext_len, void *user_data)
{
    (void)user_data;
    return aes_crypt(0, output, cipher, key, key_len, iv, iv_len, ciphertext, ciphertext_len);
}

void cm_signal_crypto_provider(signal_crypto_provider *p)
{
    memset(p, 0, sizeof(*p));
    p->random_func = sc_random;
    p->hmac_sha256_init_func = sc_hmac_init;
    p->hmac_sha256_update_func = sc_hmac_update;
    p->hmac_sha256_final_func = sc_hmac_final;
    p->hmac_sha256_cleanup_func = sc_hmac_cleanup;
    p->sha512_digest_init_func = sc_sha512_init;
    p->sha512_digest_update_func = sc_sha512_update;
    p->sha512_digest_final_func = sc_sha512_final;
    p->sha512_digest_cleanup_func = sc_sha512_cleanup;
    p->encrypt_func = sc_encrypt;
    p->decrypt_func = sc_decrypt;
    p->user_data = NULL;
}
