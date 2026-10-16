/* See include/common.h for license and attribution.
 * Port of whatsmeow/socket (noisehandshake.go, noisesocket.go, framesocket.go). */
#include "noise.h"
#include "token.h"

#include <stdlib.h>
#include <string.h>

#define CHECK(x)                          \
    do {                                  \
        cm_err e__ = (x);                 \
        if (e__ != CM_OK)                 \
            return e__;                   \
    } while (0)

void cm_conn_header(uint8_t out[CM_CONN_HEADER_LEN])
{
    out[0] = 'W';
    out[1] = 'A';
    out[2] = CM_WA_MAGIC_VALUE;
    out[3] = (uint8_t)cm_dict_version;
}

/* generateIV: 12 zero bytes with the counter big-endian in the last four. */
static void generate_iv(uint32_t count, uint8_t iv[CM_GCM_IV_LEN])
{
    memset(iv, 0, CM_GCM_IV_LEN);
    iv[8] = (uint8_t)(count >> 24);
    iv[9] = (uint8_t)(count >> 16);
    iv[10] = (uint8_t)(count >> 8);
    iv[11] = (uint8_t)count;
}

cm_err cm_noise_authenticate(cm_noise_hs *nh, const void *data, size_t len)
{
    uint8_t out[CM_SHA256_LEN];

    CHECK(cm_sha256_2(nh->hash, sizeof(nh->hash), data, len, out));
    memcpy(nh->hash, out, sizeof(out));
    return CM_OK;
}

cm_err cm_noise_start(cm_noise_hs *nh, const void *pattern, size_t pattern_len,
                      const void *header, size_t header_len)
{
    memset(nh, 0, sizeof(*nh));
    if (pattern_len == CM_SHA256_LEN)
        memcpy(nh->hash, pattern, CM_SHA256_LEN);
    else
        CHECK(cm_sha256(pattern, pattern_len, nh->hash));
    memcpy(nh->salt, nh->hash, sizeof(nh->salt));
    memcpy(nh->key, nh->hash, sizeof(nh->key));
    nh->counter = 0;
    return cm_noise_authenticate(nh, header, header_len);
}

cm_err cm_noise_encrypt(cm_noise_hs *nh, const void *pt, size_t len, uint8_t *out)
{
    uint8_t iv[CM_GCM_IV_LEN];

    generate_iv(nh->counter++, iv);
    CHECK(cm_aes256gcm_seal(nh->key, iv, nh->hash, sizeof(nh->hash), pt, len, out));
    return cm_noise_authenticate(nh, out, len + CM_GCM_TAG_LEN);
}

cm_err cm_noise_decrypt(cm_noise_hs *nh, const void *ct, size_t len, uint8_t *out)
{
    uint8_t iv[CM_GCM_IV_LEN];

    generate_iv(nh->counter++, iv); /* advances even on failure, like Go */
    CHECK(cm_aes256gcm_open(nh->key, iv, nh->hash, sizeof(nh->hash), ct, len, out));
    /* `ct` may alias `out`; the hash must be over the ORIGINAL ciphertext, so
     * callers must not decrypt in place. */
    return cm_noise_authenticate(nh, ct, len);
}

/* extractAndExpand: HKDF(sha256, secret=data, salt) -> write(32) || read(32). */
static cm_err extract_and_expand(const uint8_t salt[CM_SHA256_LEN], const void *data, size_t len,
                                 uint8_t write[32], uint8_t read[32])
{
    uint8_t okm[64];
    cm_err e = cm_hkdf_sha256(data, len, salt, CM_SHA256_LEN, NULL, 0, okm, sizeof(okm));

    if (e == CM_OK) {
        memcpy(write, okm, 32);
        memcpy(read, okm + 32, 32);
    }
    cm_cleanse(okm, sizeof(okm));
    return e;
}

cm_err cm_noise_mix_into_key(cm_noise_hs *nh, const void *data, size_t len)
{
    uint8_t write[32], read[32];
    cm_err e;

    nh->counter = 0;
    e = extract_and_expand(nh->salt, data, len, write, read);
    if (e != CM_OK)
        return e;
    memcpy(nh->salt, write, 32);
    memcpy(nh->key, read, 32);
    cm_cleanse(write, sizeof(write));
    cm_cleanse(read, sizeof(read));
    return CM_OK;
}

cm_err cm_noise_mix_shared_secret(cm_noise_hs *nh, const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t secret[32];
    cm_err e = cm_x25519(priv, pub, secret);

    if (e != CM_OK)
        return e;
    e = cm_noise_mix_into_key(nh, secret, sizeof(secret));
    cm_cleanse(secret, sizeof(secret));
    return e;
}

cm_err cm_noise_finish(const cm_noise_hs *nh, cm_noise_transport *t)
{
    memset(t, 0, sizeof(*t));
    return extract_and_expand(nh->salt, NULL, 0, t->write_key, t->read_key);
}

cm_err cm_noise_transport_seal(cm_noise_transport *t, const void *pt, size_t len, uint8_t *out)
{
    uint8_t iv[CM_GCM_IV_LEN];
    cm_err e;

    generate_iv(t->write_counter, iv);
    e = cm_aes256gcm_seal(t->write_key, iv, NULL, 0, pt, len, out);
    if (e == CM_OK)
        t->write_counter++;
    return e;
}

cm_err cm_noise_transport_open(cm_noise_transport *t, const void *ct, size_t len, uint8_t *out)
{
    uint8_t iv[CM_GCM_IV_LEN];

    generate_iv(t->read_counter++, iv);
    return cm_aes256gcm_open(t->read_key, iv, NULL, 0, ct, len, out);
}

/* ---- framing ---- */

cm_err cm_frame_encode(cm_buf *out, const uint8_t *header, size_t header_len,
                       const void *data, size_t len)
{
    if (len >= CM_FRAME_MAX_SIZE)
        return CM_ERR_TOO_LARGE;
    if (header != NULL)
        cm_buf_put(out, header, header_len);
    cm_buf_put_u8(out, (uint8_t)(len >> 16));
    cm_buf_put_u8(out, (uint8_t)(len >> 8));
    cm_buf_put_u8(out, (uint8_t)len);
    cm_buf_put(out, data, len);
    return out->err;
}

void cm_frame_parser_init(cm_frame_parser *p)
{
    memset(p, 0, sizeof(*p));
}

void cm_frame_parser_free(cm_frame_parser *p)
{
    free(p->body);
    cm_frame_parser_init(p);
}

cm_err cm_frame_parser_feed(cm_frame_parser *p, const uint8_t *data, size_t len,
                            cm_frame_cb cb, void *user)
{
    while (len > 0) {
        if (!p->in_body) {
            /* collect the 3 length bytes (may arrive split across feeds) */
            size_t need = CM_FRAME_LENGTH_SIZE - p->hdr_len;
            size_t take = len < need ? len : need;

            memcpy(p->hdr + p->hdr_len, data, take);
            p->hdr_len += take;
            data += take;
            len -= take;
            if (p->hdr_len < CM_FRAME_LENGTH_SIZE)
                break;
            p->body_len = ((size_t)p->hdr[0] << 16) | ((size_t)p->hdr[1] << 8) | p->hdr[2];
            p->body_got = 0;
            p->hdr_len = 0;
            if (len >= p->body_len) {
                /* whole frame is already in this chunk: no copy */
                cm_err e = cb(user, data, p->body_len);
                data += p->body_len;
                len -= p->body_len;
                p->body_len = 0;
                if (e != CM_OK)
                    return e;
                continue;
            }
            p->body = (uint8_t *)malloc(p->body_len ? p->body_len : 1);
            if (p->body == NULL)
                return CM_ERR_NOMEM;
            p->in_body = 1;
        }
        {
            size_t need = p->body_len - p->body_got;
            size_t take = len < need ? len : need;

            memcpy(p->body + p->body_got, data, take);
            p->body_got += take;
            data += take;
            len -= take;
            if (p->body_got == p->body_len) {
                uint8_t *frame = p->body;
                size_t flen = p->body_len;
                cm_err e;

                p->body = NULL;
                p->in_body = 0;
                p->body_len = p->body_got = 0;
                e = cb(user, frame, flen);
                free(frame);
                if (e != CM_OK)
                    return e;
            }
        }
    }
    return CM_OK;
}
