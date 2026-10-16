/* See include/common.h for license and attribution. Port of appstate/{lthash,hash,keys,decode,encode}.go crypto. */
#include "appstate_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto.h"

/* ---------------------------------------------------------------- LTHash */
void as_lthash_apply(uint8_t hash[128], const uint8_t *item, size_t len, int subtract)
{
    static const char info[] = "WhatsApp Patch Integrity";
    uint8_t x[128];
    size_t i;

    if (cm_hkdf_sha256(item, len, NULL, 0, info, sizeof(info) - 1, x, sizeof(x)) != CM_OK)
        return;
    for (i = 0; i < 128; i += 2) {
        uint16_t a = (uint16_t)(hash[i] | hash[i + 1] << 8);
        uint16_t b = (uint16_t)(x[i] | x[i + 1] << 8);
        uint16_t r = subtract ? (uint16_t)(a - b) : (uint16_t)(a + b);

        hash[i] = (uint8_t)(r & 0xff);
        hash[i + 1] = (uint8_t)(r >> 8);
    }
}

void cm_lthash_subtract_then_add(uint8_t hash[CM_LTHASH_LEN], const uint8_t *const *sub, const size_t *sublen,
                                 size_t nsub, const uint8_t *const *add, const size_t *addlen, size_t nadd)
{
    size_t i;

    for (i = 0; i < nsub; i++)
        as_lthash_apply(hash, sub[i], sublen[i], 1);
    for (i = 0; i < nadd; i++)
        as_lthash_apply(hash, add[i], addlen[i], 0);
}

/* ---------------------------------------------------------------- keys */
cm_err as_expand_keys(const uint8_t *key_data, size_t len, as_keys *out)
{
    static const char info[] = "WhatsApp Mutation Keys";
    uint8_t x[160];
    cm_err e = cm_hkdf_sha256(key_data, len, NULL, 0, info, sizeof(info) - 1, x, sizeof(x));

    if (e != CM_OK)
        return e;
    memcpy(out->index, x, 32);
    memcpy(out->value_enc, x + 32, 32);
    memcpy(out->value_mac, x + 64, 32);
    memcpy(out->snapshot_mac, x + 96, 32);
    memcpy(out->patch_mac, x + 128, 32);
    cm_cleanse(x, sizeof(x));
    return CM_OK;
}

/* ---------------------------------------------------------------- MACs */
static void put_u64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

cm_err as_snapshot_mac(const uint8_t hash[128], uint64_t version, const char *name, const uint8_t key[32],
                       uint8_t out[32])
{
    size_t nl = strlen(name);
    uint8_t *b = (uint8_t *)malloc(128 + 8 + nl);
    cm_err e;

    if (b == NULL)
        return CM_ERR_NOMEM;
    memcpy(b, hash, 128);
    put_u64(b + 128, version);
    memcpy(b + 136, name, nl);
    e = cm_hmac_sha256(key, 32, b, 128 + 8 + nl, out);
    free(b);
    return e;
}

cm_err as_patch_mac(const SPatch *p, const char *name, const uint8_t key[32], uint64_t version, uint8_t out[32])
{
    size_t nl = strlen(name), i, total = (p->has_snapshotmac ? p->snapshotmac.len : 0) + 8 + nl, o = 0;
    uint8_t *b;
    cm_err e = CM_OK;

    for (i = 0; i < p->n_mutations; i++) {
        const WAWebProtobufsServerSync__SyncdValue *v = p->mutations[i]->record ? p->mutations[i]->record->value : NULL;

        if (v == NULL || !v->has_blob || v->blob.len < 32)
            return CM_ERR_PROTO;
        total += 32;
    }
    b = (uint8_t *)malloc(total);
    if (b == NULL)
        return CM_ERR_NOMEM;
    if (p->has_snapshotmac) {
        memcpy(b, p->snapshotmac.data, p->snapshotmac.len);
        o = p->snapshotmac.len;
    }
    for (i = 0; i < p->n_mutations; i++) {
        const ProtobufCBinaryData *bl = &p->mutations[i]->record->value->blob;

        memcpy(b + o, bl->data + bl->len - 32, 32);
        o += 32;
    }
    put_u64(b + o, version);
    o += 8;
    memcpy(b + o, name, nl);
    o += nl;
    e = cm_hmac_sha256(key, 32, b, o, out);
    free(b);
    return e;
}

cm_err as_content_mac(int op, const uint8_t *data, size_t len, const uint8_t *key_id, size_t kid_len,
                      const uint8_t key[32], uint8_t out[32])
{
    uint8_t *b = (uint8_t *)malloc(1 + kid_len + len + 8), full[64];
    unsigned int ol = 64;

    if (b == NULL)
        return CM_ERR_NOMEM;
    b[0] = (uint8_t)(op + 1);
    memcpy(b + 1, key_id, kid_len);
    memcpy(b + 1 + kid_len, data, len);
    put_u64(b + 1 + kid_len + len, (uint64_t)kid_len + 1);
    if (HMAC(EVP_sha512(), key, 32, b, 1 + kid_len + len + 8, full, &ol) == NULL) {
        free(b);
        return CM_ERR_CRYPTO;
    }
    memcpy(out, full, 32);
    free(b);
    return CM_OK;
}

cm_err as_index_mac(const uint8_t key[32], const uint8_t *index_json, size_t len, uint8_t out[32])
{
    return cm_hmac_sha256(key, 32, index_json, len, out);
}

/* ---------------------------------------------------------------- AES-CBC values */
cm_err as_decrypt_value(const uint8_t key[32], const uint8_t *blob, size_t len, uint8_t **out, size_t *olen)
{
    EVP_CIPHER_CTX *cc;
    uint8_t *buf;
    int l1 = 0, l2 = 0;
    cm_err e = CM_ERR_AUTH;

    if (len < 32 || (len - 16) % 16 != 0)
        return CM_ERR_PROTO;
    cc = EVP_CIPHER_CTX_new();
    buf = (uint8_t *)malloc(len);
    if (cc == NULL || buf == NULL) {
        EVP_CIPHER_CTX_free(cc);
        free(buf);
        return CM_ERR_NOMEM;
    }
    if (EVP_DecryptInit_ex(cc, EVP_aes_256_cbc(), NULL, key, blob) == 1 &&
        EVP_DecryptUpdate(cc, buf, &l1, blob + 16, (int)(len - 16)) == 1 &&
        EVP_DecryptFinal_ex(cc, buf + l1, &l2) == 1) {
        *out = buf;
        *olen = (size_t)(l1 + l2);
        buf = NULL;
        e = CM_OK;
    }
    EVP_CIPHER_CTX_free(cc);
    free(buf);
    return e;
}

cm_err as_encrypt_value(const uint8_t key[32], const uint8_t *plain, size_t len, uint8_t **out, size_t *olen)
{
    EVP_CIPHER_CTX *cc = EVP_CIPHER_CTX_new();
    uint8_t *buf = (uint8_t *)malloc(16 + len + 16);
    uint8_t iv[16];
    int l1 = 0, l2 = 0;
    cm_err e = CM_ERR_CRYPTO;

    if (cc == NULL || buf == NULL) {
        EVP_CIPHER_CTX_free(cc);
        free(buf);
        return CM_ERR_NOMEM;
    }
    if (cm_random(iv, 16) == CM_OK && EVP_EncryptInit_ex(cc, EVP_aes_256_cbc(), NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(cc, buf + 16, &l1, plain, (int)len) == 1 &&
        EVP_EncryptFinal_ex(cc, buf + 16 + l1, &l2) == 1) {
        memcpy(buf, iv, 16);
        *out = buf;
        *olen = 16 + (size_t)(l1 + l2);
        buf = NULL;
        e = CM_OK;
    }
    EVP_CIPHER_CTX_free(cc);
    free(buf);
    return e;
}

/* ---------------------------------------------------------------- JSON string-array index */
static int hexv(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int put_utf8(char *o, uint32_t cp)
{
    if (cp < 0x80) {
        o[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        o[0] = (char)(0xC0 | (cp >> 6));
        o[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12));
        o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    o[0] = (char)(0xF0 | (cp >> 18));
    o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

static int hex4(const uint8_t *p, uint32_t *v)
{
    int i;

    *v = 0;
    for (i = 0; i < 4; i++) {
        int h = hexv(p[i]);

        if (h < 0)
            return 0;
        *v = *v * 16 + (uint32_t)h;
    }
    return 1;
}

cm_err cm_appstate_parse_index(const uint8_t *j, size_t n, char ***out, size_t *count)
{
    size_t i = 0, cnt = 0, cap = 4, k;
    char **v = (char **)calloc(cap, sizeof(char *));
    cm_err e = CM_ERR_PROTO;

    if (v == NULL)
        return CM_ERR_NOMEM;
    while (i < n && (j[i] == ' ' || j[i] == '\n' || j[i] == '\t' || j[i] == '\r'))
        i++;
    if (i >= n || j[i] != '[')
        goto fail;
    i++;
    for (;;) {
        char *s, *w;

        while (i < n && (j[i] == ' ' || j[i] == '\n' || j[i] == '\t' || j[i] == '\r' || j[i] == ','))
            i++;
        if (i >= n)
            goto fail;
        if (j[i] == ']')
            break;
        if (j[i] != '"')
            goto fail;
        i++;
        s = (char *)malloc(n - i + 1);
        if (s == NULL) {
            e = CM_ERR_NOMEM;
            goto fail;
        }
        for (w = s; i < n && j[i] != '"';) {
            if (j[i] == '\\') {
                if (i + 1 >= n) {
                    free(s);
                    goto fail;
                }
                i++;
                switch (j[i]) {
                case 'n': *w++ = '\n'; i++; break;
                case 't': *w++ = '\t'; i++; break;
                case 'r': *w++ = '\r'; i++; break;
                case 'b': *w++ = '\b'; i++; break;
                case 'f': *w++ = '\f'; i++; break;
                case 'u': {
                    uint32_t cp, lo;

                    if (i + 4 >= n || !hex4(j + i + 1, &cp)) {
                        free(s);
                        goto fail;
                    }
                    i += 5;
                    if (cp >= 0xD800 && cp < 0xDC00 && i + 5 < n && j[i] == '\\' && j[i + 1] == 'u' &&
                        hex4(j + i + 2, &lo) && lo >= 0xDC00 && lo < 0xE000) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 6;
                    }
                    if (cp == 0) {
                        free(s);
                        goto fail; /* C strings cannot hold NUL */
                    }
                    w += put_utf8(w, cp);
                    break;
                }
                default: *w++ = (char)j[i]; i++; break; /* \" \\ \/ */
                }
            } else {
                *w++ = (char)j[i++];
            }
        }
        if (i >= n) {
            free(s);
            goto fail;
        }
        i++; /* closing quote */
        *w = 0;
        if (cnt == cap) {
            char **nv = (char **)realloc(v, cap * 2 * sizeof(char *));

            if (nv == NULL) {
                free(s);
                e = CM_ERR_NOMEM;
                goto fail;
            }
            v = nv;
            cap *= 2;
        }
        v[cnt++] = s;
    }
    *out = v;
    *count = cnt;
    return CM_OK;
fail:
    for (k = 0; k < cnt; k++)
        free(v[k]);
    free(v);
    return e;
}

char *cm_appstate_marshal_index(const char *const *idx, size_t n)
{
    size_t i, cap = 8;
    char *o, *w;

    for (i = 0; i < n; i++)
        cap += strlen(idx[i]) * 6 + 4;
    o = (char *)malloc(cap);
    if (o == NULL)
        return NULL;
    w = o;
    *w++ = '[';
    for (i = 0; i < n; i++) {
        const unsigned char *s = (const unsigned char *)idx[i];

        if (i)
            *w++ = ',';
        *w++ = '"';
        for (; *s; s++) {
            if (*s == '"' || *s == '\\') {
                *w++ = '\\';
                *w++ = (char)*s;
            } else if (*s < 0x20 || *s == '<' || *s == '>' || *s == '&') { /* Go's encoding/json escapes these */
                w += sprintf(w, "\\u%04x", *s);
            } else {
                *w++ = (char)*s;
            }
        }
        *w++ = '"';
    }
    *w++ = ']';
    *w = 0;
    return o;
}
