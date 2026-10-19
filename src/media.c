/* See include/common.h for license and attribution. Media crypto, mediaconn, download, upload, retry. */
#define _POSIX_C_SOURCE 200112L
#include "media_priv.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "crypto.h"
#include "http.h"
#include "noise.h"
#include "waE2E/WAWebProtobufsE2E.pb-c.h"
#include "waMmsRetry/WAMmsRetry.pb-c.h"

#define MAC_LEN 10

/* ---------------------------------------------------------------- tables */
const char *cm_media_app_info(cm_media_type t)
{
    switch (t) {
    case CM_MEDIA_IMAGE: return "WhatsApp Image Keys";
    case CM_MEDIA_VIDEO: return "WhatsApp Video Keys";
    case CM_MEDIA_AUDIO: return "WhatsApp Audio Keys";
    case CM_MEDIA_DOCUMENT: return "WhatsApp Document Keys";
    case CM_MEDIA_HISTORY: return "WhatsApp History Keys";
    case CM_MEDIA_APPSTATE: return "WhatsApp App State Keys";
    case CM_MEDIA_STICKER_PACK: return "WhatsApp Sticker Pack Keys";
    case CM_MEDIA_LINK_THUMBNAIL: return "WhatsApp Link Thumbnail Keys";
    }
    return "";
}

const char *cm_media_mms_type(cm_media_type t)
{
    switch (t) {
    case CM_MEDIA_IMAGE: return "image";
    case CM_MEDIA_VIDEO: return "video";
    case CM_MEDIA_AUDIO: return "audio";
    case CM_MEDIA_DOCUMENT: return "document";
    case CM_MEDIA_HISTORY: return "md-msg-hist";
    case CM_MEDIA_APPSTATE: return "md-app-state";
    case CM_MEDIA_STICKER_PACK: return "sticker-pack";
    case CM_MEDIA_LINK_THUMBNAIL: return "thumbnail-link";
    }
    return "";
}

/* ---------------------------------------------------------------- hashing primitives (EVP, streaming) */
typedef struct sha {
    EVP_MD_CTX *c;
} sha;

static int sha_init(sha *s)
{
    s->c = EVP_MD_CTX_new();
    return s->c != NULL && EVP_DigestInit_ex(s->c, EVP_sha256(), NULL) == 1;
}

static void sha_upd(sha *s, const void *p, size_t n)
{
    if (n)
        EVP_DigestUpdate(s->c, p, n);
}

static void sha_fin(sha *s, uint8_t out[32])
{
    unsigned int l = 32;

    EVP_DigestFinal_ex(s->c, out, &l);
    EVP_MD_CTX_free(s->c);
    s->c = NULL;
}

static void sha_drop(sha *s)
{
    if (s->c)
        EVP_MD_CTX_free(s->c);
    s->c = NULL;
}

typedef struct hm {
    sha in;
    uint8_t opad[64];
} hm;

static int hm_init(hm *h, const uint8_t key[32])
{
    uint8_t ipad[64];
    size_t i;

    memset(ipad, 0x36, 64);
    memset(h->opad, 0x5c, 64);
    for (i = 0; i < 32; i++) {
        ipad[i] ^= key[i];
        h->opad[i] ^= key[i];
    }
    if (!sha_init(&h->in))
        return 0;
    sha_upd(&h->in, ipad, 64);
    return 1;
}

static void hm_fin(hm *h, uint8_t out[32])
{
    uint8_t inner[32];
    sha o;

    sha_fin(&h->in, inner);
    sha_init(&o);
    sha_upd(&o, h->opad, 64);
    sha_upd(&o, inner, 32);
    sha_fin(&o, out);
}

/* ---------------------------------------------------------------- keys / one-shot crypto */
cm_err cm_media_keys_derive(const uint8_t *media_key, size_t len, cm_media_type t, cm_media_keys *out)
{
    uint8_t x[112];
    const char *info = cm_media_app_info(t);
    cm_err e;

    if (media_key == NULL || len == 0)
        return CM_ERR_ARG;
    e = cm_hkdf_sha256(media_key, len, NULL, 0, info, strlen(info), x, sizeof(x));
    if (e != CM_OK)
        return e;
    memcpy(out->iv, x, 16);
    memcpy(out->cipher_key, x + 16, 32);
    memcpy(out->mac_key, x + 48, 32);
    memcpy(out->ref_key, x + 80, 32);
    cm_cleanse(x, sizeof(x));
    return CM_OK;
}

cm_err cm_media_encrypt(const cm_media_keys *k, const uint8_t *plain, size_t n, uint8_t **out, size_t *olen)
{
    EVP_CIPHER_CTX *cc = EVP_CIPHER_CTX_new();
    uint8_t *buf = (uint8_t *)malloc(n + 16 + MAC_LEN);
    int l1 = 0, l2 = 0;
    hm h;
    uint8_t mac[32];
    cm_err e = CM_ERR_CRYPTO;

    if (cc == NULL || buf == NULL) {
        EVP_CIPHER_CTX_free(cc);
        free(buf);
        return CM_ERR_NOMEM;
    }
    if (EVP_EncryptInit_ex(cc, EVP_aes_256_cbc(), NULL, k->cipher_key, k->iv) != 1 ||
        EVP_EncryptUpdate(cc, buf, &l1, plain, (int)n) != 1 || EVP_EncryptFinal_ex(cc, buf + l1, &l2) != 1)
        goto out;
    if (!hm_init(&h, k->mac_key))
        goto out;
    sha_upd(&h.in, k->iv, 16);
    sha_upd(&h.in, buf, (size_t)(l1 + l2));
    hm_fin(&h, mac);
    memcpy(buf + l1 + l2, mac, MAC_LEN);
    *out = buf;
    *olen = (size_t)(l1 + l2) + MAC_LEN;
    buf = NULL;
    e = CM_OK;
out:
    EVP_CIPHER_CTX_free(cc);
    free(buf);
    return e;
}

cm_err cm_media_decrypt(const cm_media_keys *k, const uint8_t *data, size_t n, uint8_t **plain, size_t *olen)
{
    EVP_CIPHER_CTX *cc;
    uint8_t *buf, mac[32];
    int l1 = 0, l2 = 0;
    hm h;
    cm_err e = CM_ERR_CRYPTO;

    if (n <= MAC_LEN || (n - MAC_LEN) % 16 != 0)
        return CM_ERR_PROTO;
    if (!hm_init(&h, k->mac_key))
        return CM_ERR_CRYPTO;
    sha_upd(&h.in, k->iv, 16);
    sha_upd(&h.in, data, n - MAC_LEN);
    hm_fin(&h, mac);
    if (!cm_ct_equal(mac, data + n - MAC_LEN, MAC_LEN))
        return CM_ERR_AUTH;
    cc = EVP_CIPHER_CTX_new();
    buf = (uint8_t *)malloc(n);
    if (cc == NULL || buf == NULL) {
        EVP_CIPHER_CTX_free(cc);
        free(buf);
        return CM_ERR_NOMEM;
    }
    if (EVP_DecryptInit_ex(cc, EVP_aes_256_cbc(), NULL, k->cipher_key, k->iv) != 1 ||
        EVP_DecryptUpdate(cc, buf, &l1, data, (int)(n - MAC_LEN)) != 1 ||
        EVP_DecryptFinal_ex(cc, buf + l1, &l2) != 1) {
        e = CM_ERR_AUTH;
        goto out;
    }
    *plain = buf;
    *olen = (size_t)(l1 + l2);
    buf = NULL;
    e = CM_OK;
out:
    EVP_CIPHER_CTX_free(cc);
    free(buf);
    return e;
}

/* ---------------------------------------------------------------- small helpers */
static const char B64U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64url(const uint8_t *d, size_t n) /* padded, like Go's URLEncoding */
{
    char *o = (char *)malloc((n + 2) / 3 * 4 + 1), *p = o;
    size_t i;

    if (o == NULL)
        return NULL;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t w = (uint32_t)d[i] << 16 | (uint32_t)d[i + 1] << 8 | d[i + 2];

        *p++ = B64U[w >> 18]; *p++ = B64U[(w >> 12) & 63]; *p++ = B64U[(w >> 6) & 63]; *p++ = B64U[w & 63];
    }
    if (n - i == 1) {
        uint32_t w = (uint32_t)d[i] << 16;

        *p++ = B64U[w >> 18]; *p++ = B64U[(w >> 12) & 63]; *p++ = '='; *p++ = '=';
    } else if (n - i == 2) {
        uint32_t w = (uint32_t)d[i] << 16 | (uint32_t)d[i + 1] << 8;

        *p++ = B64U[w >> 18]; *p++ = B64U[(w >> 12) & 63]; *p++ = B64U[(w >> 6) & 63]; *p++ = '=';
    }
    *p = 0;
    return o;
}

static void sleep_ms(int ms)
{
    poll(NULL, 0, ms);
}

/* ---------------------------------------------------------------- media connection */
typedef struct mstate {
    char *auth;
    int64_t expiry_ms;
    char **hosts;
    size_t nhosts;
} mstate;

static void mc_clear(mstate *m)
{
    size_t i;

    for (i = 0; i < m->nhosts; i++)
        free(m->hosts[i]);
    free(m->hosts);
    free(m->auth);
    m->hosts = NULL;
    m->auth = NULL;
    m->nhosts = 0;
}

void cmi_media_free(cm_client *c)
{
    mstate *m = (mstate *)c->mod_media;

    if (m) {
        mc_clear(m);
        free(m);
        c->mod_media = NULL;
    }
}

static cm_err mc_refresh(cm_client *c, mstate **out)
{
    mstate *m = (mstate *)c->mod_media;
    cm_node q, *resp = NULL;
    const cm_node *mc;
    const char *auth, *ttl;
    size_t i;
    cm_err e;

    if (m == NULL) {
        m = (mstate *)calloc(1, sizeof(*m));
        if (m == NULL)
            return CM_ERR_NOMEM;
        c->mod_media = m;
    }
    if (m->nhosts > 0 && m->expiry_ms > cmi_now_ms()) {
        *out = m;
        return CM_OK;
    }
    cmi_node(&q, "media_conn");
    e = cm_client_iq(c, "w:m", "set", "", &q, 0, &resp);
    if (e != CM_OK) {
        cmi_free_resp_media:
        if (resp) {
            cm_node_free(resp);
            free(resp);
        }
        return e;
    }
    mc = cm_node_child(resp, "media_conn");
    auth = mc ? cmi_attr(mc, "auth") : NULL;
    if (auth == NULL) {
        e = CM_ERR_PROTO;
        goto cmi_free_resp_media;
    }
    ttl = cmi_attr(mc, "ttl");
    mc_clear(m);
    m->auth = cm_strdup(auth);
    m->expiry_ms = cmi_now_ms() + (ttl ? atoi(ttl) : 300) * 1000LL;
    for (i = 0; i < cm_node_nchildren(mc); i++) {
        const cm_node *h = cm_node_child_at(mc, i);
        const char *hn = strcmp(h->tag, "host") == 0 ? cmi_attr(h, "hostname") : NULL;
        char **nv;

        if (hn == NULL)
            continue;
        nv = (char **)realloc(m->hosts, (m->nhosts + 1) * sizeof(char *));
        if (nv == NULL)
            break;
        m->hosts = nv;
        m->hosts[m->nhosts] = cm_strdup(hn);
        if (m->hosts[m->nhosts])
            m->nhosts++;
    }
    cm_node_free(resp);
    free(resp);
    if (m->nhosts == 0 || m->auth == NULL)
        return CM_ERR_PROTO;
    *out = m;
    return CM_OK;
}

/* ---------------------------------------------------------------- download engine */
typedef struct sink {
    int kind; /* 0 = memory, 1 = file */
    uint8_t *mem;
    size_t len, cap;
    FILE *f;
    const char *path;
} sink;

static cm_err sink_reset(sink *s)
{
    if (s->kind == 0) {
        s->len = 0;
        return CM_OK;
    }
    if (s->f)
        fclose(s->f);
    s->f = fopen(s->path, "wb");
    return s->f ? CM_OK : CM_ERR_IO;
}

static int sink_put(sink *s, const uint8_t *p, size_t n)
{
    if (n == 0)
        return 0;
    if (s->kind == 1)
        return fwrite(p, 1, n, s->f) == n ? 0 : -1;
    if (s->len + n > s->cap) {
        size_t nc = s->cap ? s->cap : 4096;
        uint8_t *nm;

        while (nc < s->len + n)
            nc *= 2;
        nm = (uint8_t *)realloc(s->mem, nc);
        if (nm == NULL)
            return -1;
        s->mem = nm;
        s->cap = nc;
    }
    memcpy(s->mem + s->len, p, n);
    s->len += n;
    return 0;
}

typedef struct dl {
    int encrypted, started, failed;
    cm_media_keys k;
    EVP_CIPHER_CTX *cc;
    hm mac;
    sha enc_sha, plain_sha;
    uint8_t tail[MAC_LEN];
    size_t ntail;
    sink *out;
    int http_status;
    cm_err err;
} dl;

static void dl_free(dl *d)
{
    if (d->cc)
        EVP_CIPHER_CTX_free(d->cc);
    d->cc = NULL;
    sha_drop(&d->enc_sha);
    sha_drop(&d->plain_sha);
    sha_drop(&d->mac.in);
}

static int dl_begin(dl *d)
{
    d->ntail = 0;
    d->started = 1;
    d->failed = 0;
    d->err = CM_OK;
    if (!sha_init(&d->enc_sha) || !sha_init(&d->plain_sha))
        return 0;
    if (d->encrypted) {
        d->cc = EVP_CIPHER_CTX_new();
        if (d->cc == NULL || EVP_DecryptInit_ex(d->cc, EVP_aes_256_cbc(), NULL, d->k.cipher_key, d->k.iv) != 1)
            return 0;
        if (!hm_init(&d->mac, d->k.mac_key))
            return 0;
        sha_upd(&d->mac.in, d->k.iv, 16);
    }
    return 1;
}

static int dl_emit(dl *d, const uint8_t *p, size_t n)
{
    sha_upd(&d->plain_sha, p, n);
    return sink_put(d->out, p, n);
}

static int dl_consume(dl *d, const uint8_t *p, size_t n)
{
    uint8_t ob[4096 + 32];

    sha_upd(&d->mac.in, p, n);
    while (n > 0) {
        size_t step = n > 4096 ? 4096 : n;
        int ol = 0;

        if (EVP_DecryptUpdate(d->cc, ob, &ol, p, (int)step) != 1)
            return -1;
        if (dl_emit(d, ob, (size_t)ol) != 0)
            return -1;
        p += step;
        n -= step;
    }
    return 0;
}

static int dl_feed(dl *d, const uint8_t *p, size_t n)
{
    size_t avail, emit, t, e2;
    uint8_t nt[MAC_LEN];

    if (!d->encrypted)
        return dl_emit(d, p, n);
    sha_upd(&d->enc_sha, p, n);
    avail = d->ntail + n;
    if (avail <= MAC_LEN) {
        memcpy(d->tail + d->ntail, p, n);
        d->ntail += n;
        return 0;
    }
    emit = avail - MAC_LEN;
    t = emit < d->ntail ? emit : d->ntail;
    e2 = emit - t;
    if (t && dl_consume(d, d->tail, t) != 0)
        return -1;
    /* new tail = unconsumed old tail || last bytes of p */
    memcpy(nt, d->tail + t, d->ntail - t);
    memcpy(nt + (d->ntail - t), p + e2, n - e2);
    if (e2 && dl_consume(d, p, e2) != 0)
        return -1;
    memcpy(d->tail, nt, MAC_LEN);
    d->ntail = MAC_LEN;
    return 0;
}

static int dl_body(void *ud, int status, const uint8_t *p, size_t n)
{
    dl *d = (dl *)ud;

    d->http_status = status;
    if (status != 200)
        return 0; /* swallow error pages */
    if (dl_feed(d, p, n) != 0) {
        d->failed = 1;
        return -1;
    }
    return 0;
}

/* verifies MAC / padding / hashes after a 200 */
static cm_err dl_finish(dl *d, const uint8_t *enc_sha, const uint8_t *file_sha)
{
    uint8_t digest[32], ob[32];
    int ol = 0;

    if (d->encrypted) {
        if (d->ntail != MAC_LEN)
            return CM_ERR_PROTO;
        hm_fin(&d->mac, digest);
        sha_init(&d->mac.in); /* keep dl_free symmetric */
        if (!cm_ct_equal(digest, d->tail, MAC_LEN))
            return CM_ERR_AUTH;
        if (EVP_DecryptFinal_ex(d->cc, ob, &ol) != 1)
            return CM_ERR_AUTH;
        if (dl_emit(d, ob, (size_t)ol) != 0)
            return CM_ERR_IO;
        sha_fin(&d->enc_sha, digest);
        if (enc_sha && !cm_ct_equal(digest, enc_sha, 32))
            return CM_ERR_AUTH;
    }
    sha_fin(&d->plain_sha, digest);
    if (file_sha && !cm_ct_equal(digest, file_sha, 32))
        return CM_ERR_AUTH;
    return CM_OK;
}

static cm_err dl_attempt_url(cm_client *c, const char *url, cm_download_info *info, sink *out, int *retryable)
{
    dl d;
    cm_http_req req;
    cm_http_opts ho;
    cm_http_resp resp;
    static const char *const hdrs[] = {"Origin: " CM_WA_ORIGIN, "Referer: " CM_WA_ORIGIN "/"};
    cm_err e;

    memset(&d, 0, sizeof(d));
    memset(&req, 0, sizeof(req));
    d.out = out;
    d.encrypted = !(info->media_key == NULL && info->enc_sha256 == NULL);
    *retryable = 0;
    if (d.encrypted) {
        if (info->media_key == NULL)
            return CM_ERR_ARG;
        e = cm_media_keys_derive(info->media_key, info->media_key_len ? info->media_key_len : 32, info->type, &d.k);
        if (e != CM_OK)
            return e;
    }
    if ((e = sink_reset(out)) != CM_OK)
        return e;
    if (!dl_begin(&d)) {
        dl_free(&d);
        return CM_ERR_CRYPTO;
    }
    req.method = "GET";
    req.url = url;
    req.headers = hdrs;
    req.nheaders = 2;
    ho.ca_file = c->ca_file;
    ho.timeout_ms = 30000;
    e = cm_http_do(&req, &ho, &resp, dl_body, &d);
    info->http_status = resp.status;
    if (e != CM_OK) {
        *retryable = !d.failed;
        dl_free(&d);
        return e;
    }
    if (resp.status != 200) {
        *retryable = resp.status == 429 || resp.status >= 500;
        dl_free(&d);
        return CM_ERR_PROTO;
    }
    e = dl_finish(&d, d.encrypted ? info->enc_sha256 : NULL, info->file_sha256);
    dl_free(&d);
    return e;
}

static cm_err download_engine(cm_client *c, cm_download_info *info, sink *out)
{
    mstate *m = NULL;
    size_t h;
    cm_err e = CM_ERR_ARG;

    info->http_status = 0;
    if (info->direct_path && info->direct_path[0]) {
        char *hash = NULL;
        const char *mms = cm_media_mms_type(info->type);

        if (info->direct_path[0] != '/')
            return CM_ERR_ARG;
        if (info->enc_sha256)
            hash = b64url(info->enc_sha256, 32);
        if ((e = mc_refresh(c, &m)) != CM_OK) {
            free(hash);
            return e;
        }
        for (h = 0; h < m->nhosts; h++) {
            size_t ul = strlen(m->hosts[h]) + strlen(info->direct_path) + (hash ? strlen(hash) : 0) + 64;
            char *url = (char *)malloc(ul);
            int attempt;

            if (url == NULL) {
                free(hash);
                return CM_ERR_NOMEM;
            }
            sprintf(url, "https://%s%s%shash=%s&mms-type=%s&__wa-mms=", m->hosts[h], info->direct_path,
                    strchr(info->direct_path, '?') ? "&" : "?", hash ? hash : "", mms);
            for (attempt = 0; attempt < 5; attempt++) {
                int retry = 0;

                e = dl_attempt_url(c, url, info, out, &retry);
                if (e == CM_OK || !retry)
                    break;
                sleep_ms((attempt + 1) * 1000);
            }
            free(url);
            if (e == CM_OK || e == CM_ERR_AUTH || info->http_status == 403 || info->http_status == 404 ||
                info->http_status == 410)
                break;
        }
        free(hash);
        return e;
    }
    if (info->url && info->url[0]) {
        int attempt;

        for (attempt = 0; attempt < 5; attempt++) {
            int retry = 0;

            e = dl_attempt_url(c, info->url, info, out, &retry);
            if (e == CM_OK || !retry)
                break;
            sleep_ms((attempt + 1) * 1000);
        }
        return e;
    }
    return CM_ERR_ARG;
}

cm_err cm_client_download(cm_client *c, cm_download_info *info, uint8_t **out, size_t *len)
{
    sink s;
    cm_err e;

    memset(&s, 0, sizeof(s));
    e = download_engine(c, info, &s);
    if (e != CM_OK) {
        free(s.mem);
        return e;
    }
    if (s.mem == NULL) { /* empty file */
        s.mem = (uint8_t *)malloc(1);
        if (s.mem == NULL)
            return CM_ERR_NOMEM;
    }
    *out = s.mem;
    *len = s.len;
    return CM_OK;
}

cm_err cm_client_download_to_file(cm_client *c, cm_download_info *info, const char *path)
{
    sink s;
    cm_err e;

    memset(&s, 0, sizeof(s));
    s.kind = 1;
    s.path = path;
    e = download_engine(c, info, &s);
    if (s.f && fclose(s.f) != 0 && e == CM_OK)
        e = CM_ERR_IO;
    if (e != CM_OK)
        remove(path);
    return e;
}

cm_err cm_client_download_message(cm_client *c, const uint8_t *msg, size_t len, uint8_t **out, size_t *olen)
{
    WAWebProtobufsE2E__Message *m = waweb_protobufs_e2_e__message__unpack(NULL, len, msg);
    cm_download_info info;
    cm_err e = CM_ERR_ARG;

    if (m == NULL)
        return CM_ERR_PROTO;
    memset(&info, 0, sizeof(info));
    if (m->devicesentmessage && m->devicesentmessage->message) {
        /* unwrap so callers can pass what the event gave them */
        WAWebProtobufsE2E__Message *inner = m->devicesentmessage->message;

        m->devicesentmessage->message = NULL;
        waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
        m = inner;
    }
#define PICK(field, ty)                                                                                         \
    if (m->field) {                                                                                              \
        info.direct_path = m->field->directpath;                                                                 \
        info.url = m->field->url;                                                                                \
        info.media_key = m->field->has_mediakey ? m->field->mediakey.data : NULL;                                \
        info.media_key_len = m->field->has_mediakey ? m->field->mediakey.len : 0;                                \
        info.enc_sha256 = m->field->has_fileencsha256 && m->field->fileencsha256.len == 32                       \
                              ? m->field->fileencsha256.data : NULL;                                             \
        info.file_sha256 = m->field->has_filesha256 && m->field->filesha256.len == 32                            \
                               ? m->field->filesha256.data : NULL;                                               \
        info.type = ty;                                                                                          \
    } else
    PICK(imagemessage, CM_MEDIA_IMAGE)
    PICK(videomessage, CM_MEDIA_VIDEO)
    PICK(audiomessage, CM_MEDIA_AUDIO)
    PICK(documentmessage, CM_MEDIA_DOCUMENT)
    PICK(stickermessage, CM_MEDIA_IMAGE)
    {
        waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
        return CM_ERR_ARG; /* no downloadable media */
    }
#undef PICK
    e = cm_client_download(c, &info, out, olen);
    waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
    return e;
}

/* ---------------------------------------------------------------- upload */
void cm_upload_resp_free(cm_upload_resp *r)
{
    if (r) {
        free(r->url);
        free(r->direct_path);
        free(r->handle);
        free(r->object_id);
        memset(r, 0, sizeof(*r));
    }
}

/* tiny JSON string-field extractor: finds "key":"value" (flat objects only) */
static char *json_str(const char *j, const char *key)
{
    char pat[48];
    const char *p;
    char *o, *w;

    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(j, pat);
    if (p == NULL)
        return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    if (*p != '"')
        return NULL;
    p++;
    o = (char *)malloc(strlen(p) + 1);
    if (o == NULL)
        return NULL;
    for (w = o; *p && *p != '"'; p++) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': *w++ = '\n'; break;
            case 't': *w++ = '\t'; break;
            case 'u': /* \u00XX only (ASCII); anything else is replaced */
                if (p[1] == '0' && p[2] == '0' && p[3] && p[4]) {
                    char hx[3];

                    hx[0] = p[3]; hx[1] = p[4]; hx[2] = 0;
                    *w++ = (char)strtol(hx, NULL, 16);
                    p += 4;
                } else {
                    *w++ = '?';
                    p += 4;
                }
                break;
            default: *w++ = *p; break;
            }
        } else {
            *w++ = *p;
        }
    }
    *w = 0;
    return o;
}

typedef struct respbuf {
    char *d;
    size_t n;
    int status;
} respbuf;

static int resp_body(void *ud, int status, const uint8_t *p, size_t n)
{
    respbuf *r = (respbuf *)ud;
    char *nd;

    r->status = status;
    if (r->n + n > 65536)
        return 0; /* response is a tiny JSON; ignore anything absurd */
    nd = (char *)realloc(r->d, r->n + n + 1);
    if (nd == NULL)
        return -1;
    memcpy(nd + r->n, p, n);
    r->n += n;
    nd[r->n] = 0;
    r->d = nd;
    return 0;
}

typedef struct fread_ud {
    FILE *f;
} fread_ud;

static long file_read_cb(void *ud, uint8_t *b, size_t n)
{
    size_t r = fread(b, 1, n, ((fread_ud *)ud)->f);

    return ferror(((fread_ud *)ud)->f) ? -1 : (long)r;
}

/* POSTs body (file or memory) to the first upload host that accepts it */
static cm_err raw_upload(cm_client *c, FILE *f, const uint8_t *mem, uint64_t size, const uint8_t token_hash[32],
                         const char *prefix, const char *mms, cm_upload_resp *out)
{
    mstate *m = NULL;
    char *token = b64url(token_hash, 32), *auth_e = NULL, *tok_e = NULL;
    size_t h;
    cm_err e;
    static const char *const hdrs[] = {"Origin: " CM_WA_ORIGIN, "Referer: " CM_WA_ORIGIN "/"};

    if (token == NULL)
        return CM_ERR_NOMEM;
    if ((e = mc_refresh(c, &m)) != CM_OK)
        goto out;
    auth_e = cm_url_escape(m->auth);
    tok_e = cm_url_escape(token);
    if (!auth_e || !tok_e) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    e = CM_ERR_IO;
    for (h = 0; h < m->nhosts; h++) {
        size_t ul = strlen(m->hosts[h]) + strlen(prefix) + strlen(mms) + strlen(token) + strlen(auth_e) +
                    strlen(tok_e) + 40;
        char *url = (char *)malloc(ul);
        cm_http_req req;
        cm_http_opts ho;
        cm_http_resp hr;
        respbuf rb;
        fread_ud fu;

        if (url == NULL) {
            e = CM_ERR_NOMEM;
            break;
        }
        sprintf(url, "https://%s/%s/%s/%s?auth=%s&token=%s", m->hosts[h], prefix, mms, token, auth_e, tok_e);
        memset(&req, 0, sizeof(req));
        memset(&rb, 0, sizeof(rb));
        req.method = "POST";
        req.url = url;
        req.headers = hdrs;
        req.nheaders = 2;
        req.body_len = size;
        if (f) {
            rewind(f);
            fu.f = f;
            req.body_read = file_read_cb;
            req.body_ud = &fu;
        } else {
            req.body = mem;
        }
        ho.ca_file = c->ca_file;
        ho.timeout_ms = 60000;
        e = cm_http_do(&req, &ho, &hr, resp_body, &rb);
        free(url);
        if (e == CM_OK && hr.status == 200 && rb.d) {
            out->url = json_str(rb.d, "url");
            out->direct_path = json_str(rb.d, "direct_path");
            out->handle = json_str(rb.d, "handle");
            out->object_id = json_str(rb.d, "object_id");
            free(rb.d);
            if (out->url == NULL && out->direct_path == NULL)
                e = CM_ERR_PROTO;
            if (e == CM_OK)
                break;
            continue;
        }
        free(rb.d);
        if (e == CM_OK)
            e = CM_ERR_PROTO;
    }
out:
    free(token);
    free(auth_e);
    free(tok_e);
    return e;
}

/* Scratch file for the encrypted upload body: in opts.tmp_dir when given (unlinked right after
 * creation so nothing is left behind), else tmpfile(). */
static FILE *scratch_file(cm_client *c)
{
    static unsigned seq;
    char *name;
    FILE *f;
    uint8_t r[4];
    size_t n;

    if (c->tmp_dir == NULL || c->tmp_dir[0] == '\0')
        return tmpfile();
    n = strlen(c->tmp_dir) + 40;
    name = (char *)malloc(n);
    if (name == NULL)
        return NULL;
    cm_random(r, sizeof r);
    sprintf(name, "%s/cmeow-%02x%02x%02x%02x-%u.tmp", c->tmp_dir, r[0], r[1], r[2], r[3], ++seq);
    f = fopen(name, "w+b");
    if (f != NULL)
        remove(name);
    free(name);
    return f;
}

cm_err cm_client_upload_stream(cm_client *c, cm_media_read_cb rd, void *ud, cm_media_type t, cm_upload_resp *out)
{
    cm_media_keys k;
    EVP_CIPHER_CTX *cc = EVP_CIPHER_CTX_new();
    FILE *tmp = scratch_file(c);
    hm mac;
    sha plain, enc;
    uint8_t in[4096], ob[4096 + 32], digest[32];
    uint64_t total = 0, upsize;
    int ol = 0, started = 0;
    long r;
    cm_err e = CM_ERR_CRYPTO;

    memset(out, 0, sizeof(*out));
    memset(&plain, 0, sizeof(plain));
    memset(&enc, 0, sizeof(enc));
    memset(&mac, 0, sizeof(mac));
    if (cc == NULL || tmp == NULL) {
        e = tmp ? CM_ERR_NOMEM : CM_ERR_IO;
        goto out;
    }
    if (cm_random(out->media_key, 32) != CM_OK || cm_media_keys_derive(out->media_key, 32, t, &k) != CM_OK)
        goto out;
    out->has_keys = 1;
    if (EVP_EncryptInit_ex(cc, EVP_aes_256_cbc(), NULL, k.cipher_key, k.iv) != 1 || !hm_init(&mac, k.mac_key) ||
        !sha_init(&plain) || !sha_init(&enc))
        goto out;
    started = 1;
    sha_upd(&mac.in, k.iv, 16);
    while ((r = rd(ud, in, sizeof(in))) > 0) {
        total += (uint64_t)r;
        sha_upd(&plain, in, (size_t)r);
        if (EVP_EncryptUpdate(cc, ob, &ol, in, (int)r) != 1)
            goto out;
        sha_upd(&mac.in, ob, (size_t)ol);
        sha_upd(&enc, ob, (size_t)ol);
        if (fwrite(ob, 1, (size_t)ol, tmp) != (size_t)ol) {
            e = CM_ERR_IO;
            goto out;
        }
    }
    if (r < 0) {
        e = CM_ERR_IO;
        goto out;
    }
    if (EVP_EncryptFinal_ex(cc, ob, &ol) != 1)
        goto out;
    sha_upd(&mac.in, ob, (size_t)ol);
    sha_upd(&enc, ob, (size_t)ol);
    if (ol && fwrite(ob, 1, (size_t)ol, tmp) != (size_t)ol) {
        e = CM_ERR_IO;
        goto out;
    }
    hm_fin(&mac, digest);
    sha_upd(&enc, digest, MAC_LEN);
    if (fwrite(digest, 1, MAC_LEN, tmp) != MAC_LEN || fflush(tmp) != 0) {
        e = CM_ERR_IO;
        goto out;
    }
    sha_fin(&plain, out->file_sha256);
    sha_fin(&enc, out->file_enc_sha256);
    started = 0;
    out->file_length = total;
    {
        long pos = ftell(tmp);

        if (pos < 0) {
            e = CM_ERR_TOO_LARGE; /* > 2 GiB on 32-bit platforms */
            goto out;
        }
        upsize = (uint64_t)pos;
    }
    e = raw_upload(c, tmp, NULL, upsize, out->file_enc_sha256, "mms", cm_media_mms_type(t), out);
out:
    if (started) {
        sha_drop(&plain);
        sha_drop(&enc);
        sha_drop(&mac.in);
    }
    if (cc)
        EVP_CIPHER_CTX_free(cc);
    if (tmp)
        fclose(tmp);
    if (e != CM_OK) {
        cm_upload_resp_free(out);
    }
    return e;
}

typedef struct memrd {
    const uint8_t *p;
    size_t n, off;
} memrd;

static long mem_read_cb(void *ud, uint8_t *b, size_t n)
{
    memrd *m = (memrd *)ud;
    size_t k = m->n - m->off < n ? m->n - m->off : n;

    memcpy(b, m->p + m->off, k);
    m->off += k;
    return (long)k;
}

cm_err cm_client_upload(cm_client *c, const uint8_t *data, size_t len, cm_media_type t, cm_upload_resp *out)
{
    memrd m;

    m.p = data;
    m.n = len;
    m.off = 0;
    return cm_client_upload_stream(c, mem_read_cb, &m, t, out);
}

cm_err cm_client_upload_file(cm_client *c, const char *path, cm_media_type t, cm_upload_resp *out)
{
    fread_ud fu;
    cm_err e;

    fu.f = fopen(path, "rb");
    if (fu.f == NULL)
        return CM_ERR_IO;
    e = cm_client_upload_stream(c, file_read_cb, &fu, t, out);
    fclose(fu.f);
    return e;
}

cm_err cm_client_upload_newsletter(cm_client *c, const uint8_t *data, size_t len, cm_media_type t,
                                   cm_upload_resp *out)
{
    char mms[40];
    uint8_t h[32];
    cm_err e;

    memset(out, 0, sizeof(*out));
    if ((e = cm_sha256(data, len, h)) != CM_OK)
        return e;
    memcpy(out->file_sha256, h, 32);
    out->file_length = len;
    snprintf(mms, sizeof(mms), "newsletter-%s", cm_media_mms_type(t));
    e = raw_upload(c, NULL, data, len, h, "newsletter", mms, out);
    if (e != CM_OK)
        cm_upload_resp_free(out);
    return e;
}

cm_err cm_client_delete_media(cm_client *c, cm_media_type t, const char *direct_path, const uint8_t *enc_sha256,
                              const char *handle)
{
    mstate *m = NULL;
    char *dp, *token, *tok_e, *auth_e, *dmd, *url, *handle_e = NULL;
    const char *q;
    uint8_t *raw;
    size_t dl_, i, n;
    cm_http_req req;
    cm_http_opts ho;
    cm_http_resp hr;
    static const char *const hdrs[] = {"Origin: " CM_WA_ORIGIN, "Referer: " CM_WA_ORIGIN "/"};
    cm_err e;

    if (direct_path == NULL || direct_path[0] == 0)
        return CM_OK;
    if ((e = mc_refresh(c, &m)) != CM_OK)
        return e;
    q = strchr(direct_path, '?');
    dl_ = q ? (size_t)(q - direct_path) : strlen(direct_path);
    dp = (char *)malloc(dl_ + 1);
    raw = (uint8_t *)malloc(dl_ + 1);
    if (dp == NULL || raw == NULL) {
        free(dp);
        free(raw);
        return CM_ERR_NOMEM;
    }
    memcpy(dp, direct_path, dl_);
    dp[dl_] = 0;
    memcpy(raw, dp, dl_);
    token = b64url(enc_sha256, 32);
    dmd = b64url(raw, dl_);
    free(raw);
    if (dmd) { /* RawURLEncoding: strip padding */
        n = strlen(dmd);
        for (i = n; i > 0 && dmd[i - 1] == '='; i--)
            dmd[i - 1] = 0;
    }
    tok_e = token ? cm_url_escape(token) : NULL;
    auth_e = cm_url_escape(m->auth);
    if (handle && handle[0])
        handle_e = cm_url_escape(handle);
    url = (char *)malloc(strlen(m->hosts[0]) + (token ? strlen(token) : 0) * 3 + (dmd ? strlen(dmd) : 0) +
                         (auth_e ? strlen(auth_e) : 0) + (handle_e ? strlen(handle_e) : 0) + 128);
    if (!token || !dmd || !tok_e || !auth_e || !url) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    sprintf(url, "https://%s/mms/%s/%s?auth=%s&d_md=%s&token=%s%s%s", m->hosts[0], cm_media_mms_type(t), token,
            auth_e, dmd, tok_e, handle_e ? "&e_handle=" : "", handle_e ? handle_e : "");
    memset(&req, 0, sizeof(req));
    req.method = "DELETE";
    req.url = url;
    req.headers = hdrs;
    req.nheaders = 2;
    ho.ca_file = c->ca_file;
    ho.timeout_ms = 30000;
    e = cm_http_do(&req, &ho, &hr, NULL, NULL);
    if (e == CM_OK && (hr.status < 200 || hr.status >= 300))
        e = CM_ERR_PROTO;
out:
    free(dp);
    free(token);
    free(tok_e);
    free(auth_e);
    free(dmd);
    free(handle_e);
    free(url);
    return e;
}

/* ---------------------------------------------------------------- message builder */
uint8_t *cm_message_build_media(cm_media_type t, const cm_upload_resp *u, const char *mimetype, const char *caption,
                                const char *filename, int voice_note, size_t *len)
{
    WAWebProtobufsE2E__Message m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__ImageMessage im = WAWEB_PROTOBUFS_E2_E__IMAGE_MESSAGE__INIT;
    WAWebProtobufsE2E__VideoMessage vm = WAWEB_PROTOBUFS_E2_E__VIDEO_MESSAGE__INIT;
    WAWebProtobufsE2E__AudioMessage am = WAWEB_PROTOBUFS_E2_E__AUDIO_MESSAGE__INIT;
    WAWebProtobufsE2E__DocumentMessage dm = WAWEB_PROTOBUFS_E2_E__DOCUMENT_MESSAGE__INIT;
    uint8_t *out;

#define FILL(x)                                                                                                  \
    x.url = u->url;                                                                                              \
    x.directpath = u->direct_path;                                                                               \
    x.mimetype = (char *)mimetype;                                                                               \
    x.has_mediakey = 1; x.mediakey.data = (uint8_t *)u->media_key; x.mediakey.len = 32;                          \
    x.has_fileencsha256 = 1; x.fileencsha256.data = (uint8_t *)u->file_enc_sha256; x.fileencsha256.len = 32;     \
    x.has_filesha256 = 1; x.filesha256.data = (uint8_t *)u->file_sha256; x.filesha256.len = 32;                  \
    x.has_filelength = 1; x.filelength = u->file_length
    switch (t) {
    case CM_MEDIA_IMAGE:
        FILL(im);
        im.caption = (char *)caption;
        m.imagemessage = &im;
        break;
    case CM_MEDIA_VIDEO:
        FILL(vm);
        vm.caption = (char *)caption;
        m.videomessage = &vm;
        break;
    case CM_MEDIA_AUDIO:
        FILL(am);
        am.has_ptt = 1;
        am.ptt = voice_note;
        m.audiomessage = &am;
        break;
    case CM_MEDIA_DOCUMENT:
        FILL(dm);
        dm.caption = (char *)caption;
        dm.filename = (char *)filename;
        m.documentmessage = &dm;
        break;
    default:
        return NULL;
    }
#undef FILL
    *len = waweb_protobufs_e2_e__message__get_packed_size(&m);
    out = (uint8_t *)malloc(*len ? *len : 1);
    if (out)
        waweb_protobufs_e2_e__message__pack(&m, out);
    return out;
}

/* ---------------------------------------------------------------- media retry */
static cm_err retry_key(const uint8_t *mk, size_t kl, uint8_t out[32])
{
    static const char info[] = "WhatsApp Media Retry Notification";

    return cm_hkdf_sha256(mk, kl, NULL, 0, info, sizeof(info) - 1, out, 32);
}

cm_err cm_client_send_media_retry(cm_client *c, const cm_jid *chat, const cm_jid *sender, int is_group,
                                  int from_me, const char *msg_id, const uint8_t *media_key, size_t key_len)
{
    WAMmsRetry__ServerErrorReceipt rc = WAMMS_RETRY__SERVER_ERROR_RECEIPT__INIT;
    uint8_t key[32], iv[12], *pt = NULL, *ct = NULL;
    size_t pl;
    cm_node r, enc, encp, encv, rmr;
    cm_jid own;
    cm_err e;

    if (!c->logged_in || !c->dev->has_id)
        return CM_ERR_CLOSED;
    rc.stanzaid = (char *)msg_id;
    pl = wamms_retry__server_error_receipt__get_packed_size(&rc);
    pt = (uint8_t *)malloc(pl + 1);
    ct = (uint8_t *)malloc(pl + CM_GCM_TAG_LEN);
    if (pt == NULL || ct == NULL) {
        free(pt);
        free(ct);
        return CM_ERR_NOMEM;
    }
    wamms_retry__server_error_receipt__pack(&rc, pt);
    if ((e = retry_key(media_key, key_len, key)) != CM_OK || (e = cm_random(iv, 12)) != CM_OK ||
        (e = cm_aes256gcm_seal(key, iv, msg_id, strlen(msg_id), pt, pl, ct)) != CM_OK)
        goto out;
    cm_jid_init(&own);
    cm_jid_to_non_ad(&own, &c->dev->id);
    cmi_node(&r, "receipt");
    cm_node_set_attr_str(&r, "id", msg_id);
    cm_node_set_attr_jid(&r, "to", &own);
    cm_node_set_attr_str(&r, "type", "server-error");
    cm_jid_free(&own);
    cmi_node(&enc, "encrypt");
    cmi_node(&encp, "enc_p");
    cm_node_set_content_bytes(&encp, ct, pl + CM_GCM_TAG_LEN);
    cm_node_add_child(&enc, &encp);
    cmi_node(&encv, "enc_iv");
    cm_node_set_content_bytes(&encv, iv, 12);
    cm_node_add_child(&enc, &encv);
    cm_node_add_child(&r, &enc);
    cmi_node(&rmr, "rmr");
    cm_node_set_attr_jid(&rmr, "jid", chat);
    cm_node_set_attr_str(&rmr, "from_me", from_me ? "true" : "false");
    if (is_group && sender)
        cm_node_set_attr_jid(&rmr, "participant", sender);
    cm_node_add_child(&r, &rmr);
    e = cm_client_send_node(c, &r);
    cm_node_free(&r);
out:
    free(pt);
    free(ct);
    return e;
}

cm_err cm_media_retry_decrypt(const cm_media_retry_evt *evt, const uint8_t *media_key, size_t key_len,
                              cm_media_retry_result *out)
{
    uint8_t key[32], *pt;
    WAMmsRetry__MediaRetryNotification *n;
    cm_err e;

    memset(out, 0, sizeof(*out));
    if (evt->ciphertext == NULL) {
        out->result = evt->error_code == 2 ? 2 : 0;
        return CM_ERR_PROTO;
    }
    if (evt->ciphertext_len < CM_GCM_TAG_LEN || evt->iv_len != 12)
        return CM_ERR_PROTO;
    if ((e = retry_key(media_key, key_len, key)) != CM_OK)
        return e;
    pt = (uint8_t *)malloc(evt->ciphertext_len);
    if (pt == NULL)
        return CM_ERR_NOMEM;
    e = cm_aes256gcm_open(key, evt->iv, evt->msg_id, strlen(evt->msg_id), evt->ciphertext, evt->ciphertext_len, pt);
    if (e != CM_OK) {
        free(pt);
        return e;
    }
    n = wamms_retry__media_retry_notification__unpack(NULL, evt->ciphertext_len - CM_GCM_TAG_LEN, pt);
    free(pt);
    if (n == NULL)
        return CM_ERR_PROTO;
    out->result = n->has_result ? (int)n->result : 0;
    if (n->directpath && n->has_result && n->result == WAMMS_RETRY__MEDIA_RETRY_NOTIFICATION__RESULT_TYPE__SUCCESS)
        out->direct_path = cm_strdup(n->directpath);
    wamms_retry__media_retry_notification__free_unpacked(n, NULL);
    return CM_OK;
}

void cmi_media_handle_retry_notification(cm_client *c, const cm_node *n)
{
    const cm_node *rmr = cm_node_child(n, "rmr"), *err = cm_node_child(n, "error"), *enc = cm_node_child(n, "encrypt");
    const cm_node *ep, *ev;
    cm_media_retry_evt evt;
    cm_jid chat, sender;
    const char *fm, *t;
    size_t l;

    if (rmr == NULL || cmi_attr(n, "id") == NULL)
        return;
    cm_jid_init(&chat);
    cm_jid_init(&sender);
    memset(&evt, 0, sizeof(evt));
    if (cmi_attr_jid(rmr, "jid", &chat) != CM_OK)
        goto out;
    cmi_attr_jid(rmr, "participant", &sender);
    fm = cmi_attr(rmr, "from_me");
    t = cmi_attr(n, "t");
    evt.msg_id = cmi_attr(n, "id");
    evt.chat = &chat;
    evt.sender = &sender;
    evt.from_me = fm && strcmp(fm, "true") == 0;
    evt.timestamp = t ? (int64_t)strtoll(t, NULL, 10) : 0;
    if (err) {
        const char *code = cmi_attr(err, "code");

        evt.error_code = code ? atoi(code) : 1;
    } else if (enc) {
        ep = cm_node_child(enc, "enc_p");
        ev = cm_node_child(enc, "enc_iv");
        if (ep == NULL || ev == NULL)
            goto out;
        evt.ciphertext = cmi_bytes(ep, &l);
        evt.ciphertext_len = evt.ciphertext ? l : 0;
        evt.iv = cmi_bytes(ev, &l);
        evt.iv_len = evt.iv ? l : 0;
    } else {
        goto out;
    }
    cmi_emit_ext(c, CM_EXT_MEDIA_RETRY, &evt);
out:
    cm_jid_free(&chat);
    cm_jid_free(&sender);
}
