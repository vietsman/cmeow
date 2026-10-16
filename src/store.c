/* See include/common.h for license and attribution. Port of whatsmeow/store. */
#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "buf.h"
#include "handshake.h"
#include "signal_crypto.h"

/* ------------------------------------------------------------------ kv map */
cm_kv *cm_kvmap_find(const cm_kvmap *m, const char *key)
{
    size_t i;

    for (i = 0; i < m->n; i++)
        if (strcmp(m->e[i].key, key) == 0)
            return &m->e[i];
    return NULL;
}

cm_err cm_kvmap_put(cm_kvmap *m, const char *key, const uint8_t *val, size_t len)
{
    cm_kv *kv = cm_kvmap_find(m, key);
    uint8_t *copy = (uint8_t *)cm_memdup(val, len);

    if (copy == NULL)
        return CM_ERR_NOMEM;
    if (kv != NULL) {
        cm_cleanse(kv->val, kv->len);
        free(kv->val);
        kv->val = copy;
        kv->len = len;
        return CM_OK;
    }
    if (m->n == m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 16;
        cm_kv *ne = (cm_kv *)realloc(m->e, nc * sizeof(cm_kv));

        if (ne == NULL) {
            free(copy);
            return CM_ERR_NOMEM;
        }
        m->e = ne;
        m->cap = nc;
    }
    m->e[m->n].key = cm_strdup(key);
    if (m->e[m->n].key == NULL) {
        free(copy);
        return CM_ERR_NOMEM;
    }
    m->e[m->n].val = copy;
    m->e[m->n].len = len;
    m->e[m->n].flag = 0;
    m->n++;
    return CM_OK;
}

int cm_kvmap_del(cm_kvmap *m, const char *key)
{
    cm_kv *kv = cm_kvmap_find(m, key);

    if (kv == NULL)
        return 0;
    cm_cleanse(kv->val, kv->len);
    free(kv->val);
    free(kv->key);
    *kv = m->e[--m->n];
    return 1;
}

void cm_kvmap_free(cm_kvmap *m)
{
    size_t i;

    for (i = 0; i < m->n; i++) {
        cm_cleanse(m->e[i].val, m->e[i].len);
        free(m->e[i].val);
        free(m->e[i].key);
    }
    free(m->e);
    memset(m, 0, sizeof(*m));
}

/* ------------------------------------------------------- libsignal glue */
static void addr_key(char *out, size_t cap, const signal_protocol_address *a)
{
    snprintf(out, cap, "%.*s.%d", (int)a->name_len, a->name, (int)a->device_id);
}

static signal_buffer *buf_of(const uint8_t *p, size_t n)
{
    return signal_buffer_create(p, n);
}

static int ss_load(signal_buffer **record, signal_buffer **user_record,
                   const signal_protocol_address *a, void *u)
{
    cm_device *d = (cm_device *)u;
    char k[300];
    cm_kv *kv;

    (void)user_record;
    addr_key(k, sizeof(k), a);
    kv = cm_kvmap_find(&d->sessions, k);
    if (kv == NULL)
        return 0;
    *record = buf_of(kv->val, kv->len);
    return *record ? 1 : SG_ERR_NOMEM;
}

static int ss_subdevs(signal_int_list **sessions, const char *name, size_t name_len, void *u)
{
    cm_device *d = (cm_device *)u;
    signal_int_list *l = signal_int_list_alloc();
    size_t i;

    if (l == NULL)
        return SG_ERR_NOMEM;
    for (i = 0; i < d->sessions.n; i++) {
        const char *k = d->sessions.e[i].key;
        const char *dot = strrchr(k, '.');

        if (dot != NULL && (size_t)(dot - k) == name_len && memcmp(k, name, name_len) == 0 &&
            atoi(dot + 1) != 0)
            signal_int_list_push_back(l, atoi(dot + 1));
    }
    *sessions = l;
    return (int)signal_int_list_size(l);
}

static int ss_store(const signal_protocol_address *a, uint8_t *rec, size_t len, uint8_t *ur,
                    size_t url, void *u)
{
    char k[300];

    (void)ur;
    (void)url;
    addr_key(k, sizeof(k), a);
    return cm_kvmap_put(&((cm_device *)u)->sessions, k, rec, len) == CM_OK ? 0 : SG_ERR_NOMEM;
}

static int ss_contains(const signal_protocol_address *a, void *u)
{
    char k[300];

    addr_key(k, sizeof(k), a);
    return cm_kvmap_find(&((cm_device *)u)->sessions, k) != NULL;
}

static int ss_delete(const signal_protocol_address *a, void *u)
{
    char k[300];

    addr_key(k, sizeof(k), a);
    return cm_kvmap_del(&((cm_device *)u)->sessions, k);
}

static int ss_delete_all(const char *name, size_t name_len, void *u)
{
    cm_device *d = (cm_device *)u;
    size_t i = 0;
    int n = 0;

    while (i < d->sessions.n) {
        const char *k = d->sessions.e[i].key;
        const char *dot = strrchr(k, '.');

        if (dot != NULL && (size_t)(dot - k) == name_len && memcmp(k, name, name_len) == 0) {
            cm_kvmap_del(&d->sessions, k);
            n++;
        } else {
            i++;
        }
    }
    return n;
}

static void noop_destroy(void *u) { (void)u; }

static void pk_key(char *out, uint32_t id) { snprintf(out, 16, "%lu", (unsigned long)id); }

static int make_pair(ec_key_pair **kp, const uint8_t priv[32], const uint8_t pub[32],
                     signal_context *ctx)
{
    uint8_t pub33[33];
    ec_public_key *pu = NULL;
    ec_private_key *pr = NULL;
    int r;

    pub33[0] = 5;
    memcpy(pub33 + 1, pub, 32);
    r = curve_decode_point(&pu, pub33, 33, ctx);
    if (r < 0)
        return r;
    r = curve_decode_private_point(&pr, priv, 32, ctx);
    if (r < 0) {
        SIGNAL_UNREF(pu);
        return r;
    }
    r = ec_key_pair_create(kp, pu, pr);
    SIGNAL_UNREF(pu);
    SIGNAL_UNREF(pr);
    return r;
}

static int pk_load(signal_buffer **record, uint32_t id, void *u)
{
    cm_device *d = (cm_device *)u;
    char k[16];
    cm_kv *kv;
    ec_key_pair *kp = NULL;
    session_pre_key *pk = NULL;
    int r;

    pk_key(k, id);
    kv = cm_kvmap_find(&d->prekeys, k);
    if (kv == NULL || kv->len != 64)
        return SG_ERR_INVALID_KEY_ID;
    r = make_pair(&kp, kv->val, kv->val + 32, d->sctx);
    if (r < 0)
        return r;
    r = session_pre_key_create(&pk, id, kp);
    SIGNAL_UNREF(kp);
    if (r < 0)
        return r;
    r = session_pre_key_serialize(record, pk);
    SIGNAL_UNREF(pk);
    return r < 0 ? r : SG_SUCCESS;
}

static int pk_store(uint32_t id, uint8_t *rec, size_t len, void *u)
{
    (void)id; (void)rec; (void)len; (void)u;
    return SG_ERR_UNKNOWN; /* whatsmeow panics here too: prekeys come from cm_device_* only */
}

static int pk_contains(uint32_t id, void *u)
{
    char k[16];

    pk_key(k, id);
    return cm_kvmap_find(&((cm_device *)u)->prekeys, k) != NULL;
}

static int pk_remove(uint32_t id, void *u)
{
    char k[16];

    pk_key(k, id);
    cm_kvmap_del(&((cm_device *)u)->prekeys, k);
    return 0;
}

static int spk_load(signal_buffer **record, uint32_t id, void *u)
{
    cm_device *d = (cm_device *)u;
    ec_key_pair *kp = NULL;
    session_signed_pre_key *sp = NULL;
    int r;

    if (id != d->signed_prekey.id)
        return SG_ERR_INVALID_KEY_ID;
    r = make_pair(&kp, d->signed_prekey.key.priv, d->signed_prekey.key.pub, d->sctx);
    if (r < 0)
        return r;
    r = session_signed_pre_key_create(&sp, id, 0, kp, d->signed_prekey.signature, 64);
    SIGNAL_UNREF(kp);
    if (r < 0)
        return r;
    r = session_signed_pre_key_serialize(record, sp);
    SIGNAL_UNREF(sp);
    return r < 0 ? r : SG_SUCCESS;
}

static int spk_store(uint32_t id, uint8_t *rec, size_t len, void *u)
{
    (void)id; (void)rec; (void)len; (void)u;
    return SG_ERR_UNKNOWN;
}

static int spk_contains(uint32_t id, void *u) { return id == ((cm_device *)u)->signed_prekey.id; }
static int spk_remove(uint32_t id, void *u) { (void)id; (void)u; return 0; }

static int ik_pair(signal_buffer **pub, signal_buffer **priv, void *u)
{
    cm_device *d = (cm_device *)u;
    uint8_t p33[33];

    p33[0] = 5;
    memcpy(p33 + 1, d->identity_key.pub, 32);
    *pub = buf_of(p33, 33);
    *priv = buf_of(d->identity_key.priv, 32);
    return (*pub && *priv) ? 0 : SG_ERR_NOMEM;
}

static int ik_regid(void *u, uint32_t *id)
{
    *id = ((cm_device *)u)->registration_id;
    return 0;
}

static int ik_save(const signal_protocol_address *a, uint8_t *key, size_t len, void *u)
{
    char k[300];

    if (len != 33)
        return SG_ERR_INVALID_KEY;
    addr_key(k, sizeof(k), a);
    return cm_kvmap_put(&((cm_device *)u)->identities, k, key + 1, 32) == CM_OK ? 0 : SG_ERR_NOMEM;
}

static int ik_trusted(const signal_protocol_address *a, uint8_t *key, size_t len, void *u)
{
    char k[300];
    cm_kv *kv;

    if (len != 33)
        return 0;
    addr_key(k, sizeof(k), a);
    kv = cm_kvmap_find(&((cm_device *)u)->identities, k);
    return kv == NULL || (kv->len == 32 && memcmp(kv->val, key + 1, 32) == 0);
}

static void sk_name(char *out, size_t cap, const signal_protocol_sender_key_name *n)
{
    snprintf(out, cap, "%.*s::%.*s.%d", (int)n->group_id_len, n->group_id,
             (int)n->sender.name_len, n->sender.name, (int)n->sender.device_id);
}

static int sk_store(const signal_protocol_sender_key_name *n, uint8_t *rec, size_t len,
                    uint8_t *ur, size_t url, void *u)
{
    char k[600];

    (void)ur; (void)url;
    sk_name(k, sizeof(k), n);
    return cm_kvmap_put(&((cm_device *)u)->sender_keys, k, rec, len) == CM_OK ? 0 : SG_ERR_NOMEM;
}

static int sk_load(signal_buffer **rec, signal_buffer **ur,
                   const signal_protocol_sender_key_name *n, void *u)
{
    char k[600];
    cm_kv *kv;

    (void)ur;
    sk_name(k, sizeof(k), n);
    kv = cm_kvmap_find(&((cm_device *)u)->sender_keys, k);
    if (kv == NULL)
        return 0;
    *rec = buf_of(kv->val, kv->len);
    return *rec ? 1 : SG_ERR_NOMEM;
}

static void dummy_log(int level, const char *m, size_t len, void *u)
{
    (void)level; (void)m; (void)len; (void)u;
}

cm_err cm_device_signal_init(cm_device *d)
{
    signal_crypto_provider prov;
    signal_protocol_session_store ss = {ss_load, ss_subdevs, ss_store, ss_contains, ss_delete,
                                        ss_delete_all, noop_destroy, NULL};
    signal_protocol_pre_key_store pk = {pk_load, pk_store, pk_contains, pk_remove, noop_destroy, NULL};
    signal_protocol_signed_pre_key_store sp = {spk_load, spk_store, spk_contains, spk_remove,
                                               noop_destroy, NULL};
    signal_protocol_identity_key_store ik = {ik_pair, ik_regid, ik_save, ik_trusted, noop_destroy, NULL};
    signal_protocol_sender_key_store sk = {sk_store, sk_load, noop_destroy, NULL};

    ss.user_data = pk.user_data = sp.user_data = ik.user_data = sk.user_data = d;
    if (signal_context_create(&d->sctx, d) != 0)
        return CM_ERR_NOMEM;
    cm_signal_crypto_provider(&prov);
    prov.user_data = d;
    if (signal_context_set_crypto_provider(d->sctx, &prov) != 0)
        return CM_ERR_CRYPTO;
    signal_context_set_log_function(d->sctx, dummy_log);
    if (signal_protocol_store_context_create(&d->sstore, d->sctx) != 0)
        return CM_ERR_NOMEM;
    if (signal_protocol_store_context_set_session_store(d->sstore, &ss) != 0 ||
        signal_protocol_store_context_set_pre_key_store(d->sstore, &pk) != 0 ||
        signal_protocol_store_context_set_signed_pre_key_store(d->sstore, &sp) != 0 ||
        signal_protocol_store_context_set_identity_key_store(d->sstore, &ik) != 0 ||
        signal_protocol_store_context_set_sender_key_store(d->sstore, &sk) != 0)
        return CM_ERR_NOMEM;
    return CM_OK;
}

/* --------------------------------------------------------------- device */
static cm_err sign_prekey(const cm_keypair *identity, cm_prekey *pk)
{
    uint8_t m[33];

    m[0] = 5;
    memcpy(m + 1, pk->key.pub, 32);
    pk->has_signature = 1;
    return cm_xeddsa_sign(identity->priv, m, 33, pk->signature);
}

cm_err cm_device_new(cm_device **out)
{
    cm_device *d = (cm_device *)calloc(1, sizeof(*d));
    cm_err e;
    uint8_t r[4];

    if (d == NULL)
        return CM_ERR_NOMEM;
    cm_jid_init(&d->id);
    cm_jid_init(&d->lid);
    if ((e = cm_keypair_generate(&d->noise_key)) != CM_OK ||
        (e = cm_keypair_generate(&d->identity_key)) != CM_OK ||
        (e = cm_keypair_generate(&d->signed_prekey.key)) != CM_OK ||
        (e = cm_random(d->adv_secret_key, 32)) != CM_OK || (e = cm_random(r, 4)) != CM_OK)
        goto fail;
    d->signed_prekey.id = 1;
    if ((e = sign_prekey(&d->identity_key, &d->signed_prekey)) != CM_OK)
        goto fail;
    d->registration_id = ((uint32_t)r[0] << 24 | (uint32_t)r[1] << 16 | (uint32_t)r[2] << 8 | r[3]);
    d->next_prekey_id = 1;
    if ((e = cm_device_signal_init(d)) != CM_OK)
        goto fail;
    *out = d;
    return CM_OK;
fail:
    cm_device_free(d);
    return e;
}

void cm_device_free(cm_device *d)
{
    if (d == NULL)
        return;
    if (d->sstore)
        signal_protocol_store_context_destroy(d->sstore);
    if (d->sctx)
        signal_context_destroy(d->sctx);
    cm_kvmap_free(&d->identities);
    cm_kvmap_free(&d->sessions);
    cm_kvmap_free(&d->sender_keys);
    cm_kvmap_free(&d->app_state_keys);
    cm_kvmap_free(&d->prekeys);
    cm_kvmap_free(&d->lid_map);
    cm_kvmap_free(&d->tc_tokens);
    cm_jid_free(&d->id);
    cm_jid_free(&d->lid);
    free(d->account);
    free(d->platform);
    free(d->business_name);
    free(d->push_name);
    cm_cleanse(d, sizeof(*d));
    free(d);
}

cm_err cm_device_set_id(cm_device *d, const cm_jid *id)
{
    cm_jid_free(&d->id);
    cm_jid_init(&d->id);
    d->has_id = 1;
    return cm_jid_copy(&d->id, id);
}

cm_err cm_signal_address_string(const cm_jid *j, char **out)
{
    char *user = NULL, *s;
    cm_err e = cm_jid_signal_address_user(j, &user);

    if (e != CM_OK)
        return e;
    s = (char *)malloc(strlen(user) + 8);
    if (s == NULL) {
        free(user);
        return CM_ERR_NOMEM;
    }
    sprintf(s, "%s.%u", user, (unsigned)j->device);
    free(user);
    *out = s;
    return CM_OK;
}

/* ------------------------------------------------------------ prekeys */
cm_err cm_device_get_or_gen_prekeys(cm_device *d, uint32_t count, cm_prekey **out, uint32_t *n)
{
    cm_prekey *res = (cm_prekey *)calloc(count ? count : 1, sizeof(cm_prekey));
    uint32_t got = 0;
    size_t i;
    cm_err e;

    if (res == NULL)
        return CM_ERR_NOMEM;
    for (i = 0; i < d->prekeys.n && got < count; i++) {
        cm_kv *kv = &d->prekeys.e[i];

        if (kv->flag == 0 && kv->len == 64) {
            res[got].id = (uint32_t)strtoul(kv->key, NULL, 10);
            memcpy(res[got].key.priv, kv->val, 32);
            memcpy(res[got].key.pub, kv->val + 32, 32);
            got++;
        }
    }
    while (got < count) {
        char k[16];
        uint8_t v[64];

        e = cm_keypair_generate(&res[got].key);
        if (e != CM_OK) {
            free(res);
            return e;
        }
        res[got].id = d->next_prekey_id++;
        memcpy(v, res[got].key.priv, 32);
        memcpy(v + 32, res[got].key.pub, 32);
        pk_key(k, res[got].id);
        e = cm_kvmap_put(&d->prekeys, k, v, 64);
        if (e != CM_OK) {
            free(res);
            return e;
        }
        got++;
    }
    *out = res;
    *n = got;
    return CM_OK;
}

cm_err cm_device_mark_prekeys_uploaded(cm_device *d, uint32_t up_to)
{
    size_t i;

    for (i = 0; i < d->prekeys.n; i++)
        if ((uint32_t)strtoul(d->prekeys.e[i].key, NULL, 10) <= up_to)
            d->prekeys.e[i].flag = 1;
    return CM_OK;
}

size_t cm_device_uploaded_prekey_count(const cm_device *d)
{
    size_t i, n = 0;

    for (i = 0; i < d->prekeys.n; i++)
        n += d->prekeys.e[i].flag != 0;
    return n;
}

/* ------------------------------------------------------- LID mapping */
static int lid_set(cm_kvmap *m, const char *pfx, const char *k, const char *v)
{
    char key[256];
    cm_kv *e;

    if (snprintf(key, sizeof key, "%s%s", pfx, k) >= (int)sizeof key)
        return 0;
    e = cm_kvmap_find(m, key);
    if (e != NULL && strcmp((const char *)e->val, v) == 0)
        return 0;
    return cm_kvmap_put(m, key, (const uint8_t *)v, strlen(v) + 1) == CM_OK;
}

int cm_device_lid_put(cm_device *d, const char *pn_user, const char *lid_user)
{
    int a, b;

    if (pn_user == NULL || lid_user == NULL || !pn_user[0] || !lid_user[0])
        return 0;
    a = lid_set(&d->lid_map, "p:", pn_user, lid_user);
    b = lid_set(&d->lid_map, "l:", lid_user, pn_user);
    return a || b;
}

static const char *lid_get(const cm_device *d, const char *pfx, const char *k)
{
    char key[256];
    cm_kv *e;

    if (k == NULL || snprintf(key, sizeof key, "%s%s", pfx, k) >= (int)sizeof key)
        return NULL;
    e = cm_kvmap_find(&d->lid_map, key);
    return e ? (const char *)e->val : NULL;
}

const char *cm_device_lid_for_pn(const cm_device *d, const char *pn_user) { return lid_get(d, "p:", pn_user); }
const char *cm_device_pn_for_lid(const cm_device *d, const char *lid_user) { return lid_get(d, "l:", lid_user); }

/* ------------------------------------------------------- persistence */
#define MAGIC "CMDEV001"

static void put32(cm_buf *b, uint32_t v)
{
    uint8_t x[4];

    x[0] = (uint8_t)(v >> 24); x[1] = (uint8_t)(v >> 16); x[2] = (uint8_t)(v >> 8); x[3] = (uint8_t)v;
    cm_buf_put(b, x, 4);
}

static void putbytes(cm_buf *b, const void *p, size_t n)
{
    put32(b, (uint32_t)n);
    cm_buf_put(b, p, n);
}

static void putstr(cm_buf *b, const char *s)
{
    putbytes(b, s ? s : "", s ? strlen(s) : 0);
}

static void putmap(cm_buf *b, const cm_kvmap *m)
{
    size_t i;

    put32(b, (uint32_t)m->n);
    for (i = 0; i < m->n; i++) {
        putstr(b, m->e[i].key);
        putbytes(b, m->e[i].val, m->e[i].len);
        put32(b, m->e[i].flag);
    }
}

cm_err cm_device_save(const cm_device *d, const char *path)
{
    cm_buf b;
    char tmp[1024];
    FILE *f;
    char *ids = NULL, *lids = NULL;
    cm_err e = CM_OK;

    cm_buf_init(&b);
    cm_buf_put(&b, MAGIC, 8);
    cm_buf_put(&b, &d->noise_key, sizeof(cm_keypair));
    cm_buf_put(&b, &d->identity_key, sizeof(cm_keypair));
    put32(&b, d->signed_prekey.id);
    cm_buf_put(&b, &d->signed_prekey.key, sizeof(cm_keypair));
    cm_buf_put(&b, d->signed_prekey.signature, 64);
    put32(&b, d->registration_id);
    cm_buf_put(&b, d->adv_secret_key, 32);
    put32(&b, d->next_prekey_id);
    if (d->has_id) {
        e = cm_jid_to_ad_string(&d->id, &ids);
        if (e != CM_OK)
            goto out;
    }
    if (!cm_jid_is_empty(&d->lid)) {
        e = cm_jid_to_ad_string(&d->lid, &lids);
        if (e != CM_OK)
            goto out;
    }
    put32(&b, d->has_id);
    putstr(&b, ids);
    putstr(&b, lids);
    putbytes(&b, d->account, d->account_len);
    putstr(&b, d->platform);
    putstr(&b, d->business_name);
    putstr(&b, d->push_name);
    putmap(&b, &d->identities);
    putmap(&b, &d->sessions);
    putmap(&b, &d->sender_keys);
    putmap(&b, &d->app_state_keys);
    putmap(&b, &d->prekeys);
    putmap(&b, &d->lid_map);
    putmap(&b, &d->tc_tokens);
    if (b.err != CM_OK) {
        e = b.err;
        goto out;
    }
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
        e = CM_ERR_ARG;
        goto out;
    }
    f = fopen(tmp, "wb");
    if (f == NULL) {
        e = CM_ERR_IO;
        goto out;
    }
    if (fwrite(b.data, 1, b.len, f) != b.len || fclose(f) != 0 || rename(tmp, path) != 0)
        e = CM_ERR_IO;
out:
    cm_cleanse(b.data, b.len);
    cm_buf_free(&b);
    free(ids);
    free(lids);
    return e;
}

struct rd {
    const uint8_t *p;
    size_t n, off;
    int bad;
};

static const uint8_t *rd_take(struct rd *r, size_t n)
{
    const uint8_t *p;

    if (r->bad || r->n - r->off < n) {
        r->bad = 1;
        return NULL;
    }
    p = r->p + r->off;
    r->off += n;
    return p;
}

static uint32_t rd32(struct rd *r)
{
    const uint8_t *p = rd_take(r, 4);

    return p ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]) : 0;
}

static const uint8_t *rdbytes(struct rd *r, size_t *n)
{
    uint32_t l = rd32(r);

    *n = l;
    return rd_take(r, l);
}

static char *rdstr(struct rd *r)
{
    size_t n;
    const uint8_t *p = rdbytes(r, &n);

    if (p == NULL)
        return NULL;
    return cm_strndup((const char *)p, n);
}

static void rdmap(struct rd *r, cm_kvmap *m)
{
    uint32_t cnt = rd32(r), i;

    for (i = 0; i < cnt && !r->bad; i++) {
        char *k = rdstr(r);
        size_t n;
        const uint8_t *v = rdbytes(r, &n);
        uint32_t flag = rd32(r);

        if (k == NULL || (v == NULL && n != 0) || cm_kvmap_put(m, k, v ? v : (const uint8_t *)"", n) != CM_OK)
            r->bad = 1;
        else
            cm_kvmap_find(m, k)->flag = flag;
        free(k);
    }
}

cm_err cm_device_load(cm_device **out, const char *path)
{
    FILE *f = fopen(path, "rb");
    uint8_t *data = NULL;
    long sz;
    struct rd r;
    cm_device *d = NULL;
    cm_err e = CM_ERR_IO;
    const uint8_t *p;
    char *ids = NULL, *lids = NULL;
    size_t n;

    if (f == NULL)
        return CM_ERR_IO;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return CM_ERR_IO;
    }
    data = (uint8_t *)malloc((size_t)sz + 1);
    if (data == NULL || fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(data);
        return data ? CM_ERR_IO : CM_ERR_NOMEM;
    }
    fclose(f);
    r.p = data; r.n = (size_t)sz; r.off = 0; r.bad = 0;

    d = (cm_device *)calloc(1, sizeof(*d));
    if (d == NULL) {
        free(data);
        return CM_ERR_NOMEM;
    }
    cm_jid_init(&d->id);
    cm_jid_init(&d->lid);
    p = rd_take(&r, 8);
    if (p == NULL || memcmp(p, MAGIC, 8) != 0) {
        e = CM_ERR_PROTO;
        goto fail;
    }
#define RDCOPY(dst, len) do { const uint8_t *q_ = rd_take(&r, (len)); if (q_) memcpy((dst), q_, (len)); } while (0)
    RDCOPY(&d->noise_key, sizeof(cm_keypair));
    RDCOPY(&d->identity_key, sizeof(cm_keypair));
    d->signed_prekey.id = rd32(&r);
    RDCOPY(&d->signed_prekey.key, sizeof(cm_keypair));
    RDCOPY(d->signed_prekey.signature, 64);
    d->signed_prekey.has_signature = 1;
    d->registration_id = rd32(&r);
    RDCOPY(d->adv_secret_key, 32);
    d->next_prekey_id = rd32(&r);
    d->has_id = (int)rd32(&r);
    ids = rdstr(&r);
    lids = rdstr(&r);
    p = rdbytes(&r, &n);
    if (p != NULL && n > 0) {
        d->account = (uint8_t *)cm_memdup(p, n);
        d->account_len = n;
    }
    d->platform = rdstr(&r);
    d->business_name = rdstr(&r);
    d->push_name = rdstr(&r);
    rdmap(&r, &d->identities);
    rdmap(&r, &d->sessions);
    rdmap(&r, &d->sender_keys);
    rdmap(&r, &d->app_state_keys);
    rdmap(&r, &d->prekeys);
    if (r.off < r.n) /* absent in files written before LID support */
        rdmap(&r, &d->lid_map);
    if (r.off < r.n)
        rdmap(&r, &d->tc_tokens);
#undef RDCOPY
    if (r.bad) {
        e = CM_ERR_PROTO;
        goto fail;
    }
    if (d->has_id && (ids == NULL || cm_jid_parse(&d->id, ids) != CM_OK)) {
        e = CM_ERR_PROTO;
        goto fail;
    }
    if (lids != NULL && lids[0] != '\0' && cm_jid_parse(&d->lid, lids) != CM_OK) {
        e = CM_ERR_PROTO;
        goto fail;
    }
    if ((e = cm_device_signal_init(d)) != CM_OK)
        goto fail;
    free(ids);
    free(lids);
    cm_cleanse(data, (size_t)sz);
    free(data);
    *out = d;
    return CM_OK;
fail:
    free(ids);
    free(lids);
    cm_cleanse(data, (size_t)sz);
    free(data);
    cm_device_free(d);
    return e;
}
