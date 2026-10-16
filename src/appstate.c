/* See include/common.h for license and attribution.
 * Port of whatsmeow appstate/{decode,encode,recovery}.go and appstate.go. */
#define _POSIX_C_SOURCE 200112L
#include "appstate_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <zlib.h>

#include "crypto.h"
#include "media.h"
#include "messaging.h"
#include "waE2E/WAWebProtobufsE2E.pb-c.h"
#include "waSyncdSnapshotRecovery/WAWebProtobufsSyncdSnapshotRecovery.pb-c.h"

#define NCOLL 5
static const char *const COLL_NAMES[NCOLL] = {"critical_block", "critical_unblock_low", "regular_high", "regular",
                                              "regular_low"};

typedef struct as_coll {
    uint64_t version;
    uint8_t hash[128];
    cm_kvmap macs; /* hex(indexMAC) -> valueMAC[32] */
} as_coll;

typedef struct as_state {
    as_coll coll[NCOLL];
    int loaded;
    char **req_key; /* hex key IDs already requested */
    int64_t *req_ts;
    size_t nreq;
} as_state;

/* ---------------------------------------------------------------- helpers */
static void to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int from_hex(const char *s, uint8_t *out, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        int h = s[2 * i], l = s[2 * i + 1];

        h = h >= '0' && h <= '9' ? h - '0' : (h >= 'a' && h <= 'f' ? h - 'a' + 10 : -1);
        l = l >= '0' && l <= '9' ? l - '0' : (l >= 'a' && l <= 'f' ? l - 'a' + 10 : -1);
        if (h < 0 || l < 0)
            return 0;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return 1;
}

static int coll_index(const char *name)
{
    int i;

    for (i = 0; i < NCOLL; i++)
        if (strcmp(COLL_NAMES[i], name) == 0)
            return i;
    return -1;
}

/* ---------------------------------------------------------------- persistence */
static char *state_path(cm_client *c)
{
    char *p;

    if (c->save_path == NULL)
        return NULL;
    p = (char *)malloc(strlen(c->save_path) + 10);
    if (p)
        sprintf(p, "%s.appstate", c->save_path);
    return p;
}

static void put_be(FILE *f, uint64_t v, int n)
{
    int i;

    for (i = n - 1; i >= 0; i--)
        fputc((int)((v >> (8 * i)) & 0xff), f);
}

static int get_be(FILE *f, uint64_t *v, int n)
{
    int i, ch;

    *v = 0;
    for (i = 0; i < n; i++) {
        if ((ch = fgetc(f)) == EOF)
            return 0;
        *v = *v << 8 | (uint64_t)ch;
    }
    return 1;
}

static void as_save(cm_client *c)
{
    as_state *s = (as_state *)c->mod_appstate;
    char *p = state_path(c), *tmp;
    FILE *f;
    int i;
    size_t k;

    if (p == NULL || s == NULL)
        return;
    tmp = (char *)malloc(strlen(p) + 5);
    if (tmp == NULL) {
        free(p);
        return;
    }
    sprintf(tmp, "%s.tmp", p);
    f = fopen(tmp, "wb");
    if (f == NULL)
        goto out;
    fwrite("CMAPPST1", 1, 8, f);
    for (i = 0; i < NCOLL; i++) {
        as_coll *co = &s->coll[i];

        put_be(f, co->version, 8);
        fwrite(co->hash, 1, 128, f);
        put_be(f, co->macs.n, 4);
        for (k = 0; k < co->macs.n; k++) {
            uint8_t im[32];

            if (!from_hex(co->macs.e[k].key, im, 32) || co->macs.e[k].len != 32) {
                memset(im, 0, 32);
            }
            fwrite(im, 1, 32, f);
            fwrite(co->macs.e[k].val, 1, 32, f);
        }
    }
    if (fclose(f) == 0)
        rename(tmp, p);
    else
        remove(tmp);
out:
    free(tmp);
    free(p);
}

static void as_load(cm_client *c, as_state *s)
{
    char *p = state_path(c);
    FILE *f;
    char magic[8];
    int i;

    s->loaded = 1;
    if (p == NULL)
        return;
    f = fopen(p, "rb");
    free(p);
    if (f == NULL)
        return;
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, "CMAPPST1", 8) != 0)
        goto done;
    for (i = 0; i < NCOLL; i++) {
        as_coll *co = &s->coll[i];
        uint64_t n, k;

        if (!get_be(f, &co->version, 8) || fread(co->hash, 1, 128, f) != 128 || !get_be(f, &n, 4))
            goto bad;
        for (k = 0; k < n; k++) {
            uint8_t im[32], vm[32];
            char hx[65];

            if (fread(im, 1, 32, f) != 32 || fread(vm, 1, 32, f) != 32)
                goto bad;
            to_hex(im, 32, hx);
            cm_kvmap_put(&co->macs, hx, vm, 32);
        }
    }
    goto done;
bad: /* a torn file: forget everything, a full sync will rebuild it */
    for (i = 0; i < NCOLL; i++) {
        cm_kvmap_free(&s->coll[i].macs);
        memset(&s->coll[i], 0, sizeof(s->coll[i]));
    }
done:
    fclose(f);
}

static as_state *ast(cm_client *c)
{
    as_state *s = (as_state *)c->mod_appstate;

    if (s == NULL) {
        s = (as_state *)calloc(1, sizeof(*s));
        if (s == NULL)
            return NULL;
        c->mod_appstate = s;
    }
    if (!s->loaded)
        as_load(c, s);
    return s;
}

void cmi_appstate_free(cm_client *c)
{
    as_state *s = (as_state *)c->mod_appstate;
    size_t i;

    if (s == NULL)
        return;
    for (i = 0; i < NCOLL; i++)
        cm_kvmap_free(&s->coll[i].macs);
    for (i = 0; i < s->nreq; i++)
        free(s->req_key[i]);
    free(s->req_key);
    free(s->req_ts);
    free(s);
    c->mod_appstate = NULL;
}

/* ---------------------------------------------------------------- keys */
static cm_err get_keys(cm_client *c, const uint8_t *kid, size_t kl, as_keys *out)
{
    char hx[2 * 64 + 1];
    cm_kv *kv;

    if (kl == 0 || kl > 64)
        return AS_ERR_NOKEY;
    to_hex(kid, kl, hx);
    kv = cm_kvmap_find(&c->dev->app_state_keys, hx);
    if (kv == NULL || kv->len <= 8)
        return AS_ERR_NOKEY;
    return as_expand_keys(kv->val + 8, kv->len - 8, out);
}

/* highest-timestamp key; returns malloc()ed key id */
static uint8_t *latest_key_id(cm_client *c, size_t *len)
{
    const cm_kvmap *m = &c->dev->app_state_keys;
    size_t i, best = (size_t)-1;
    uint64_t bt = 0;
    uint8_t *out;

    for (i = 0; i < m->n; i++) {
        uint64_t t = 0;
        int k;

        if (m->e[i].len <= 8)
            continue;
        for (k = 0; k < 8; k++)
            t = t << 8 | m->e[i].val[k];
        if (best == (size_t)-1 || t > bt) {
            best = i;
            bt = t;
        }
    }
    if (best == (size_t)-1)
        return NULL;
    *len = strlen(m->e[best].key) / 2;
    out = (uint8_t *)malloc(*len);
    if (out && !from_hex(m->e[best].key, out, *len)) {
        free(out);
        return NULL;
    }
    return out;
}

static int have_key(cm_client *c, const uint8_t *kid, size_t kl)
{
    char hx[2 * 64 + 1];

    if (kl == 0 || kl > 64)
        return 0;
    to_hex(kid, kl, hx);
    return cm_kvmap_find(&c->dev->app_state_keys, hx) != NULL;
}

/* ---------------------------------------------------------------- patch lists */
typedef struct plist {
    char name[40];
    int has_more;
    SPatch **patches;
    WAWebProtobufsServerSync__SyncdMutations **ext;
    size_t n;
    SSnap *snap;
} plist;

static void plist_free(plist *pl)
{
    size_t i;

    for (i = 0; i < pl->n; i++) {
        if (pl->ext && pl->ext[i]) {
            pl->patches[i]->mutations = NULL;
            pl->patches[i]->n_mutations = 0;
            waweb_protobufs_server_sync__syncd_mutations__free_unpacked(pl->ext[i], NULL);
        }
        waweb_protobufs_server_sync__syncd_patch__free_unpacked(pl->patches[i], NULL);
    }
    free(pl->patches);
    free(pl->ext);
    if (pl->snap)
        waweb_protobufs_server_sync__syncd_snapshot__free_unpacked(pl->snap, NULL);
    memset(pl, 0, sizeof(*pl));
}

static cm_err download_ref(cm_client *c, const WAWebProtobufsServerSync__ExternalBlobReference *r, uint8_t **out,
                           size_t *len)
{
    cm_download_info info;

    memset(&info, 0, sizeof(info));
    info.direct_path = r->directpath;
    info.media_key = r->has_mediakey ? r->mediakey.data : NULL;
    info.media_key_len = r->has_mediakey ? r->mediakey.len : 0;
    info.enc_sha256 = r->has_fileencsha256 && r->fileencsha256.len == 32 ? r->fileencsha256.data : NULL;
    info.file_sha256 = r->has_filesha256 && r->filesha256.len == 32 ? r->filesha256.data : NULL;
    info.type = CM_MEDIA_APPSTATE;
    return cm_client_download(c, &info, out, len);
}

static cm_err parse_plist(cm_client *c, const cm_node *coll, plist *pl)
{
    const char *nm = cmi_attr(coll, "name"), *hm = cmi_attr(coll, "has_more_patches");
    const cm_node *sn = cm_node_child(coll, "snapshot"), *ps = cm_node_child(coll, "patches");
    size_t i, l;
    cm_err e = CM_OK;

    memset(pl, 0, sizeof(*pl));
    if (nm == NULL || strlen(nm) >= sizeof(pl->name))
        return CM_ERR_PROTO;
    strcpy(pl->name, nm);
    pl->has_more = hm && strcmp(hm, "true") == 0;
    if (sn) {
        const uint8_t *raw = cmi_bytes(sn, &l);

        if (raw) {
            WAWebProtobufsServerSync__ExternalBlobReference *ref =
                waweb_protobufs_server_sync__external_blob_reference__unpack(NULL, l, raw);
            uint8_t *data = NULL;
            size_t dl = 0;

            if (ref == NULL)
                return CM_ERR_PROTO;
            e = download_ref(c, ref, &data, &dl);
            waweb_protobufs_server_sync__external_blob_reference__free_unpacked(ref, NULL);
            if (e != CM_OK)
                return e;
            pl->snap = waweb_protobufs_server_sync__syncd_snapshot__unpack(NULL, dl, data);
            free(data);
            if (pl->snap == NULL)
                return CM_ERR_PROTO;
        }
    }
    if (ps) {
        size_t np = cm_node_nchildren(ps);

        pl->patches = (SPatch **)calloc(np + 1, sizeof(SPatch *));
        pl->ext = (WAWebProtobufsServerSync__SyncdMutations **)calloc(np + 1, sizeof(void *));
        if (pl->patches == NULL || pl->ext == NULL) {
            plist_free(pl);
            return CM_ERR_NOMEM;
        }
        for (i = 0; i < np; i++) {
            const cm_node *pn = cm_node_child_at(ps, i);
            const uint8_t *raw = strcmp(pn->tag, "patch") == 0 ? cmi_bytes(pn, &l) : NULL;
            SPatch *p;

            if (raw == NULL)
                continue;
            p = waweb_protobufs_server_sync__syncd_patch__unpack(NULL, l, raw);
            if (p == NULL) {
                plist_free(pl);
                return CM_ERR_PROTO;
            }
            pl->patches[pl->n] = p;
            pl->ext[pl->n] = NULL;
            pl->n++;
            if (p->externalmutations != NULL) {
                uint8_t *data = NULL;
                size_t dl = 0;
                WAWebProtobufsServerSync__SyncdMutations *dm;

                e = download_ref(c, p->externalmutations, &data, &dl);
                if (e != CM_OK) {
                    plist_free(pl);
                    return e;
                }
                dm = waweb_protobufs_server_sync__syncd_mutations__unpack(NULL, dl, data);
                free(data);
                if (dm == NULL || dm->n_mutations == 0) {
                    if (dm)
                        waweb_protobufs_server_sync__syncd_mutations__free_unpacked(dm, NULL);
                    plist_free(pl);
                    return CM_ERR_PROTO;
                }
                pl->ext[pl->n - 1] = dm;
                p->mutations = dm->mutations;
                p->n_mutations = dm->n_mutations;
            }
        }
    }
    return CM_OK;
}

/* ---------------------------------------------------------------- hash bookkeeping */
static const uint8_t *prev_value_mac(as_coll *co, const SPatch *patch, size_t i, const uint8_t *idx, size_t il)
{
    char hx[65];
    cm_kv *kv;
    size_t k;

    if (il != 32)
        return NULL;
    if (patch) {
        for (k = i; k > 0; k--) {
            const SMut *pm = patch->mutations[k - 1];
            const ProtobufCBinaryData *pi = &pm->record->index->blob;

            if (pi->len == 32 && memcmp(pi->data, idx, 32) == 0) {
                if (!pm->has_operation || pm->operation == WAWEB_PROTOBUFS_SERVER_SYNC__SYNCD_MUTATION__SYNCD_OPERATION__SET) {
                    const ProtobufCBinaryData *v = &pm->record->value->blob;

                    return v->data + v->len - 32;
                }
                return NULL;
            }
        }
    }
    if (co == NULL)
        return NULL;
    to_hex(idx, 32, hx);
    kv = cm_kvmap_find(&co->macs, hx);
    return kv && kv->len == 32 ? kv->val : NULL;
}

static int mut_valid(const SMut *m)
{
    return m->record && m->record->index && m->record->index->has_blob && m->record->value &&
           m->record->value->has_blob && m->record->value->blob.len >= 32 + 16 + 16 && m->record->keyid &&
           m->record->keyid->has_id;
}

static int is_set(const SMut *m)
{
    return !m->has_operation || m->operation == WAWEB_PROTOBUFS_SERVER_SYNC__SYNCD_MUTATION__SYNCD_OPERATION__SET;
}

/* updateHash: subtract previous values of touched indexes, add new SET values */
static cm_err hash_update(uint8_t hash[128], SMut *const *muts, size_t n, as_coll *co, const SPatch *patch)
{
    const uint8_t **rem = (const uint8_t **)calloc(n + 1, sizeof(void *));
    const uint8_t **add = (const uint8_t **)calloc(n + 1, sizeof(void *));
    size_t i, nr = 0, na = 0;

    if (rem == NULL || add == NULL) {
        free(rem);
        free(add);
        return CM_ERR_NOMEM;
    }
    for (i = 0; i < n; i++) {
        const ProtobufCBinaryData *v, *ix;
        const uint8_t *prev;

        if (!mut_valid(muts[i])) {
            free(rem);
            free(add);
            return CM_ERR_PROTO;
        }
        v = &muts[i]->record->value->blob;
        ix = &muts[i]->record->index->blob;
        if (is_set(muts[i]))
            add[na++] = v->data + v->len - 32;
        prev = prev_value_mac(co, patch, i, ix->data, ix->len);
        if (prev)
            rem[nr++] = prev;
    }
    for (i = 0; i < nr; i++)
        as_lthash_apply(hash, rem[i], 32, 1);
    for (i = 0; i < na; i++)
        as_lthash_apply(hash, add[i], 32, 0);
    free(rem);
    free(add);
    return CM_OK;
}

/* ---------------------------------------------------------------- mutation decoding */
typedef struct dmut {
    int is_set;
    uint8_t index_mac[32], value_mac[32];
    char **index;
    size_t nindex;
    SAData *sad;
} dmut;

static void dmut_free(dmut *d)
{
    size_t i;

    for (i = 0; i < d->nindex; i++)
        free(d->index[i]);
    free(d->index);
    if (d->sad)
        waweb_protobuf_sync_action__sync_action_data__free_unpacked(d->sad, NULL);
    memset(d, 0, sizeof(*d));
}

static cm_err decode_mutation(cm_client *c, const SMut *m, int validate, dmut *out)
{
    as_keys k;
    const ProtobufCBinaryData *blob, *kid, *ix;
    uint8_t *plain = NULL, exp[32];
    size_t plen = 0, clen;
    cm_err e;

    memset(out, 0, sizeof(*out));
    if (!mut_valid(m))
        return CM_ERR_PROTO;
    blob = &m->record->value->blob;
    kid = &m->record->keyid->id;
    ix = &m->record->index->blob;
    if (ix->len != 32)
        return CM_ERR_PROTO;
    if ((e = get_keys(c, kid->data, kid->len, &k)) != CM_OK)
        return e;
    clen = blob->len - 32;
    memcpy(out->value_mac, blob->data + clen, 32);
    memcpy(out->index_mac, ix->data, 32);
    out->is_set = is_set(m);
    if (validate) {
        if ((e = as_content_mac(is_set(m) ? 0 : 1, blob->data, clen, kid->data, kid->len, k.value_mac, exp)) != CM_OK)
            return e;
        if (!cm_ct_equal(exp, out->value_mac, 32))
            return CM_ERR_AUTH;
    }
    if ((e = as_decrypt_value(k.value_enc, blob->data, clen, &plain, &plen)) != CM_OK)
        return e;
    out->sad = waweb_protobuf_sync_action__sync_action_data__unpack(NULL, plen, plain);
    free(plain);
    if (out->sad == NULL || !out->sad->has_index) {
        dmut_free(out);
        return CM_ERR_PROTO;
    }
    if (validate) {
        e = as_index_mac(k.index, out->sad->index.data, out->sad->index.len, exp);
        if (e != CM_OK || !cm_ct_equal(exp, out->index_mac, 32)) {
            dmut_free(out);
            return e != CM_OK ? e : CM_ERR_AUTH;
        }
    }
    e = cm_appstate_parse_index(out->sad->index.data, out->sad->index.len, &out->index, &out->nindex);
    if (e != CM_OK) {
        dmut_free(out);
        return e;
    }
    return CM_OK;
}

/* accumulated effect of a patch/snapshot */
typedef struct pout {
    uint8_t (*rem)[32];
    size_t nrem, caprem;
    struct macpair {
        uint8_t i[32], v[32];
    } *add;
    size_t nadd, capadd;
    dmut *muts;
    size_t nmuts;
} pout;

static void pout_free(pout *o)
{
    size_t i;

    for (i = 0; i < o->nmuts; i++)
        dmut_free(&o->muts[i]);
    free(o->muts);
    free(o->rem);
    free(o->add);
    memset(o, 0, sizeof(*o));
}

static cm_err pout_remove(pout *o, const uint8_t im[32])
{
    size_t i, w = 0;

    if (o->nrem == o->caprem) {
        size_t nc = o->caprem ? o->caprem * 2 : 16;
        void *nv = realloc(o->rem, nc * 32);

        if (nv == NULL)
            return CM_ERR_NOMEM;
        o->rem = (uint8_t(*)[32])nv;
        o->caprem = nc;
    }
    memcpy(o->rem[o->nrem++], im, 32);
    for (i = 0; i < o->nadd; i++)
        if (memcmp(o->add[i].i, im, 32) != 0)
            o->add[w++] = o->add[i];
    o->nadd = w;
    return CM_OK;
}

static cm_err pout_add(pout *o, const uint8_t im[32], const uint8_t vm[32])
{
    if (o->nadd == o->capadd) {
        size_t nc = o->capadd ? o->capadd * 2 : 16;
        void *nv = realloc(o->add, nc * sizeof(struct macpair));

        if (nv == NULL)
            return CM_ERR_NOMEM;
        o->add = (struct macpair *)nv;
        o->capadd = nc;
    }
    memcpy(o->add[o->nadd].i, im, 32);
    memcpy(o->add[o->nadd].v, vm, 32);
    o->nadd++;
    return CM_OK;
}

static cm_err decode_mutations(cm_client *c, SMut *const *muts, size_t n, int validate, pout *o)
{
    size_t i;
    cm_err e;

    o->muts = (dmut *)calloc(n + 1, sizeof(dmut));
    if (o->muts == NULL)
        return CM_ERR_NOMEM;
    for (i = 0; i < n; i++) {
        dmut *d = &o->muts[o->nmuts];

        if ((e = decode_mutation(c, muts[i], validate, d)) != CM_OK)
            return e;
        o->nmuts++;
        e = d->is_set ? pout_add(o, d->index_mac, d->value_mac) : pout_remove(o, d->index_mac);
        if (e != CM_OK)
            return e;
    }
    return CM_OK;
}

static void store_macs(as_coll *co, uint64_t version, const uint8_t hash[128], const pout *o)
{
    size_t i;
    char hx[65];

    co->version = version;
    memcpy(co->hash, hash, 128);
    for (i = 0; i < o->nrem; i++) {
        to_hex(o->rem[i], 32, hx);
        cm_kvmap_del(&co->macs, hx);
    }
    for (i = 0; i < o->nadd; i++) {
        to_hex(o->add[i].i, 32, hx);
        cm_kvmap_put(&co->macs, hx, o->add[i].v, 32);
    }
}

/* ---------------------------------------------------------------- events */
static void emit_mutation(cm_client *c, const char *coll, const dmut *d, uint64_t patch_version, int full)
{
    cm_appstate_mutation ev;

    memset(&ev, 0, sizeof(ev));
    ev.collection = coll;
    ev.is_set = d->is_set;
    ev.version = d->sad->has_version ? d->sad->version : 0;
    ev.patch_version = patch_version;
    ev.index = (const char *const *)d->index;
    ev.nindex = d->nindex;
    ev.timestamp = d->sad->value && d->sad->value->has_timestamp ? d->sad->value->timestamp : 0;
    ev.from_full_sync = full;
    ev.action = d->is_set ? d->sad->value : NULL;
    if (d->is_set && d->nindex == 1 && strcmp(d->index[0], CM_AS_IDX_PUSH_NAME) == 0 && d->sad->value &&
        d->sad->value->pushnamesetting && d->sad->value->pushnamesetting->name) {
        free(c->dev->push_name);
        c->dev->push_name = cm_strdup(d->sad->value->pushnamesetting->name);
        cmi_save(c);
    }
    cmi_emit_ext(c, CM_EXT_APPSTATE_MUTATION, &ev);
}

static void emit_sync(cm_client *c, int kind, const char *coll, uint64_t version, int full, int recovery, cm_err err)
{
    cm_appstate_sync_evt ev;

    ev.collection = coll;
    ev.version = version;
    ev.full_sync = full;
    ev.recovery = recovery;
    ev.err = err;
    cmi_emit_ext(c, kind, &ev);
}

/* ---------------------------------------------------------------- applying patches */
static cm_err validate_snapshot_mac(cm_client *c, const char *name, const uint8_t hash[128], uint64_t version,
                                    const ProtobufCBinaryData *keyid, const ProtobufCBinaryData *expected)
{
    as_keys k;
    uint8_t mac[32];
    cm_err e = get_keys(c, keyid->data, keyid->len, &k);

    if (e != CM_OK)
        return e;
    if ((e = as_snapshot_mac(hash, version, name, k.snapshot_mac, mac)) != CM_OK)
        return e;
    return expected->len == 32 && cm_ct_equal(mac, expected->data, 32) ? CM_OK : CM_ERR_AUTH;
}

static cm_err apply_snapshot(cm_client *c, int ci, SSnap *ss, int full)
{
    as_state *s = ast(c);
    as_coll *co = &s->coll[ci];
    uint8_t hash[128];
    SMut **muts;
    size_t i;
    pout out;
    cm_err e;
    uint64_t version = ss->version && ss->version->has_version ? ss->version->version : 0;

    memcpy(hash, co->hash, 128);
    muts = (SMut **)calloc(ss->n_records + 1, sizeof(SMut *));
    if (muts == NULL)
        return CM_ERR_NOMEM;
    for (i = 0; i < ss->n_records; i++) {
        SMut *m = (SMut *)calloc(1, sizeof(SMut));

        if (m == NULL) {
            e = CM_ERR_NOMEM;
            goto out;
        }
        waweb_protobufs_server_sync__syncd_mutation__init(m);
        m->has_operation = 1;
        m->operation = WAWEB_PROTOBUFS_SERVER_SYNC__SYNCD_MUTATION__SYNCD_OPERATION__SET;
        m->record = ss->records[i];
        muts[i] = m;
    }
    memset(&out, 0, sizeof(out));
    if ((e = hash_update(hash, muts, ss->n_records, NULL, NULL)) != CM_OK)
        goto out;
    if (!ss->keyid || !ss->keyid->has_id || !ss->has_mac) {
        e = CM_ERR_PROTO;
        goto out;
    }
    if ((e = validate_snapshot_mac(c, COLL_NAMES[ci], hash, version, &ss->keyid->id, &ss->mac)) != CM_OK)
        goto out;
    if ((e = decode_mutations(c, muts, ss->n_records, 1, &out)) != CM_OK)
        goto out;
    store_macs(co, version, hash, &out);
    for (i = 0; i < out.nmuts; i++)
        emit_mutation(c, COLL_NAMES[ci], &out.muts[i], version, full);
out:
    pout_free(&out);
    for (i = 0; i < ss->n_records; i++)
        free(muts[i]);
    free(muts);
    return e;
}

static cm_err apply_patch(cm_client *c, int ci, SPatch *p, int full)
{
    as_state *s = ast(c);
    as_coll *co = &s->coll[ci];
    uint8_t hash[128];
    uint64_t version = p->version && p->version->has_version ? p->version->version : 0;
    as_keys k;
    uint8_t mac[32];
    pout out;
    size_t i;
    cm_err e;

    memcpy(hash, co->hash, 128);
    memset(&out, 0, sizeof(out));
    for (i = 0; i < p->n_mutations; i++)
        if (!mut_valid(p->mutations[i]))
            return CM_ERR_PROTO;
    if ((e = hash_update(hash, p->mutations, p->n_mutations, co, p)) != CM_OK)
        return e;
    if (!p->keyid || !p->keyid->has_id || !p->has_snapshotmac || !p->has_patchmac)
        return CM_ERR_PROTO;
    if ((e = validate_snapshot_mac(c, COLL_NAMES[ci], hash, version, &p->keyid->id, &p->snapshotmac)) != CM_OK)
        return e;
    if ((e = get_keys(c, p->keyid->id.data, p->keyid->id.len, &k)) != CM_OK)
        return e;
    if ((e = as_patch_mac(p, COLL_NAMES[ci], k.patch_mac, version, mac)) != CM_OK)
        return e;
    if (p->patchmac.len != 32 || !cm_ct_equal(mac, p->patchmac.data, 32))
        return CM_ERR_AUTH;
    if ((e = decode_mutations(c, p->mutations, p->n_mutations, 1, &out)) != CM_OK) {
        pout_free(&out);
        return e;
    }
    store_macs(co, version, hash, &out);
    for (i = 0; i < out.nmuts; i++)
        emit_mutation(c, COLL_NAMES[ci], &out.muts[i], version, full);
    pout_free(&out);
    return CM_OK;
}

/* ---------------------------------------------------------------- key requests */
cm_err cm_client_request_app_state_keys(cm_client *c, const uint8_t *const *ids, const size_t *lens, size_t n)
{
    WAWebProtobufsE2E__Message m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__ProtocolMessage pm = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__INIT;
    WAWebProtobufsE2E__AppStateSyncKeyRequest rq = WAWEB_PROTOBUFS_E2_E__APP_STATE_SYNC_KEY_REQUEST__INIT;
    WAWebProtobufsE2E__AppStateSyncKeyId *kv;
    WAWebProtobufsE2E__AppStateSyncKeyId **kp;
    uint8_t *buf;
    size_t i, len;
    cm_err e;

    if (n == 0)
        return CM_OK;
    kv = (WAWebProtobufsE2E__AppStateSyncKeyId *)calloc(n, sizeof(*kv));
    kp = (WAWebProtobufsE2E__AppStateSyncKeyId **)calloc(n, sizeof(*kp));
    if (kv == NULL || kp == NULL) {
        free(kv);
        free(kp);
        return CM_ERR_NOMEM;
    }
    for (i = 0; i < n; i++) {
        waweb_protobufs_e2_e__app_state_sync_key_id__init(&kv[i]);
        kv[i].has_keyid = 1;
        kv[i].keyid.data = (uint8_t *)ids[i];
        kv[i].keyid.len = lens[i];
        kp[i] = &kv[i];
    }
    rq.n_keyids = n;
    rq.keyids = kp;
    pm.has_type = 1;
    pm.type = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__APP_STATE_SYNC_KEY_REQUEST;
    pm.appstatesynckeyrequest = &rq;
    m.protocolmessage = &pm;
    len = waweb_protobufs_e2_e__message__get_packed_size(&m);
    buf = (uint8_t *)malloc(len + 1);
    if (buf == NULL) {
        free(kv);
        free(kp);
        return CM_ERR_NOMEM;
    }
    waweb_protobufs_e2_e__message__pack(&m, buf);
    e = cm_client_send_peer_message(c, buf, len, "high", NULL);
    free(buf);
    free(kv);
    free(kp);
    return e;
}

static int already_requested(as_state *s, const char *hx, int64_t now)
{
    size_t i;
    void *a, *b;

    for (i = 0; i < s->nreq; i++)
        if (strcmp(s->req_key[i], hx) == 0) {
            if (s->req_ts[i] + 24 * 3600 * 1000LL > now)
                return 1;
            s->req_ts[i] = now;
            return 0;
        }
    a = realloc(s->req_key, (s->nreq + 1) * sizeof(char *));
    if (a == NULL)
        return 0;
    s->req_key = (char **)a;
    b = realloc(s->req_ts, (s->nreq + 1) * sizeof(int64_t));
    if (b == NULL)
        return 0;
    s->req_ts = (int64_t *)b;
    s->req_key[s->nreq] = cm_strdup(hx);
    s->req_ts[s->nreq] = now;
    s->nreq++;
    return 0;
}

static void request_missing(cm_client *c, const plist *pl)
{
    as_state *s = ast(c);
    const uint8_t **ids = (const uint8_t **)calloc(pl->n * 1 + 1 + (pl->snap ? pl->snap->n_records : 0) + 1, sizeof(void *));
    size_t *lens = (size_t *)calloc(pl->n + 1 + (pl->snap ? pl->snap->n_records : 0) + 1, sizeof(size_t));
    size_t n = 0, i, j;
    int64_t now = cmi_now_ms();

#define CONSIDER(kidp)                                                                                    \
    do {                                                                                                   \
        const ProtobufCBinaryData *kb = (kidp);                                                            \
        if (kb && kb->len > 0 && kb->len <= 64 && !have_key(c, kb->data, kb->len)) {                       \
            char hx[129];                                                                                  \
            int dup = 0;                                                                                   \
            for (j = 0; j < n; j++)                                                                        \
                if (lens[j] == kb->len && memcmp(ids[j], kb->data, kb->len) == 0)                          \
                    dup = 1;                                                                               \
            to_hex(kb->data, kb->len, hx);                                                                 \
            if (!dup && !already_requested(s, hx, now)) {                                                  \
                ids[n] = kb->data;                                                                         \
                lens[n++] = kb->len;                                                                       \
            }                                                                                              \
        }                                                                                                  \
    } while (0)
    if (ids && lens) {
        if (pl->snap) {
            if (pl->snap->keyid)
                CONSIDER(&pl->snap->keyid->id);
            for (i = 0; i < pl->snap->n_records; i++)
                if (pl->snap->records[i]->keyid)
                    CONSIDER(&pl->snap->records[i]->keyid->id);
        }
        for (i = 0; i < pl->n; i++)
            if (pl->patches[i]->keyid)
                CONSIDER(&pl->patches[i]->keyid->id);
        cm_client_request_app_state_keys(c, ids, lens, n);
    }
#undef CONSIDER
    free(ids);
    free(lens);
}

/* ---------------------------------------------------------------- applying a parsed list */
static cm_err apply_plist(cm_client *c, int ci, plist *pl, int full)
{
    size_t i;
    cm_err e = CM_OK;

    if (pl->snap && (e = apply_snapshot(c, ci, pl->snap, full)) != CM_OK)
        goto fail;
    for (i = 0; i < pl->n; i++)
        if ((e = apply_patch(c, ci, pl->patches[i], full)) != CM_OK)
            goto fail;
    return CM_OK;
fail:
    if (e == AS_ERR_NOKEY)
        request_missing(c, pl);
    return e;
}

static cm_err collection_iq(cm_client *c, const char *name, uint64_t version, int snapshot,
                            const uint8_t *patch, size_t plen, cm_node **resp)
{
    cm_node sync, coll;

    cmi_node(&sync, "sync");
    cmi_node(&coll, "collection");
    cm_node_set_attr_str(&coll, "name", name);
    cm_node_set_attr_bool(&coll, "return_snapshot", snapshot);
    if (!snapshot)
        cm_node_set_attr_u64(&coll, "version", version);
    if (patch) {
        cm_node pn;

        cmi_node(&pn, "patch");
        cm_node_set_content_bytes(&pn, patch, plen);
        cm_node_add_child(&coll, &pn);
    }
    cm_node_add_child(&sync, &coll);
    return cm_client_iq(c, "w:sync:app:state", "set", "", &sync, 0, resp);
}

static void free_resp(cm_node *r)
{
    if (r) {
        cm_node_free(r);
        free(r);
    }
}

static cm_err fetch_one(cm_client *c, int ci, int full, int only_if_not_synced)
{
    as_state *s = ast(c);
    as_coll *co = &s->coll[ci];
    int want_snapshot, has_more = 1;
    cm_err e = CM_OK;

    if (full) {
        cm_kvmap_free(&co->macs);
        memset(co->hash, 0, 128);
        co->version = 0;
    }
    if (co->version == 0)
        full = 1;
    else if (only_if_not_synced)
        return CM_OK;
    want_snapshot = full;
    while (has_more) {
        cm_node *resp = NULL;
        const cm_node *sy, *cn;
        plist pl;

        e = collection_iq(c, COLL_NAMES[ci], co->version, want_snapshot, NULL, 0, &resp);
        if (e != CM_OK) {
            free_resp(resp);
            goto fail;
        }
        sy = cm_node_child(resp, "sync");
        cn = sy ? cm_node_child(sy, "collection") : NULL;
        if (cn == NULL) {
            free_resp(resp);
            e = CM_ERR_PROTO;
            goto fail;
        }
        e = parse_plist(c, cn, &pl);
        free_resp(resp);
        if (e != CM_OK)
            goto fail;
        if ((!want_snapshot && pl.snap) || (pl.snap && co->version != 0)) {
            plist_free(&pl);
            e = CM_ERR_PROTO;
            goto fail;
        }
        want_snapshot = 0;
        has_more = pl.has_more;
        e = apply_plist(c, ci, &pl, full);
        plist_free(&pl);
        if (e != CM_OK)
            goto fail;
        as_save(c);
    }
    if (full)
        emit_sync(c, CM_EXT_APPSTATE_SYNC_DONE, COLL_NAMES[ci], co->version, 1, 0, CM_OK);
    return CM_OK;
fail:
    if (e != AS_ERR_NOKEY)
        emit_sync(c, CM_EXT_APPSTATE_SYNC_ERROR, COLL_NAMES[ci], co->version, full, 0, e);
    return e == AS_ERR_NOKEY ? CM_ERR_AUTH : e;
}

cm_err cm_client_fetch_app_state(cm_client *c, const char *name, int full_sync, int only_if_not_synced)
{
    int ci = coll_index(name);

    if (ci < 0 || ast(c) == NULL)
        return CM_ERR_ARG;
    if (!c->logged_in)
        return CM_ERR_CLOSED;
    return fetch_one(c, ci, full_sync, only_if_not_synced);
}

cm_err cm_client_fetch_all_app_state(cm_client *c, int full_sync, int only_if_not_synced)
{
    int i;
    cm_err first = CM_OK;

    for (i = 0; i < NCOLL; i++) {
        cm_err e = cm_client_fetch_app_state(c, COLL_NAMES[i], full_sync, only_if_not_synced);

        if (e != CM_OK && first == CM_OK)
            first = e;
    }
    return first;
}

/* ---------------------------------------------------------------- notifications and key shares */
void cmi_appstate_server_sync(cm_client *c, const cm_node *sync_child)
{
    size_t i;

    for (i = 0; sync_child && i < cm_node_nchildren(sync_child); i++) {
        const cm_node *ch = cm_node_child_at(sync_child, i);
        const char *nm = strcmp(ch->tag, "collection") == 0 ? cmi_attr(ch, "name") : NULL;

        if (nm && coll_index(nm) >= 0)
            cm_client_fetch_app_state(c, nm, 0, 0);
    }
}

void cmi_appstate_on_connected(cm_client *c)
{
    if (c->dev->app_state_keys.n > 0)
        cm_client_fetch_all_app_state(c, 0, 1);
}

static void handle_key_share(cm_client *c, const WAWebProtobufsE2E__AppStateSyncKeyShare *ks)
{
    as_state *s = ast(c);
    size_t i, j;
    int only_if_not_synced = 1;

    for (i = 0; i < ks->n_keys; i++) {
        const WAWebProtobufsE2E__AppStateSyncKey *k = ks->keys[i];
        char hx[129];
        uint8_t *val;
        size_t dl;
        int64_t ts;
        int b;

        if (!k->keyid || !k->keyid->has_keyid || !k->keydata || !k->keydata->has_keydata || k->keyid->keyid.len == 0 ||
            k->keyid->keyid.len > 64)
            continue;
        to_hex(k->keyid->keyid.data, k->keyid->keyid.len, hx);
        for (j = 0; s && j < s->nreq; j++)
            if (strcmp(s->req_key[j], hx) == 0)
                only_if_not_synced = 0;
        dl = k->keydata->keydata.len;
        val = (uint8_t *)malloc(8 + dl);
        if (val == NULL)
            continue;
        ts = k->keydata->has_timestamp ? k->keydata->timestamp : 0;
        for (b = 0; b < 8; b++)
            val[b] = (uint8_t)((uint64_t)ts >> (8 * (7 - b)));
        memcpy(val + 8, k->keydata->keydata.data, dl);
        cm_kvmap_put(&c->dev->app_state_keys, hx, val, 8 + dl);
        free(val);
    }
    cmi_save(c);
    cm_client_fetch_all_app_state(c, 0, only_if_not_synced);
}

/* ---------------------------------------------------------------- snapshot recovery */
static cm_err process_recovery(cm_client *c, const WAWebProtobufsSyncdSnapshotRecovery__SyncdSnapshotRecovery *r)
{
    as_state *s = ast(c);
    const char *name = r->collectionname;
    int ci = name ? coll_index(name) : -1;
    uint64_t version = r->version && r->version->has_version ? r->version->version : 0;
    size_t i;
    dmut *ms;
    uint8_t (*im)[32], (*vm)[32];
    cm_err e = CM_OK;

    if (ci < 0 || !r->has_collectionlthash || r->collectionlthash.len != 128)
        return CM_ERR_PROTO;
    if (s->coll[ci].version >= version)
        return CM_OK; /* we are already ahead */
    ms = (dmut *)calloc(r->n_mutationrecords + 1, sizeof(dmut));
    im = (uint8_t(*)[32])calloc(r->n_mutationrecords + 1, 32);
    vm = (uint8_t(*)[32])calloc(r->n_mutationrecords + 1, 32);
    if (!ms || !im || !vm) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    for (i = 0; i < r->n_mutationrecords; i++) {
        const WAWebProtobufsSyncdSnapshotRecovery__SyncdPlainTextRecord *rec = r->mutationrecords[i];
        as_keys k;

        if (!rec->value || !rec->value->has_index || !rec->has_keyid || !rec->has_mac || rec->mac.len != 32) {
            e = CM_ERR_PROTO;
            goto out;
        }
        if ((e = get_keys(c, rec->keyid.data, rec->keyid.len, &k)) != CM_OK)
            goto out;
        if ((e = cm_appstate_parse_index(rec->value->index.data, rec->value->index.len, &ms[i].index, &ms[i].nindex)) !=
            CM_OK)
            goto out;
        if ((e = as_index_mac(k.index, rec->value->index.data, rec->value->index.len, im[i])) != CM_OK)
            goto out;
        memcpy(vm[i], rec->mac.data, 32);
        ms[i].is_set = 1;
        ms[i].sad = rec->value;
        memcpy(ms[i].index_mac, im[i], 32);
        memcpy(ms[i].value_mac, vm[i], 32);
    }
    {
        as_coll *co = &s->coll[ci];
        char hx[65];

        cm_kvmap_free(&co->macs);
        co->version = version;
        memcpy(co->hash, r->collectionlthash.data, 128);
        for (i = 0; i < r->n_mutationrecords; i++) {
            to_hex(im[i], 32, hx);
            cm_kvmap_put(&co->macs, hx, vm[i], 32);
        }
        as_save(c);
        for (i = 0; i < r->n_mutationrecords; i++)
            emit_mutation(c, COLL_NAMES[ci], &ms[i], version, 1);
        emit_sync(c, CM_EXT_APPSTATE_SYNC_DONE, COLL_NAMES[ci], version, 1, 1, CM_OK);
    }
out:
    for (i = 0; ms && i < r->n_mutationrecords; i++) {
        size_t k;

        for (k = 0; k < ms[i].nindex; k++)
            free(ms[i].index[k]);
        free(ms[i].index); /* sad is borrowed from r */
    }
    free(ms);
    free(im);
    free(vm);
    return e;
}

static void handle_recovery_response(cm_client *c, const WAWebProtobufsE2E__PeerDataOperationRequestResponseMessage *rm)
{
    const WAWebProtobufsE2E__PeerDataOperationRequestResponseMessage__PeerDataOperationResult__SyncDSnapshotFatalRecoveryResponse *rr;
    uint8_t *data = NULL;
    size_t dl;
    WAWebProtobufsSyncdSnapshotRecovery__SyncdSnapshotRecovery *rec;

    if (rm->n_peerdataoperationresult == 0 || !rm->peerdataoperationresult[0]->syncdsnapshotfatalrecoveryresponse)
        return;
    rr = rm->peerdataoperationresult[0]->syncdsnapshotfatalrecoveryresponse;
    if (!rr->has_collectionsnapshot)
        return;
    if (rr->has_iscompressed && rr->iscompressed) {
        z_stream z;
        size_t cap = rr->collectionsnapshot.len * 8 + 4096, used = 0;
        int zr;

        memset(&z, 0, sizeof(z));
        if (inflateInit2(&z, 16 + MAX_WBITS) != Z_OK)
            return;
        data = (uint8_t *)malloc(cap);
        if (data == NULL) {
            inflateEnd(&z);
            return;
        }
        z.next_in = rr->collectionsnapshot.data;
        z.avail_in = (uInt)rr->collectionsnapshot.len;
        do {
            if (used == cap) {
                uint8_t *nd;

                if (cap > ((size_t)256 << 20)) { /* 256 MiB cap */
                    zr = Z_MEM_ERROR;
                    break;
                }
                nd = (uint8_t *)realloc(data, cap * 2);
                if (nd == NULL) {
                    zr = Z_MEM_ERROR;
                    break;
                }
                data = nd;
                cap *= 2;
            }
            z.next_out = data + used;
            z.avail_out = (uInt)(cap - used);
            zr = inflate(&z, Z_NO_FLUSH);
            used = cap - z.avail_out;
        } while (zr == Z_OK);
        inflateEnd(&z);
        if (zr != Z_STREAM_END) {
            free(data);
            return;
        }
        dl = used;
    } else {
        data = (uint8_t *)cm_memdup(rr->collectionsnapshot.data, rr->collectionsnapshot.len);
        dl = rr->collectionsnapshot.len;
        if (data == NULL)
            return;
    }
    rec = waweb_protobufs_syncd_snapshot_recovery__syncd_snapshot_recovery__unpack(NULL, dl, data);
    free(data);
    if (rec == NULL)
        return;
    process_recovery(c, rec);
    waweb_protobufs_syncd_snapshot_recovery__syncd_snapshot_recovery__free_unpacked(rec, NULL);
}

void cmi_appstate_on_protocol_message(cm_client *c, const void *vpm)
{
    const WAWebProtobufsE2E__ProtocolMessage *pm = (const WAWebProtobufsE2E__ProtocolMessage *)vpm;

    if (pm == NULL)
        return;
    if (pm->appstatesynckeyshare)
        handle_key_share(c, pm->appstatesynckeyshare);
    if (pm->peerdataoperationrequestresponsemessage)
        handle_recovery_response(c, pm->peerdataoperationrequestresponsemessage);
}

void cmi_appstate_on_key_share(cm_client *c, const uint8_t *protocol_message, size_t len)
{
    WAWebProtobufsE2E__ProtocolMessage *pm = waweb_protobufs_e2_e__protocol_message__unpack(NULL, len, protocol_message);

    if (pm) {
        cmi_appstate_on_protocol_message(c, pm);
        waweb_protobufs_e2_e__protocol_message__free_unpacked(pm, NULL);
    }
}

cm_err cm_client_request_app_state_recovery(cm_client *c, const char *collection)
{
    WAWebProtobufsE2E__Message m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__ProtocolMessage pm = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__INIT;
    WAWebProtobufsE2E__PeerDataOperationRequestMessage rq = WAWEB_PROTOBUFS_E2_E__PEER_DATA_OPERATION_REQUEST_MESSAGE__INIT;
    WAWebProtobufsE2E__PeerDataOperationRequestMessage__SyncDCollectionFatalRecoveryRequest fr =
        WAWEB_PROTOBUFS_E2_E__PEER_DATA_OPERATION_REQUEST_MESSAGE__SYNC_DCOLLECTION_FATAL_RECOVERY_REQUEST__INIT;
    uint8_t *buf;
    size_t len;
    cm_err e;

    fr.collectionname = (char *)collection;
    fr.has_timestamp = 1;
    fr.timestamp = (int64_t)time(NULL);
    rq.has_peerdataoperationrequesttype = 1;
    rq.peerdataoperationrequesttype = WAWEB_PROTOBUFS_E2_E__PEER_DATA_OPERATION_REQUEST_TYPE__COMPANION_SYNCD_SNAPSHOT_FATAL_RECOVERY;
    rq.syncdcollectionfatalrecoveryrequest = &fr;
    pm.has_type = 1;
    pm.type = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__PEER_DATA_OPERATION_REQUEST_MESSAGE;
    pm.peerdataoperationrequestmessage = &rq;
    m.protocolmessage = &pm;
    len = waweb_protobufs_e2_e__message__get_packed_size(&m);
    buf = (uint8_t *)malloc(len + 1);
    if (buf == NULL)
        return CM_ERR_NOMEM;
    waweb_protobufs_e2_e__message__pack(&m, buf);
    e = cm_client_send_peer_message(c, buf, len, "high_force", NULL);
    free(buf);
    return e;
}

/* ---------------------------------------------------------------- sending patches */
typedef struct minfo {
    char *idx[6];
    size_t nidx;
    int version;
    SAValue *val;
} minfo;

static cm_err encode_patch(cm_client *c, int ci, const uint8_t *kid, size_t kl, minfo *mi, size_t n, uint8_t **out,
                           size_t *olen)
{
    as_state *s = ast(c);
    as_coll *co = &s->coll[ci];
    as_keys k;
    SMut **muts = (SMut **)calloc(n + 1, sizeof(SMut *));
    SMut *mv = (SMut *)calloc(n + 1, sizeof(SMut));
    WAWebProtobufsServerSync__SyncdRecord *rv =
        (WAWebProtobufsServerSync__SyncdRecord *)calloc(n + 1, sizeof(WAWebProtobufsServerSync__SyncdRecord));
    WAWebProtobufsServerSync__SyncdIndex *iv =
        (WAWebProtobufsServerSync__SyncdIndex *)calloc(n + 1, sizeof(WAWebProtobufsServerSync__SyncdIndex));
    WAWebProtobufsServerSync__SyncdValue *vv =
        (WAWebProtobufsServerSync__SyncdValue *)calloc(n + 1, sizeof(WAWebProtobufsServerSync__SyncdValue));
    WAWebProtobufsServerSync__KeyId kidm = WAWEB_PROTOBUFS_SERVER_SYNC__KEY_ID__INIT;
    uint8_t **blobs = (uint8_t **)calloc(n + 1, sizeof(uint8_t *));
    uint8_t **idxmacs = (uint8_t **)calloc(n + 1, sizeof(uint8_t *));
    SPatch patch = WAWEB_PROTOBUFS_SERVER_SYNC__SYNCD_PATCH__INIT;
    uint8_t hash[128], snap_mac[32], pmac[32];
    int64_t now = (int64_t)time(NULL) * 1000;
    size_t i;
    cm_err e = CM_ERR_NOMEM;

    *out = NULL;
    if (!muts || !mv || !rv || !iv || !vv || !blobs || !idxmacs)
        goto out;
    if ((e = get_keys(c, kid, kl, &k)) != CM_OK)
        goto out;
    kidm.has_id = 1;
    kidm.id.data = (uint8_t *)kid;
    kidm.id.len = kl;
    for (i = 0; i < n; i++) {
        SAData sad = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_DATA__INIT;
        char *ij = cm_appstate_marshal_index((const char *const *)mi[i].idx, mi[i].nidx);
        uint8_t *content, *enc = NULL, vmac[32];
        size_t cl, el = 0;

        if (ij == NULL) {
            e = CM_ERR_NOMEM;
            goto out;
        }
        mi[i].val->has_timestamp = 1;
        mi[i].val->timestamp = now;
        sad.has_index = 1;
        sad.index.data = (uint8_t *)ij;
        sad.index.len = strlen(ij);
        sad.value = mi[i].val;
        sad.has_padding = 1;
        sad.padding.len = 0;
        sad.padding.data = NULL;
        sad.has_version = 1;
        sad.version = mi[i].version;
        cl = waweb_protobuf_sync_action__sync_action_data__get_packed_size(&sad);
        content = (uint8_t *)malloc(cl + 1);
        idxmacs[i] = (uint8_t *)malloc(32);
        if (content == NULL || idxmacs[i] == NULL) {
            free(ij);
            free(content);
            e = CM_ERR_NOMEM;
            goto out;
        }
        waweb_protobuf_sync_action__sync_action_data__pack(&sad, content);
        e = as_encrypt_value(k.value_enc, content, cl, &enc, &el);
        free(content);
        if (e == CM_OK)
            e = as_content_mac(0, enc, el, kid, kl, k.value_mac, vmac);
        if (e == CM_OK)
            e = as_index_mac(k.index, sad.index.data, sad.index.len, idxmacs[i]);
        free(ij);
        if (e != CM_OK) {
            free(enc);
            goto out;
        }
        blobs[i] = (uint8_t *)realloc(enc, el + 32);
        if (blobs[i] == NULL) {
            free(enc);
            e = CM_ERR_NOMEM;
            goto out;
        }
        memcpy(blobs[i] + el, vmac, 32);
        waweb_protobufs_server_sync__syncd_index__init(&iv[i]);
        iv[i].has_blob = 1;
        iv[i].blob.data = idxmacs[i];
        iv[i].blob.len = 32;
        waweb_protobufs_server_sync__syncd_value__init(&vv[i]);
        vv[i].has_blob = 1;
        vv[i].blob.data = blobs[i];
        vv[i].blob.len = el + 32;
        waweb_protobufs_server_sync__syncd_record__init(&rv[i]);
        rv[i].index = &iv[i];
        rv[i].value = &vv[i];
        rv[i].keyid = &kidm;
        waweb_protobufs_server_sync__syncd_mutation__init(&mv[i]);
        mv[i].has_operation = 1;
        mv[i].operation = WAWEB_PROTOBUFS_SERVER_SYNC__SYNCD_MUTATION__SYNCD_OPERATION__SET;
        mv[i].record = &rv[i];
        muts[i] = &mv[i];
    }
    memcpy(hash, co->hash, 128);
    if ((e = hash_update(hash, muts, n, co, NULL)) != CM_OK)
        goto out;
    if ((e = as_snapshot_mac(hash, co->version + 1, COLL_NAMES[ci], k.snapshot_mac, snap_mac)) != CM_OK)
        goto out;
    patch.has_snapshotmac = 1;
    patch.snapshotmac.data = snap_mac;
    patch.snapshotmac.len = 32;
    patch.keyid = &kidm;
    patch.n_mutations = n;
    patch.mutations = muts;
    if ((e = as_patch_mac(&patch, COLL_NAMES[ci], k.patch_mac, co->version + 1, pmac)) != CM_OK)
        goto out;
    patch.has_patchmac = 1;
    patch.patchmac.data = pmac;
    patch.patchmac.len = 32;
    *olen = waweb_protobufs_server_sync__syncd_patch__get_packed_size(&patch);
    *out = (uint8_t *)malloc(*olen + 1);
    if (*out == NULL) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    waweb_protobufs_server_sync__syncd_patch__pack(&patch, *out);
    e = CM_OK;
out:
    for (i = 0; i < n; i++) {
        if (blobs)
            free(blobs[i]);
        if (idxmacs)
            free(idxmacs[i]);
    }
    free(blobs);
    free(idxmacs);
    free(muts);
    free(mv);
    free(rv);
    free(iv);
    free(vv);
    return e;
}

static cm_err send_patch(cm_client *c, int ci, minfo *mi, size_t n, int allow_retry)
{
    as_state *s = ast(c);
    as_coll *co = &s->coll[ci];
    uint8_t *kid, *patch = NULL;
    size_t kl = 0, pl = 0;
    cm_node *resp = NULL;
    const cm_node *sy, *cn;
    cm_err e;

    if (!c->logged_in)
        return CM_ERR_CLOSED;
    kid = latest_key_id(c, &kl);
    if (kid == NULL)
        return CM_ERR_PROTO; /* no app state keys yet: ask the phone first */
    e = encode_patch(c, ci, kid, kl, mi, n, &patch, &pl);
    free(kid);
    if (e != CM_OK)
        return e;
    e = collection_iq(c, COLL_NAMES[ci], co->version, 0, patch, pl, &resp);
    free(patch);
    if (e != CM_OK) {
        free_resp(resp);
        return e;
    }
    sy = cm_node_child(resp, "sync");
    cn = sy ? cm_node_child(sy, "collection") : NULL;
    if (cn == NULL) {
        free_resp(resp);
        return CM_ERR_PROTO;
    }
    if (cmi_attr(cn, "type") != NULL && strcmp(cmi_attr(cn, "type"), "error") == 0) {
        const cm_node *en = cm_node_child(cn, "error");
        const char *code = en ? cmi_attr(en, "code") : NULL;

        e = CM_ERR_PROTO;
        if (code && atoi(code) == 409 && allow_retry) {
            plist pl2;

            if (parse_plist(c, cn, &pl2) == CM_OK) {
                cm_err ae = apply_plist(c, ci, &pl2, 0);

                plist_free(&pl2);
                free_resp(resp);
                if (ae != CM_OK)
                    return e;
                as_save(c);
                return send_patch(c, ci, mi, n, 0);
            }
        }
        free_resp(resp);
        return e;
    }
    free_resp(resp);
    return fetch_one(c, ci, 0, 0);
}

/* ---------------------------------------------------------------- mutation builders */
static char *jstr(const cm_jid *j)
{
    char *s = NULL;

    return cm_jid_to_string(j, &s) == CM_OK ? s : NULL;
}

static void minfo_free(minfo *m, size_t n)
{
    size_t i, k;

    for (i = 0; i < n; i++)
        for (k = 0; k < m[i].nidx; k++)
            free(m[i].idx[k]);
}

static int64_t ts_or_now(int64_t t)
{
    return t ? t : (int64_t)time(NULL);
}

cm_err cm_client_app_state_mute(cm_client *c, const cm_jid *chat, int mute, int64_t duration_sec)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__MuteAction a = WAWEB_PROTOBUF_SYNC_ACTION__MUTE_ACTION__INIT;
    minfo mi;
    cm_err e;

    a.has_muted = 1;
    a.muted = mute;
    if (mute) {
        a.has_muteendtimestamp = 1;
        a.muteendtimestamp = duration_sec > 0 ? ((int64_t)time(NULL) + duration_sec) * 1000 : -1;
    }
    v.muteaction = &a;
    memset(&mi, 0, sizeof(mi));
    mi.idx[0] = cm_strdup(CM_AS_IDX_MUTE);
    mi.idx[1] = jstr(chat);
    mi.nidx = 2;
    mi.version = 2;
    mi.val = &v;
    e = (mi.idx[0] && mi.idx[1]) ? send_patch(c, coll_index(CM_AS_REGULAR_HIGH), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}

static void fill_pin(minfo *m, const cm_jid *chat, int pin, SAValue *v, WAWebProtobufSyncAction__PinAction *a)
{
    memset(m, 0, sizeof(*m));
    a->has_pinned = 1;
    a->pinned = pin;
    v->pinaction = a;
    m->idx[0] = cm_strdup(CM_AS_IDX_PIN);
    m->idx[1] = jstr(chat);
    m->nidx = 2;
    m->version = 5;
    m->val = v;
}

cm_err cm_client_app_state_pin(cm_client *c, const cm_jid *chat, int pin)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__PinAction a = WAWEB_PROTOBUF_SYNC_ACTION__PIN_ACTION__INIT;
    minfo mi;
    cm_err e;

    fill_pin(&mi, chat, pin, &v, &a);
    e = (mi.idx[0] && mi.idx[1]) ? send_patch(c, coll_index(CM_AS_REGULAR_LOW), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}

cm_err cm_client_app_state_archive(cm_client *c, const cm_jid *chat, int archive, int64_t last_msg_ts)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT, v2 = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__ArchiveChatAction a = WAWEB_PROTOBUF_SYNC_ACTION__ARCHIVE_CHAT_ACTION__INIT;
    WAWebProtobufSyncAction__SyncActionMessageRange mr = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_MESSAGE_RANGE__INIT;
    WAWebProtobufSyncAction__PinAction pa = WAWEB_PROTOBUF_SYNC_ACTION__PIN_ACTION__INIT;
    minfo mi[2];
    size_t n = 1;
    cm_err e;

    memset(mi, 0, sizeof(mi));
    mr.has_lastmessagetimestamp = 1;
    mr.lastmessagetimestamp = ts_or_now(last_msg_ts);
    a.has_archived = 1;
    a.archived = archive;
    a.messagerange = &mr;
    v.archivechataction = &a;
    mi[0].idx[0] = cm_strdup(CM_AS_IDX_ARCHIVE);
    mi[0].idx[1] = jstr(chat);
    mi[0].nidx = 2;
    mi[0].version = 3;
    mi[0].val = &v;
    if (archive) { /* archiving also unpins */
        fill_pin(&mi[1], chat, 0, &v2, &pa);
        n = 2;
    }
    e = (mi[0].idx[0] && mi[0].idx[1]) ? send_patch(c, coll_index(CM_AS_REGULAR_LOW), mi, n, 1) : CM_ERR_NOMEM;
    minfo_free(mi, n);
    return e;
}

cm_err cm_client_app_state_mark_chat_read(cm_client *c, const cm_jid *chat, int read, int64_t last_msg_ts)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__MarkChatAsReadAction a = WAWEB_PROTOBUF_SYNC_ACTION__MARK_CHAT_AS_READ_ACTION__INIT;
    WAWebProtobufSyncAction__SyncActionMessageRange mr = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_MESSAGE_RANGE__INIT;
    minfo mi;
    cm_err e;

    memset(&mi, 0, sizeof(mi));
    mr.has_lastmessagetimestamp = 1;
    mr.lastmessagetimestamp = ts_or_now(last_msg_ts);
    a.has_read = 1;
    a.read = read;
    a.messagerange = &mr;
    v.markchatasreadaction = &a;
    mi.idx[0] = cm_strdup(CM_AS_IDX_MARK_READ);
    mi.idx[1] = jstr(chat);
    mi.nidx = 2;
    mi.version = 3;
    mi.val = &v;
    e = (mi.idx[0] && mi.idx[1]) ? send_patch(c, coll_index(CM_AS_REGULAR_LOW), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}

cm_err cm_client_app_state_star(cm_client *c, const cm_jid *chat, const cm_jid *sender, const char *msg_id,
                                int from_me, int starred)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__StarAction a = WAWEB_PROTOBUF_SYNC_ACTION__STAR_ACTION__INIT;
    minfo mi;
    cm_err e;

    memset(&mi, 0, sizeof(mi));
    a.has_starred = 1;
    a.starred = starred;
    v.staraction = &a;
    mi.idx[0] = cm_strdup(CM_AS_IDX_STAR);
    mi.idx[1] = jstr(chat);
    mi.idx[2] = cm_strdup(msg_id);
    mi.idx[3] = cm_strdup(from_me ? "1" : "0");
    mi.idx[4] = (sender == NULL || (sender->user && chat->user && strcmp(sender->user, chat->user) == 0))
                    ? cm_strdup("0") : jstr(sender);
    mi.nidx = 5;
    mi.version = 2;
    mi.val = &v;
    e = (mi.idx[0] && mi.idx[1] && mi.idx[2] && mi.idx[3] && mi.idx[4])
            ? send_patch(c, coll_index(CM_AS_REGULAR_HIGH), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}

cm_err cm_client_app_state_push_name(cm_client *c, const char *name)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__PushNameSetting a = WAWEB_PROTOBUF_SYNC_ACTION__PUSH_NAME_SETTING__INIT;
    minfo mi;
    cm_err e;

    memset(&mi, 0, sizeof(mi));
    a.name = (char *)name;
    v.pushnamesetting = &a;
    mi.idx[0] = cm_strdup(CM_AS_IDX_PUSH_NAME);
    mi.nidx = 1;
    mi.version = 1;
    mi.val = &v;
    e = mi.idx[0] ? send_patch(c, coll_index(CM_AS_CRITICAL_BLOCK), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}

cm_err cm_client_app_state_delete_chat(cm_client *c, const cm_jid *chat, int64_t last_msg_ts, int delete_media)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__DeleteChatAction a = WAWEB_PROTOBUF_SYNC_ACTION__DELETE_CHAT_ACTION__INIT;
    WAWebProtobufSyncAction__SyncActionMessageRange mr = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_MESSAGE_RANGE__INIT;
    minfo mi;
    cm_err e;

    memset(&mi, 0, sizeof(mi));
    mr.has_lastmessagetimestamp = 1;
    mr.lastmessagetimestamp = ts_or_now(last_msg_ts);
    a.messagerange = &mr;
    v.deletechataction = &a;
    mi.idx[0] = cm_strdup(CM_AS_IDX_DELETE_CHAT);
    mi.idx[1] = jstr(chat);
    mi.idx[2] = cm_strdup(delete_media ? "1" : "0");
    mi.nidx = 3;
    mi.version = 6;
    mi.val = &v;
    e = (mi.idx[0] && mi.idx[1] && mi.idx[2]) ? send_patch(c, coll_index(CM_AS_REGULAR_HIGH), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}

static cm_err label_assoc(cm_client *c, minfo *mi, int labeled)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__LabelAssociationAction a = WAWEB_PROTOBUF_SYNC_ACTION__LABEL_ASSOCIATION_ACTION__INIT;
    cm_err e = CM_OK;
    size_t i;

    a.has_labeled = 1;
    a.labeled = labeled;
    v.labelassociationaction = &a;
    mi->val = &v;
    mi->version = 3;
    for (i = 0; i < mi->nidx; i++)
        if (mi->idx[i] == NULL)
            e = CM_ERR_NOMEM;
    if (e == CM_OK)
        e = send_patch(c, coll_index(CM_AS_REGULAR), mi, 1, 1);
    minfo_free(mi, 1);
    return e;
}

cm_err cm_client_app_state_label_chat(cm_client *c, const cm_jid *chat, const char *label_id, int labeled)
{
    minfo mi;

    memset(&mi, 0, sizeof(mi));
    mi.idx[0] = cm_strdup(CM_AS_IDX_LABEL_CHAT);
    mi.idx[1] = cm_strdup(label_id);
    mi.idx[2] = jstr(chat);
    mi.nidx = 3;
    return label_assoc(c, &mi, labeled);
}

cm_err cm_client_app_state_label_message(cm_client *c, const cm_jid *chat, const char *label_id, const char *msg_id,
                                         int labeled)
{
    minfo mi;

    memset(&mi, 0, sizeof(mi));
    mi.idx[0] = cm_strdup(CM_AS_IDX_LABEL_MESSAGE);
    mi.idx[1] = cm_strdup(label_id);
    mi.idx[2] = jstr(chat);
    mi.idx[3] = cm_strdup(msg_id);
    mi.idx[4] = cm_strdup("0");
    mi.idx[5] = cm_strdup("0");
    mi.nidx = 6;
    return label_assoc(c, &mi, labeled);
}

cm_err cm_client_app_state_label_edit(cm_client *c, const char *label_id, const char *name, int32_t color, int deleted)
{
    SAValue v = WAWEB_PROTOBUF_SYNC_ACTION__SYNC_ACTION_VALUE__INIT;
    WAWebProtobufSyncAction__LabelEditAction a = WAWEB_PROTOBUF_SYNC_ACTION__LABEL_EDIT_ACTION__INIT;
    minfo mi;
    cm_err e;

    memset(&mi, 0, sizeof(mi));
    a.name = (char *)name;
    a.has_color = 1;
    a.color = color;
    a.has_deleted = 1;
    a.deleted = deleted;
    v.labeleditaction = &a;
    mi.idx[0] = cm_strdup(CM_AS_IDX_LABEL_EDIT);
    mi.idx[1] = cm_strdup(label_id);
    mi.nidx = 2;
    mi.version = 3;
    mi.val = &v;
    e = (mi.idx[0] && mi.idx[1]) ? send_patch(c, coll_index(CM_AS_REGULAR), &mi, 1, 1) : CM_ERR_NOMEM;
    minfo_free(&mi, 1);
    return e;
}
