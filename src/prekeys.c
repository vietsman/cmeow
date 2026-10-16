/* See include/common.h for license and attribution. Port of whatsmeow/prekeys.go */
#define _POSIX_C_SOURCE 200112L
#include "client_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WANTED_PREKEYS 50
#define INITIAL_PREKEYS 812
#define MIN_PREKEYS 5

static void free_resp(cm_node *r)
{
    if (r) {
        cm_node_free(r);
        free(r);
    }
}

static cm_err get_server_count(cm_client *c, int *count)
{
    cm_node ch, *resp = NULL;
    const cm_node *cn;
    const char *v;
    cm_err e = cmi_node(&ch, "count");

    if (e != CM_OK)
        return e;
    e = cm_client_iq(c, "encrypt", "get", "", &ch, 0, &resp);
    cm_node_free(&ch);
    if (e != CM_OK) {
        free_resp(resp);
        return e;
    }
    cn = cm_node_child(resp, "count");
    v = cn ? cmi_attr(cn, "value") : NULL;
    if (v == NULL)
        e = CM_ERR_PROTO;
    else
        *count = atoi(v);
    free_resp(resp);
    return e;
}

static cm_err key_node(cm_node *out, const char *tag, uint32_t id, const uint8_t pub[32], const uint8_t *sig)
{
    cm_node idn, val, sg;
    uint8_t idb[3];
    cm_err e;

    idb[0] = (uint8_t)(id >> 16); idb[1] = (uint8_t)(id >> 8); idb[2] = (uint8_t)id;
    if ((e = cmi_node(out, tag)) != CM_OK) return e;
    cmi_node(&idn, "id");
    cm_node_set_content_bytes(&idn, idb, 3);
    cm_node_add_child(out, &idn);
    cmi_node(&val, "value");
    cm_node_set_content_bytes(&val, pub, 32);
    cm_node_add_child(out, &val);
    if (sig != NULL) {
        cmi_node(&sg, "signature");
        cm_node_set_content_bytes(&sg, sig, 64);
        e = cm_node_add_child(out, &sg);
    }
    return e;
}

static cm_err upload(cm_client *c, int initial)
{
    cm_device *d = c->dev;
    uint32_t want = initial ? INITIAL_PREKEYS : WANTED_PREKEYS, n = 0, i;
    cm_prekey *pks = NULL;
    cm_node *resp = NULL, reg, type, ident, list, skey, set_content;
    uint8_t rid[4], dj = 5;
    cm_err e = cm_device_get_or_gen_prekeys(d, want, &pks, &n);

    if (e != CM_OK)
        return e;
    rid[0] = (uint8_t)(d->registration_id >> 24); rid[1] = (uint8_t)(d->registration_id >> 16);
    rid[2] = (uint8_t)(d->registration_id >> 8); rid[3] = (uint8_t)d->registration_id;
    /* the iq helper takes ONE child; wrap the five parts in a fake container and unwrap by sending raw */
    cmi_node(&set_content, "__multi__");
    cmi_node(&reg, "registration"); cm_node_set_content_bytes(&reg, rid, 4); cm_node_add_child(&set_content, &reg);
    cmi_node(&type, "type"); cm_node_set_content_bytes(&type, &dj, 1); cm_node_add_child(&set_content, &type);
    cmi_node(&ident, "identity"); cm_node_set_content_bytes(&ident, d->identity_key.pub, 32); cm_node_add_child(&set_content, &ident);
    cmi_node(&list, "list");
    for (i = 0; i < n; i++) {
        cm_node k;

        if (key_node(&k, "key", pks[i].id, pks[i].key.pub, NULL) == CM_OK)
            cm_node_add_child(&list, &k);
    }
    cm_node_add_child(&set_content, &list);
    key_node(&skey, "skey", d->signed_prekey.id, d->signed_prekey.key.pub, d->signed_prekey.signature);
    cm_node_add_child(&set_content, &skey);
    e = cm_client_iq_multi(c, "encrypt", "set", "", &set_content, 0, &resp);
    cm_node_free(&set_content);
    free_resp(resp);
    if (e == CM_OK) {
        cm_device_mark_prekeys_uploaded(d, pks[n - 1].id);
        cmi_save(c);
    }
    free(pks);
    return e;
}

cm_err cmi_upload_prekeys_if_needed(cm_client *c)
{
    size_t db = cm_device_uploaded_prekey_count(c->dev);
    int server = 0;
    cm_err e = get_server_count(c, &server);

    if (e != CM_OK)
        return e;
    if (server < MIN_PREKEYS || db < MIN_PREKEYS)
        return upload(c, db == 0 && server == 0);
    return CM_OK;
}

/* ---- fetching bundles and building sessions ---- */
static cm_err ec_pub(ec_public_key **out, const uint8_t *k32, signal_context *ctx)
{
    uint8_t b[33];

    b[0] = 5;
    memcpy(b + 1, k32, 32);
    return curve_decode_point(out, b, 33, ctx) < 0 ? CM_ERR_CRYPTO : CM_OK;
}

static uint32_t be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }

cm_err cmi_process_bundle(cm_client *c, const cm_jid *jin, const cm_node *user)
{
    cm_jid j;
    const cm_node *keys, *reg, *id, *key, *skey, *kid, *kval, *sid, *sval, *ssig;
    size_t l;
    const uint8_t *b, *regb;
    ec_public_key *ident = NULL, *pk = NULL, *spk = NULL;
    session_pre_key_bundle *bundle = NULL;
    session_builder *sb = NULL;
    signal_protocol_address addr;
    char *name = NULL;
    uint32_t pkid = 0;
    cm_err e = CM_ERR_PROTO;
    int r;

    cm_jid_init(&j);
    if (cm_jid_copy(&j, jin) != CM_OK)
        goto out;
    if (cm_node_child(user, "error") != NULL)
        goto out;
    reg = cm_node_child(user, "registration");
    regb = reg ? cmi_bytes(reg, &l) : NULL;
    if (regb == NULL || l != 4)
        goto out;
    keys = cm_node_child(user, "keys");
    if (keys == NULL)
        keys = user;
    id = cm_node_child(keys, "identity");
    b = id ? cmi_bytes(id, &l) : NULL;
    if (b == NULL || l != 32 || ec_pub(&ident, b, c->dev->sctx) != CM_OK)
        goto out;
    skey = cm_node_child(keys, "skey");
    if (skey == NULL)
        goto out;
    sid = cm_node_child(skey, "id"); sval = cm_node_child(skey, "value"); ssig = cm_node_child(skey, "signature");
    if (!sid || !sval || !ssig)
        goto out;
    b = cmi_bytes(sid, &l);
    if (b == NULL || l != 3) goto out;
    {
        uint32_t spkid = be24(b);
        size_t sl, gl;
        const uint8_t *sv = cmi_bytes(sval, &sl), *sg = cmi_bytes(ssig, &gl);

        if (sv == NULL || sl != 32 || sg == NULL || gl != 64 || ec_pub(&spk, sv, c->dev->sctx) != CM_OK)
            goto out;
        key = cm_node_child(keys, "key");
        if (key != NULL) {
            kid = cm_node_child(key, "id"); kval = cm_node_child(key, "value");
            if (kid && kval) {
                size_t kl;
                const uint8_t *kb = cmi_bytes(kid, &kl), *kv;

                if (kb == NULL || kl != 3) goto out;
                pkid = be24(kb);
                kv = cmi_bytes(kval, &kl);
                if (kv == NULL || kl != 32 || ec_pub(&pk, kv, c->dev->sctx) != CM_OK) goto out;
            }
        }
        r = session_pre_key_bundle_create(&bundle,
                (uint32_t)regb[0] << 24 | (uint32_t)regb[1] << 16 | (uint32_t)regb[2] << 8 | regb[3],
                j.device, pkid, pk, spkid, spk, sg, 64, ident);
        if (r < 0) { e = CM_ERR_CRYPTO; goto out; }
    }
    if (cm_jid_signal_address_user(&j, &name) != CM_OK) { e = CM_ERR_NOMEM; goto out; }
    addr.name = name; addr.name_len = strlen(name); addr.device_id = j.device;
    if (session_builder_create(&sb, c->dev->sstore, &addr, c->dev->sctx) < 0) { e = CM_ERR_CRYPTO; goto out; }
    r = session_builder_process_pre_key_bundle(sb, bundle);
    e = r < 0 ? CM_ERR_CRYPTO : CM_OK;
out:
    if (sb) session_builder_free(sb);
    if (bundle) SIGNAL_UNREF(bundle);
    if (ident) SIGNAL_UNREF(ident);
    if (pk) SIGNAL_UNREF(pk);
    if (spk) SIGNAL_UNREF(spk);
    free(name);
    cm_jid_free(&j);
    return e;
}

static cm_err process_user(cm_client *c, const cm_node *user)
{
    cm_jid j;
    cm_err e;

    cm_jid_init(&j);
    if (cmi_attr_jid(user, "jid", &j) != CM_OK) {
        cm_jid_free(&j);
        return CM_ERR_PROTO;
    }
    e = cmi_process_bundle(c, &j, user);
    cm_jid_free(&j);
    return e;
}

/* Fetches prekeys for jids[0..n) and builds sessions. Per-device failures are skipped. */
cm_err cmi_build_sessions(cm_client *c, const cm_jid *jids, size_t n)
{
    cm_node key, *resp = NULL;
    const cm_node *list;
    size_t i;
    cm_err e;

    if (n == 0)
        return CM_OK;
    cmi_node(&key, "key");
    for (i = 0; i < n; i++) {
        cm_node u;

        cmi_node(&u, "user");
        cm_node_set_attr_jid(&u, "jid", &jids[i]);
        cm_node_set_attr_str(&u, "reason", "identity");
        cm_node_add_child(&key, &u);
    }
    e = cm_client_iq(c, "encrypt", "get", "", &key, 0, &resp);
    cm_node_free(&key);
    if (e != CM_OK) {
        free_resp(resp);
        return e;
    }
    list = cm_node_child(resp, "list");
    if (list == NULL) {
        free_resp(resp);
        return CM_ERR_PROTO;
    }
    for (i = 0; i < cm_node_nchildren(list); i++) {
        const cm_node *u = cm_node_child_at(list, i);

        if (strcmp(u->tag, "user") == 0)
            process_user(c, u);
    }
    free_resp(resp);
    return CM_OK;
}
