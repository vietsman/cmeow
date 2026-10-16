/* See include/common.h for license and attribution.
 * Port of whatsmeow tctoken.go: "trusted contact" privacy tokens. Contacts send them in
 * privacy_token notifications; we attach them to 1:1 messages to that contact and issue our own. */
#include <stdlib.h>
#include <string.h>

#include "client_priv.h"

#define TC_BUCKET_S (7 * 24 * 3600)
#define TC_VALID_S  (28 * 24 * 3600)

static void put_ts(uint8_t *o, int64_t t)
{
    int i;

    for (i = 7; i >= 0; i--) {
        o[i] = (uint8_t)(t & 0xff);
        t >>= 8;
    }
}

static int64_t get_ts(const uint8_t *p)
{
    int64_t t = 0;
    int i;

    for (i = 0; i < 8; i++)
        t = (t << 8) | p[i];
    return t;
}

static int64_t now_s(cm_client *c) { return cmi_now_ms() / 1000 + c->server_offset; }

static void store_token(cm_client *c, const char *user, int64_t ts, const uint8_t *tok, size_t len)
{
    cm_kv *old = cm_kvmap_find(&c->dev->tc_tokens, user);
    uint8_t *v;

    if (user == NULL || len == 0 || len > 4096)
        return;
    if (old != NULL && old->len >= 8 && get_ts(old->val) > ts)
        return;
    v = (uint8_t *)malloc(len + 8);
    if (v == NULL)
        return;
    put_ts(v, ts);
    memcpy(v + 8, tok, len);
    cm_kvmap_put(&c->dev->tc_tokens, user, v, len + 8);
    free(v);
}

void cmi_tctoken_notification(cm_client *c, const cm_node *n)
{
    const cm_node *toks = cm_node_child(n, "tokens");
    cm_jid from, other;
    size_t i;

    if (toks == NULL)
        return;
    cm_jid_init(&from);
    cm_jid_init(&other);
    if (cmi_attr_jid(n, "from", &from) != CM_OK) {
        cm_jid_free(&from);
        return;
    }
    if (cmi_attr_jid(n, "sender_lid", &other) == CM_OK)
        cmi_lid_learn_jids(c, &from, &other);
    for (i = 0; i < cm_node_nchildren(toks); i++) {
        const cm_node *t = cm_node_child_at(toks, i);
        const char *ty = cmi_attr(t, "type"), *ts = cmi_attr(t, "t");
        size_t l = 0;
        const uint8_t *b = cmi_bytes(t, &l);

        if (strcmp(t->tag, "token") != 0 || ty == NULL || strcmp(ty, "trusted_contact") != 0 || b == NULL)
            continue;
        store_token(c, from.user, ts ? (int64_t)strtoll(ts, NULL, 10) : now_s(c), b, l);
    }
    cm_jid_free(&from);
    cm_jid_free(&other);
    cmi_save(c);
}

/* Returns a still-valid token for the user (any of its PN/LID forms), or NULL. */
const uint8_t *cmi_tctoken_for(cm_client *c, const cm_jid *jid, size_t *len)
{
    const char *cands[3];
    size_t i;

    cands[0] = jid->user;
    cands[1] = cm_device_lid_for_pn(c->dev, jid->user);
    cands[2] = cm_device_pn_for_lid(c->dev, jid->user);
    for (i = 0; i < 3; i++) {
        cm_kv *kv = cands[i] ? cm_kvmap_find(&c->dev->tc_tokens, cands[i]) : NULL;

        if (kv != NULL && kv->len > 8 && now_s(c) - get_ts(kv->val) <= TC_VALID_S) {
            *len = kv->len - 8;
            return kv->val + 8;
        }
    }
    return NULL;
}

/* Tells the contact's server-side privacy that they are trusted (iq privacy/set tokens). */
void cmi_tctoken_issue(cm_client *c, const cm_jid *jid)
{
    cm_node toks, t, *resp = NULL;
    cm_jid nonad;
    int64_t bucket = now_s(c) / TC_BUCKET_S * TC_BUCKET_S;
    cm_kv *last;
    char key[300];

    if (jid == NULL || jid->user == NULL || snprintf(key, sizeof key, "issued:%s", jid->user) >= (int)sizeof key)
        return;
    last = cm_kvmap_find(&c->dev->tc_tokens, key);
    if (last != NULL && last->len == 8 && get_ts(last->val) >= bucket)
        return;
    cm_jid_init(&nonad);
    if (cm_jid_to_non_ad(&nonad, jid) != CM_OK)
        return;
    cmi_node(&toks, "tokens");
    cmi_node(&t, "token");
    cm_node_set_attr_jid(&t, "jid", &nonad);
    cm_node_set_attr_str(&t, "type", "trusted_contact");
    cm_node_set_attr_i64(&t, "t", bucket);
    cm_node_add_child(&toks, &t);
    if (cm_client_iq(c, "privacy", "set", "", &toks, 0, &resp) == CM_OK) {
        uint8_t v[8];

        put_ts(v, bucket);
        cm_kvmap_put(&c->dev->tc_tokens, key, v, 8);
    }
    cm_node_free(&toks);
    if (resp) {
        cm_node_free(resp);
        free(resp);
    }
    cm_jid_free(&nonad);
}
