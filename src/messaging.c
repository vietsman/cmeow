/* See include/common.h for license and attribution.
 * Module state, device cache and receipt handling (whatsmeow receipt.go, parts of send.go / user.go). */
#define _POSIX_C_SOURCE 200112L
#include "messaging_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_TTL_MS (60 * 60 * 1000LL)

/* ---------------------------------------------------------------- helpers */
cm_err cmi_jl_add(cmi_jidlist *l, const cm_jid *j)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 8;
        cm_jid *nv = (cm_jid *)realloc(l->v, nc * sizeof(cm_jid));

        if (nv == NULL)
            return CM_ERR_NOMEM;
        l->v = nv;
        l->cap = nc;
    }
    cm_jid_init(&l->v[l->n]);
    if (cm_jid_copy(&l->v[l->n], j) != CM_OK)
        return CM_ERR_NOMEM;
    l->n++;
    return CM_OK;
}

void cmi_jl_free(cmi_jidlist *l)
{
    size_t i;

    for (i = 0; i < l->n; i++)
        cm_jid_free(&l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

void cmi_free_resp(cm_node *r)
{
    if (r) {
        cm_node_free(r);
        free(r);
    }
}

cm_err cmi_set_attr_copy(cm_node *dst, const cm_node *src, const char *from_key, const char *to_key)
{
    const cm_value *v = cm_node_get_attr(src, from_key);
    cm_value cp;

    if (v == NULL)
        return CM_ERR_ARG;
    cm_value_init(&cp);
    if (cm_value_clone(&cp, v) != CM_OK)
        return CM_ERR_NOMEM;
    if (cm_node_set_attr_value(dst, to_key, &cp) != CM_OK) {
        cm_value_free(&cp);
        return CM_ERR_NOMEM;
    }
    return CM_OK;
}

char *cmi_gen_msg_id(void)
{
    uint8_t r[9];
    char *s = (char *)malloc(4 + 18 + 1);
    size_t i;

    if (s == NULL || cm_random(r, 9) != CM_OK) {
        free(s);
        return NULL;
    }
    memcpy(s, "3EB0", 4);
    for (i = 0; i < 9; i++)
        sprintf(s + 4 + 2 * i, "%02X", r[i]);
    return s;
}

void cmi_addr_of(const cm_jid *j, char **name, signal_protocol_address *a)
{
    *name = NULL;
    cm_jid_signal_address_user(j, name);
    a->name = *name ? *name : "";
    a->name_len = *name ? strlen(*name) : 0;
    a->device_id = j->device;
}

/* ---------------------------------------------------------------- state */
struct cmi_mstate *cmi_ms(cm_client *c)
{
    if (c->mod_messaging == NULL)
        c->mod_messaging = calloc(1, sizeof(struct cmi_mstate));
    return (struct cmi_mstate *)c->mod_messaging;
}

void cmi_messaging_free(cm_client *c)
{
    struct cmi_mstate *m = (struct cmi_mstate *)c->mod_messaging;
    size_t i;

    if (m == NULL)
        return;
    for (i = 0; i < m->ndev; i++) {
        free(m->dev[i].key);
        cmi_jl_free(&m->dev[i].devs);
    }
    free(m->dev);
    for (i = 0; i < 64; i++) {
        free(m->sent[i].id);
        free(m->sent[i].msg);
    }
    for (i = 0; i < m->nret; i++)
        free(m->retries[i].k);
    free(m->retries);
    for (i = 0; i < m->nskdm; i++)
        free(m->skdm[i]);
    free(m->skdm);
    for (i = 0; i < m->ngroups; i++) {
        free(m->groups[i].key);
        cm_group_info_free(&m->groups[i].gi);
    }
    free(m->groups);
    free(m);
    c->mod_messaging = NULL;
}

void cmi_messaging_on_connected(cm_client *c) { (void)c; }

void cmi_remember_sent(cm_client *c, const char *id, const cm_jid *chat, const uint8_t *msg, size_t len)
{
    struct cmi_mstate *m = cmi_ms(c);
    size_t i;
    char *cs = NULL, *key;

    (void)chat;
    if (m == NULL || id == NULL)
        return;
    i = m->sent_next++ % 64;
    free(m->sent[i].id);
    free(m->sent[i].msg);
    key = (char *)malloc(strlen(id) + 1);
    (void)cs;
    if (key)
        strcpy(key, id);
    m->sent[i].id = key;
    m->sent[i].msg = (uint8_t *)cm_memdup(msg, len);
    m->sent[i].len = m->sent[i].msg ? len : 0;
}

const uint8_t *cmi_find_sent(cm_client *c, const char *id, size_t *len)
{
    struct cmi_mstate *m = cmi_ms(c);
    size_t i;

    for (i = 0; m && i < 64; i++)
        if (m->sent[i].id && strcmp(m->sent[i].id, id) == 0 && m->sent[i].msg) {
            *len = m->sent[i].len;
            return m->sent[i].msg;
        }
    return NULL;
}

int cmi_retry_count_inc(cm_client *c, const char *key)
{
    struct cmi_mstate *m = cmi_ms(c);
    size_t i;
    void *nv;

    for (i = 0; i < m->nret; i++)
        if (strcmp(m->retries[i].k, key) == 0)
            return ++m->retries[i].v;
    if (m->nret >= 256) { /* bounded: drop the oldest half */
        for (i = 0; i < 128; i++)
            free(m->retries[i].k);
        memmove(m->retries, m->retries + 128, (m->nret - 128) * sizeof(m->retries[0]));
        m->nret -= 128;
    }
    nv = realloc(m->retries, (m->nret + 1) * sizeof(m->retries[0]));
    if (nv == NULL)
        return 1;
    m->retries = (__typeof__(m->retries))nv;
    m->retries[m->nret].k = (char *)malloc(strlen(key) + 1);
    if (m->retries[m->nret].k == NULL)
        return 1;
    strcpy(m->retries[m->nret].k, key);
    m->retries[m->nret].v = 1;
    m->nret++;
    return 1;
}

/* skdm tracking: entries are "group\n<ad-string>" */
static char *skdm_key(const char *group, const cm_jid *dev)
{
    char *ad = NULL, *k;

    if (cm_jid_to_ad_string(dev, &ad) != CM_OK)
        return NULL;
    k = (char *)malloc(strlen(group) + strlen(ad) + 2);
    if (k)
        sprintf(k, "%s\n%s", group, ad);
    free(ad);
    return k;
}

int cmi_skdm_has(cm_client *c, const char *group, const cm_jid *dev)
{
    struct cmi_mstate *m = cmi_ms(c);
    char *k = skdm_key(group, dev);
    size_t i;
    int r = 0;

    for (i = 0; k && i < m->nskdm; i++)
        if (strcmp(m->skdm[i], k) == 0) {
            r = 1;
            break;
        }
    free(k);
    return r;
}

void cmi_skdm_mark(cm_client *c, const char *group, const cm_jid *dev)
{
    struct cmi_mstate *m = cmi_ms(c);
    char *k;

    if (cmi_skdm_has(c, group, dev))
        return;
    k = skdm_key(group, dev);
    if (k == NULL)
        return;
    if (m->nskdm == m->capskdm) {
        size_t nc = m->capskdm ? m->capskdm * 2 : 32;
        char **nv = (char **)realloc(m->skdm, nc * sizeof(char *));

        if (nv == NULL) {
            free(k);
            return;
        }
        m->skdm = nv;
        m->capskdm = nc;
    }
    m->skdm[m->nskdm++] = k;
}

void cmi_skdm_reset(cm_client *c, const char *group)
{
    struct cmi_mstate *m = cmi_ms(c);
    size_t i, w = 0, gl = strlen(group);

    for (i = 0; i < m->nskdm; i++) {
        if (strncmp(m->skdm[i], group, gl) == 0 && m->skdm[i][gl] == '\n')
            free(m->skdm[i]);
        else
            m->skdm[w++] = m->skdm[i];
    }
    m->nskdm = w;
}

/* ---------------------------------------------------------------- device cache */
static char *user_key(const cm_jid *u)
{
    cm_jid n;
    char *s = NULL;

    cm_jid_init(&n);
    if (cm_jid_to_non_ad(&n, u) == CM_OK)
        cm_jid_to_string(&n, &s);
    cm_jid_free(&n);
    return s;
}

void cmi_devices_forget(cm_client *c, const cm_jid *user)
{
    struct cmi_mstate *m = cmi_ms(c);
    char *k = user_key(user);
    size_t i;

    for (i = 0; k && i < m->ndev; i++)
        if (strcmp(m->dev[i].key, k) == 0) {
            m->dev[i].exp = 0;
            break;
        }
    free(k);
}

static void dev_store(struct cmi_mstate *m, const char *key, const cmi_jidlist *devs, int64_t exp)
{
    size_t i, k;

    for (i = 0; i < m->ndev; i++)
        if (strcmp(m->dev[i].key, key) == 0)
            break;
    if (i == m->ndev) {
        void *nv = realloc(m->dev, (m->ndev + 1) * sizeof(m->dev[0]));

        if (nv == NULL)
            return;
        m->dev = (__typeof__(m->dev))nv;
        m->dev[i].key = (char *)malloc(strlen(key) + 1);
        if (m->dev[i].key == NULL)
            return;
        strcpy(m->dev[i].key, key);
        memset(&m->dev[i].devs, 0, sizeof(cmi_jidlist));
        m->ndev++;
    } else {
        cmi_jl_free(&m->dev[i].devs);
    }
    for (k = 0; k < devs->n; k++)
        cmi_jl_add(&m->dev[i].devs, &devs->v[k]);
    m->dev[i].exp = exp;
}

static cm_err usync_devices(cm_client *c, const cm_jid *users, size_t nusers)
{
    struct cmi_mstate *m = cmi_ms(c);
    cm_node usync, query, devices, list, *resp = NULL;
    const cm_node *l;
    char *sid = cm_client_new_id(c);
    size_t i, k;
    cm_err e;

    if (sid == NULL)
        return CM_ERR_NOMEM;
    cmi_node(&usync, "usync");
    cm_node_set_attr_str(&usync, "sid", sid);
    cm_node_set_attr_str(&usync, "mode", "query");
    cm_node_set_attr_str(&usync, "last", "true");
    cm_node_set_attr_str(&usync, "index", "0");
    cm_node_set_attr_str(&usync, "context", "message");
    free(sid);
    cmi_node(&query, "query");
    cmi_node(&devices, "devices");
    cm_node_set_attr_str(&devices, "version", "2");
    cm_node_add_child(&query, &devices);
    cm_node_add_child(&usync, &query);
    cmi_node(&list, "list");
    for (i = 0; i < nusers; i++) {
        cm_node u;

        cmi_node(&u, "user");
        cm_node_set_attr_jid(&u, "jid", &users[i]);
        cm_node_add_child(&list, &u);
    }
    cm_node_add_child(&usync, &list);
    e = cm_client_iq(c, "usync", "get", "", &usync, 0, &resp);
    cm_node_free(&usync);
    if (e != CM_OK) {
        cmi_free_resp(resp);
        return e;
    }
    l = cm_node_child(resp, "usync");
    l = l ? cm_node_child(l, "list") : NULL;
    if (l == NULL) {
        cmi_free_resp(resp);
        return CM_ERR_PROTO;
    }
    for (i = 0; i < cm_node_nchildren(l); i++) {
        const cm_node *u = cm_node_child_at(l, i), *dn, *dl;
        cm_jid j;
        cmi_jidlist got = {0, 0, 0};
        char *key;

        if (strcmp(u->tag, "user") != 0)
            continue;
        cm_jid_init(&j);
        if (cmi_attr_jid(u, "jid", &j) != CM_OK) {
            cm_jid_free(&j);
            continue;
        }
        dn = cm_node_child(u, "devices");
        dl = dn ? cm_node_child(dn, "device-list") : NULL;
        for (k = 0; dl && k < cm_node_nchildren(dl); k++) {
            const cm_node *d = cm_node_child_at(dl, k);
            const char *ids = strcmp(d->tag, "device") == 0 ? cmi_attr(d, "id") : NULL;

            if (ids != NULL) {
                j.device = (uint16_t)atoi(ids);
                cmi_jl_add(&got, &j);
            }
        }
        key = user_key(&j);
        if (key && got.n > 0)
            dev_store(m, key, &got, cmi_now_ms() + DEVICE_TTL_MS);
        free(key);
        cmi_jl_free(&got);
        cm_jid_free(&j);
    }
    cmi_free_resp(resp);
    return CM_OK;
}

cm_err cmi_get_devices(cm_client *c, const cm_jid *users, size_t n, cmi_jidlist *out)
{
    struct cmi_mstate *m = cmi_ms(c);
    cmi_jidlist miss = {0, 0, 0};
    size_t i, k;
    int64_t now = cmi_now_ms();
    cm_err e = CM_OK;

    if (m == NULL)
        return CM_ERR_NOMEM;
    for (i = 0; i < n; i++) {
        char *key = user_key(&users[i]);
        int hit = 0;

        for (k = 0; key && k < m->ndev; k++)
            if (strcmp(m->dev[k].key, key) == 0 && m->dev[k].exp > now) {
                hit = 1;
                break;
            }
        free(key);
        if (!hit)
            cmi_jl_add(&miss, &users[i]);
    }
    if (miss.n > 0)
        e = usync_devices(c, miss.v, miss.n);
    cmi_jl_free(&miss);
    if (e != CM_OK)
        return e;
    for (i = 0; i < n; i++) {
        char *key = user_key(&users[i]);

        for (k = 0; key && k < m->ndev; k++)
            if (strcmp(m->dev[k].key, key) == 0) {
                size_t d;

                for (d = 0; d < m->dev[k].devs.n; d++)
                    cmi_jl_add(out, &m->dev[k].devs.v[d]);
                break;
            }
        free(key);
    }
    return CM_OK;
}

/* ---------------------------------------------------------------- receipts (receipt.go) */
void cmi_messaging_handle_receipt(cm_client *c, const cm_node *n)
{
    const char *type = cmi_attr(n, "type"), *id = cmi_attr(n, "id"), *t = cmi_attr(n, "t");
    cm_jid from, participant, recipient, chat, sender;
    const cm_node *list;
    const char **ids = NULL;
    size_t nids = 0, i;
    int is_group, from_me = 0;
    const char *own = c->dev->has_id ? c->dev->id.user : "";
    const char *own_lid = c->dev->lid.user ? c->dev->lid.user : "";
    cm_receipt_evt ev;

    cm_jid_init(&from); cm_jid_init(&participant); cm_jid_init(&recipient);
    cm_jid_init(&chat); cm_jid_init(&sender);
    if (type == NULL)
        type = "";
    if (cmi_attr_jid(n, "from", &from) != CM_OK || id == NULL)
        goto done;
    if (strcmp(type, "retry") == 0) {
        cmi_handle_retry_receipt(c, n);
        goto done;
    }
    is_group = strcmp(from.server, CM_SERVER_GROUP) == 0 || strcmp(from.server, CM_SERVER_BROADCAST) == 0;
    cm_jid_copy(&chat, &from);
    if (is_group) {
        cmi_attr_jid(n, "participant", &participant);
        cm_jid_copy(&sender, &participant);
    } else {
        cm_jid_copy(&sender, &from);
        if (from.user && (strcmp(from.user, own) == 0 || (own_lid[0] && strcmp(from.user, own_lid) == 0))) {
            from_me = 1;
            if (cmi_attr_jid(n, "recipient", &recipient) == CM_OK) {
                cm_jid_free(&chat);
                cm_jid_init(&chat);
                cm_jid_copy(&chat, &recipient);
            }
        }
    }
    list = cm_node_child(n, "list");
    ids = (const char **)calloc((list ? cm_node_nchildren(list) : 0) + 1, sizeof(char *));
    if (ids == NULL)
        goto done;
    ids[nids++] = id;
    for (i = 0; list && i < cm_node_nchildren(list); i++) {
        const cm_node *it = cm_node_child_at(list, i);
        const char *iid = strcmp(it->tag, "item") == 0 ? cmi_attr(it, "id") : NULL;

        if (iid)
            ids[nids++] = iid;
    }
    memset(&ev, 0, sizeof(ev));
    ev.chat = &chat;
    ev.sender = &sender;
    ev.ids = ids;
    ev.nids = nids;
    ev.timestamp = t ? (int64_t)strtoll(t, NULL, 10) : 0;
    ev.type = type;
    ev.is_group = is_group;
    ev.is_from_me = from_me;
    cmi_emit_ext(c, CM_EXT_RECEIPT, &ev);
done:
    free(ids);
    cm_jid_free(&from); cm_jid_free(&participant); cm_jid_free(&recipient);
    cm_jid_free(&chat); cm_jid_free(&sender);
    cmi_ack(c, n);
}

cm_err cm_client_mark_read(cm_client *c, const cm_jid *chat, const cm_jid *sender,
                           const char *const *ids, size_t nids, int64_t timestamp, cm_receipt_kind kind)
{
    cm_node r, list;
    size_t i;
    cm_err e;

    if (nids == 0 || !c->logged_in)
        return nids == 0 ? CM_ERR_ARG : CM_ERR_CLOSED;
    if ((e = cmi_node(&r, "receipt")) != CM_OK)
        return e;
    cm_node_set_attr_str(&r, "id", ids[0]);
    cm_node_set_attr_jid(&r, "to", chat);
    if (sender != NULL && !cm_jid_is_empty(sender) &&
        (strcmp(chat->server, CM_SERVER_GROUP) == 0 || strcmp(chat->server, CM_SERVER_BROADCAST) == 0))
        cm_node_set_attr_jid(&r, "participant", sender);
    cm_node_set_attr_str(&r, "type", kind == CM_RECEIPT_PLAYED ? "played" : "read");
    cm_node_set_attr_i64(&r, "t", timestamp);
    if (nids > 1) {
        cmi_node(&list, "list");
        for (i = 1; i < nids; i++) {
            cm_node it;

            cmi_node(&it, "item");
            cm_node_set_attr_str(&it, "id", ids[i]);
            cm_node_add_child(&list, &it);
        }
        cm_node_add_child(&r, &list);
    }
    e = cm_client_send_node(c, &r);
    cm_node_free(&r);
    return e;
}
