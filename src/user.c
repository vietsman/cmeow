/* See include/common.h for license and attribution.
 * Port of whatsmeow user.go, presence.go, privacy_settings.go, notification.go, call.go. */
#include <stdlib.h>
#include <string.h>

#include "user.h"
#include "client_priv.h"
#include "messaging_priv.h"
#include "media_priv.h"

void cmi_user_free(cm_client *c) { cmi_paircode_free(c); }

static char *dupstr(const char *s)
{
    char *o;

    if (s == NULL)
        return NULL;
    o = (char *)malloc(strlen(s) + 1);
    if (o != NULL)
        strcpy(o, s);
    return o;
}

static int64_t attr_i64(const cm_node *n, const char *k)
{
    const char *s = cmi_attr(n, k);

    return s ? (int64_t)strtoll(s, NULL, 10) : 0;
}

static char *content_str(const cm_node *n)
{
    size_t l = 0;
    const uint8_t *b = cmi_bytes(n, &l);
    char *o;

    if (b == NULL)
        return NULL;
    o = (char *)malloc(l + 1);
    if (o != NULL) {
        memcpy(o, b, l);
        o[l] = 0;
    }
    return o;
}

/* iq with one child (taken), returns result node or error. */
static cm_err iq1(cm_client *c, const char *xmlns, const char *type, const char *to, cm_node *child, cm_node **resp)
{
    cm_err e = cm_client_iq(c, xmlns, type, to, child, 0, resp);

    if (child)
        cm_node_free(child);
    if (e != CM_OK && resp && *resp) {
        cm_node_free(*resp);
        free(*resp);
        *resp = NULL;
    }
    return e;
}

static void drop(cm_node *r)
{
    if (r) {
        cm_node_free(r);
        free(r);
    }
}

/* ---------------------------------------------------------------- presence */
cm_err cm_client_send_chat_presence(cm_client *c, const cm_jid *to, const char *state, const char *media)
{
    cm_node n, ch;
    cm_err e;

    if (to == NULL || state == NULL)
        return CM_ERR_ARG;
    e = cmi_node(&n, "chatstate");
    if (e == CM_OK) e = cm_node_set_attr_jid(&n, "to", to);
    if (e == CM_OK) e = cmi_node(&ch, state);
    if (e == CM_OK) {
        if (media && media[0] && strcmp(state, "composing") == 0)
            cm_node_set_attr_str(&ch, "media", media);
        e = cm_node_add_child(&n, &ch);
    }
    if (e == CM_OK) e = cm_client_send_node(c, &n);
    cm_node_free(&n);
    return e;
}

cm_err cm_client_subscribe_presence(cm_client *c, const cm_jid *jid)
{
    cm_node n;
    cm_err e = cmi_node(&n, "presence");

    if (e == CM_OK) e = cm_node_set_attr_str(&n, "type", "subscribe");
    if (e == CM_OK) e = cm_node_set_attr_jid(&n, "to", jid);
    if (e == CM_OK) e = cm_client_send_node(c, &n);
    cm_node_free(&n);
    return e;
}

/* ---------------------------------------------------------------- usync */
static cm_err usync_call(cm_client *c, const char *context, cm_node *query, cm_node *list, cm_node **resp)
{
    cm_node us;
    char *sid = cm_client_new_id(c);
    cm_err e;

    if (sid == NULL)
        return CM_ERR_NOMEM;
    cmi_node(&us, "usync");
    cm_node_set_attr_str(&us, "sid", sid);
    cm_node_set_attr_str(&us, "mode", "query");
    cm_node_set_attr_str(&us, "last", "true");
    cm_node_set_attr_str(&us, "index", "0");
    cm_node_set_attr_str(&us, "context", context);
    free(sid);
    cm_node_add_child(&us, query);
    cm_node_add_child(&us, list);
    e = iq1(c, "usync", "get", "", &us, resp);
    return e;
}

static const cm_node *usync_list(const cm_node *resp)
{
    const cm_node *u = resp ? cm_node_child(resp, "usync") : NULL;

    return u ? cm_node_child(u, "list") : NULL;
}

cm_err cm_client_is_on_whatsapp(cm_client *c, const char *const *phones, size_t n, cm_on_whatsapp **out)
{
    cm_node query, list, tmp, *resp = NULL;
    cm_on_whatsapp *r;
    const cm_node *l;
    size_t i, k;
    cm_err e;

    if (out == NULL || (n > 0 && phones == NULL))
        return CM_ERR_ARG;
    *out = NULL;
    r = (cm_on_whatsapp *)calloc(n ? n : 1, sizeof(*r));
    if (r == NULL)
        return CM_ERR_NOMEM;
    for (i = 0; i < n; i++)
        r[i].query = dupstr(phones[i]);
    cmi_node(&query, "query");
    cmi_node(&tmp, "business");
    {
        cm_node vv;

        cmi_node(&vv, "verified_name");
        cm_node_add_child(&tmp, &vv);
    }
    cm_node_add_child(&query, &tmp);
    cmi_node(&tmp, "contact");
    cm_node_add_child(&query, &tmp);
    cmi_node(&tmp, "lid");
    cm_node_add_child(&query, &tmp);
    cmi_node(&list, "list");
    for (i = 0; i < n; i++) {
        cm_node u, ct;
        const char *p = phones[i];
        char *buf = (char *)malloc(strlen(p) + 2);

        if (buf == NULL) {
            cm_node_free(&query);
            cm_node_free(&list);
            cm_on_whatsapp_free(r, n);
            return CM_ERR_NOMEM;
        }
        buf[0] = '+';
        strcpy(buf + (p[0] == '+' ? 0 : 1), p);
        cmi_node(&u, "user");
        cmi_node(&ct, "contact");
        cm_node_set_content_str(&ct, buf);
        free(buf);
        cm_node_add_child(&u, &ct);
        cm_node_add_child(&list, &u);
    }
    e = usync_call(c, "interactive", &query, &list, &resp);
    cm_node_free(&query);
    cm_node_free(&list);
    if (e != CM_OK) {
        cm_on_whatsapp_free(r, n);
        return e;
    }
    l = usync_list(resp);
    for (k = 0; l && k < cm_node_nchildren(l) && k < n; k++) {
        const cm_node *u = cm_node_child_at(l, k), *ct = cm_node_child(u, "contact");
        const char *t = ct ? cmi_attr(ct, "type") : NULL;

        /* replies come in request order */
        r[k].is_in = t != NULL && strcmp(t, "in") == 0;
        r[k].jid = dupstr(cmi_attr(u, "jid"));
        r[k].is_business = cm_node_child(u, "business") != NULL;
        {
            const cm_node *ln = cm_node_child(u, "lid");
            cm_jid pj, lj;

            cm_jid_init(&pj);
            cm_jid_init(&lj);
            if (ln && r[k].jid && cmi_attr_jid(ln, "val", &lj) == CM_OK && cm_jid_parse(&pj, r[k].jid) == CM_OK)
                cmi_lid_learn_jids(c, &pj, &lj);
            cm_jid_free(&pj);
            cm_jid_free(&lj);
        }
    }
    drop(resp);
    *out = r;
    return CM_OK;
}

void cm_on_whatsapp_free(cm_on_whatsapp *r, size_t n)
{
    size_t i;

    for (i = 0; r && i < n; i++) {
        free(r[i].query);
        free(r[i].jid);
    }
    free(r);
}

cm_err cm_client_get_user_info(cm_client *c, const cm_jid *jids, size_t n, cm_user_info **out)
{
    cm_node query, list, tmp, *resp = NULL;
    cm_user_info *r;
    const cm_node *l;
    size_t i, k;
    cm_err e;

    if (out == NULL || (n > 0 && jids == NULL))
        return CM_ERR_ARG;
    *out = NULL;
    r = (cm_user_info *)calloc(n ? n : 1, sizeof(*r));
    if (r == NULL)
        return CM_ERR_NOMEM;
    cmi_node(&query, "query");
    cmi_node(&tmp, "status");
    cm_node_add_child(&query, &tmp);
    cmi_node(&tmp, "picture");
    cm_node_add_child(&query, &tmp);
    cmi_node(&list, "list");
    for (i = 0; i < n; i++) {
        cm_node u;

        cmi_node(&u, "user");
        cm_node_set_attr_jid(&u, "jid", &jids[i]);
        cm_node_add_child(&list, &u);
        cm_jid_to_string(&jids[i], &r[i].jid);
    }
    e = usync_call(c, "full", &query, &list, &resp);
    cm_node_free(&query);
    cm_node_free(&list);
    if (e != CM_OK) {
        cm_user_info_free(r, n);
        return e;
    }
    l = usync_list(resp);
    for (k = 0; l && k < cm_node_nchildren(l); k++) {
        const cm_node *u = cm_node_child_at(l, k), *st, *pic;
        const char *ju = cmi_attr(u, "jid");

        for (i = 0; ju && i < n; i++) {
            if (r[i].jid && strcmp(r[i].jid, ju) == 0)
                break;
        }
        if (i >= n)
            continue;
        st = cm_node_child(u, "status");
        if (st) {
            free(r[i].status);
            r[i].status = content_str(st);
            r[i].status_ts = attr_i64(st, "t");
        }
        pic = cm_node_child(u, "picture");
        if (pic) {
            free(r[i].picture_id);
            r[i].picture_id = dupstr(cmi_attr(pic, "id"));
        }
    }
    drop(resp);
    *out = r;
    return CM_OK;
}

void cm_user_info_free(cm_user_info *r, size_t n)
{
    size_t i;

    for (i = 0; r && i < n; i++) {
        free(r[i].jid);
        free(r[i].status);
        free(r[i].picture_id);
    }
    free(r);
}

/* ---------------------------------------------------------------- profile picture / status */
cm_err cm_client_get_profile_picture(cm_client *c, const cm_jid *jid, int preview,
                                     const char *existing_id, cm_picture_info **out)
{
    cm_node pic, *resp = NULL;
    const cm_node *p;
    cm_picture_info *pi;
    cm_err e;
    char *js = NULL;

    if (jid == NULL || out == NULL)
        return CM_ERR_ARG;
    *out = NULL;
    cmi_node(&pic, "picture");
    cm_node_set_attr_str(&pic, "query", "url");
    cm_node_set_attr_str(&pic, "type", preview ? "preview" : "image");
    if (existing_id && existing_id[0])
        cm_node_set_attr_str(&pic, "id", existing_id);
    cm_jid_to_string(jid, &js);
    e = iq1(c, "w:profile:picture", "get", js, &pic, &resp);
    free(js);
    if (e != CM_OK) {
        /* item-not-found / not-authorized (404/401): no picture visible */
        if (e == CM_ERR_PROTO)
            return CM_OK;
        return e;
    }
    p = cm_node_child(resp, "picture");
    if (p == NULL) {
        drop(resp);
        return CM_OK; /* unchanged */
    }
    pi = (cm_picture_info *)calloc(1, sizeof(*pi));
    if (pi == NULL) {
        drop(resp);
        return CM_ERR_NOMEM;
    }
    pi->id = dupstr(cmi_attr(p, "id"));
    pi->url = dupstr(cmi_attr(p, "url"));
    pi->direct_path = dupstr(cmi_attr(p, "direct_path"));
    drop(resp);
    *out = pi;
    return CM_OK;
}

void cm_picture_info_free(cm_picture_info *p)
{
    if (p) {
        free(p->id);
        free(p->url);
        free(p->direct_path);
        free(p);
    }
}

cm_err cm_client_set_status_message(cm_client *c, const char *msg)
{
    cm_node st, *resp = NULL;
    cm_err e = cmi_node(&st, "status");

    if (e == CM_OK) e = cm_node_set_content_bytes(&st, msg ? msg : "", msg ? strlen(msg) : 0);
    if (e != CM_OK)
        return e;
    e = iq1(c, "status", "set", "", &st, &resp);
    drop(resp);
    return e;
}

/* ---------------------------------------------------------------- blocklist */
cm_err cm_client_get_blocklist(cm_client *c, char ***jids, size_t *n)
{
    cm_node *resp = NULL;
    const cm_node *l;
    char **v = NULL;
    size_t i, cnt = 0;
    cm_err e;

    if (jids == NULL || n == NULL)
        return CM_ERR_ARG;
    *jids = NULL;
    *n = 0;
    e = iq1(c, "blocklist", "get", "", NULL, &resp);
    if (e != CM_OK)
        return e;
    l = cm_node_child(resp, "list");
    for (i = 0; l && i < cm_node_nchildren(l); i++) {
        const cm_node *it = cm_node_child_at(l, i);
        const char *j = strcmp(it->tag, "item") == 0 ? cmi_attr(it, "jid") : NULL;
        void *nv;

        if (j == NULL)
            continue;
        nv = realloc(v, (cnt + 1) * sizeof(*v));
        if (nv == NULL)
            break;
        v = (char **)nv;
        v[cnt] = dupstr(j);
        if (v[cnt] != NULL)
            cnt++;
    }
    drop(resp);
    *jids = v;
    *n = cnt;
    return CM_OK;
}

cm_err cm_client_update_blocklist(cm_client *c, const cm_jid *jid, int block)
{
    cm_node it, *resp = NULL;
    cm_err e = cmi_node(&it, "item");

    if (e == CM_OK) e = cm_node_set_attr_jid(&it, "jid", jid);
    if (e == CM_OK) e = cm_node_set_attr_str(&it, "action", block ? "block" : "unblock");
    if (e != CM_OK)
        return e;
    e = iq1(c, "blocklist", "set", "", &it, &resp);
    drop(resp);
    return e;
}

/* ---------------------------------------------------------------- privacy */
cm_err cm_client_get_privacy_settings(cm_client *c, cm_privacy_setting **out, size_t *n)
{
    cm_node pv, *resp = NULL;
    const cm_node *p;
    cm_privacy_setting *v = NULL;
    size_t i, cnt = 0;
    cm_err e;

    if (out == NULL || n == NULL)
        return CM_ERR_ARG;
    *out = NULL;
    *n = 0;
    cmi_node(&pv, "privacy");
    e = iq1(c, "privacy", "get", "", &pv, &resp);
    if (e != CM_OK)
        return e;
    p = cm_node_child(resp, "privacy");
    for (i = 0; p && i < cm_node_nchildren(p); i++) {
        const cm_node *ct = cm_node_child_at(p, i);
        const char *nm = cmi_attr(ct, "name"), *val = cmi_attr(ct, "value");
        void *nv;

        if (nm == NULL || val == NULL)
            continue;
        nv = realloc(v, (cnt + 1) * sizeof(*v));
        if (nv == NULL)
            break;
        v = (cm_privacy_setting *)nv;
        v[cnt].name = dupstr(nm);
        v[cnt].value = dupstr(val);
        cnt++;
    }
    drop(resp);
    *out = v;
    *n = cnt;
    return CM_OK;
}

void cm_privacy_settings_free(cm_privacy_setting *s, size_t n)
{
    size_t i;

    for (i = 0; s && i < n; i++) {
        free(s[i].name);
        free(s[i].value);
    }
    free(s);
}

cm_err cm_client_set_privacy_setting(cm_client *c, const char *name, const char *value)
{
    cm_node pv, ct, *resp = NULL;
    cm_err e;

    if (name == NULL || value == NULL)
        return CM_ERR_ARG;
    cmi_node(&pv, "privacy");
    cmi_node(&ct, "category");
    cm_node_set_attr_str(&ct, "name", name);
    cm_node_set_attr_str(&ct, "value", value);
    cm_node_add_child(&pv, &ct);
    e = iq1(c, "privacy", "set", "", &pv, &resp);
    drop(resp);
    return e;
}

/* ---------------------------------------------------------------- business profile */
void cm_business_profile_free(cm_business_profile *p)
{
    size_t i;

    if (p == NULL)
        return;
    free(p->jid); free(p->address); free(p->description); free(p->email); free(p->timezone);
    for (i = 0; i < p->nwebsites; i++)
        free(p->websites[i]);
    free(p->websites);
    for (i = 0; i < p->ncategories; i++) {
        free(p->categories[i].id);
        free(p->categories[i].name);
    }
    free(p->categories);
    for (i = 0; i < p->nhours; i++) {
        free(p->hours[i].day);
        free(p->hours[i].mode);
    }
    free(p->hours);
    free(p);
}

static void *grow(void *v, size_t n, size_t sz)
{
    return realloc(v, (n + 1) * sz);
}

cm_err cm_client_get_business_profile(cm_client *c, const cm_jid *jid, cm_business_profile **out)
{
    cm_node bp, pr, *resp = NULL;
    const cm_node *b, *p, *x;
    cm_business_profile *r;
    cm_err e;
    size_t i;

    if (jid == NULL || out == NULL)
        return CM_ERR_ARG;
    *out = NULL;
    cmi_node(&bp, "business_profile");
    cm_node_set_attr_str(&bp, "v", "244");
    cmi_node(&pr, "profile");
    cm_node_set_attr_jid(&pr, "jid", jid);
    cm_node_add_child(&bp, &pr);
    e = iq1(c, "w:biz", "get", "", &bp, &resp);
    if (e != CM_OK)
        return e;
    b = cm_node_child(resp, "business_profile");
    p = b ? cm_node_child(b, "profile") : NULL;
    if (p == NULL) {
        drop(resp);
        return CM_OK;
    }
    r = (cm_business_profile *)calloc(1, sizeof(*r));
    if (r == NULL) {
        drop(resp);
        return CM_ERR_NOMEM;
    }
    r->jid = dupstr(cmi_attr(p, "jid"));
    if ((x = cm_node_child(p, "address")) != NULL) r->address = content_str(x);
    if ((x = cm_node_child(p, "description")) != NULL) r->description = content_str(x);
    if ((x = cm_node_child(p, "email")) != NULL) r->email = content_str(x);
    for (i = 0; i < cm_node_nchildren(p); i++) {
        const cm_node *ch = cm_node_child_at(p, i);

        if (strcmp(ch->tag, "website") == 0) {
            char **nv = (char **)grow(r->websites, r->nwebsites, sizeof(char *));

            if (nv) {
                r->websites = nv;
                r->websites[r->nwebsites] = content_str(ch);
                if (r->websites[r->nwebsites]) r->nwebsites++;
            }
        } else if (strcmp(ch->tag, "categories") == 0) {
            size_t k;

            for (k = 0; k < cm_node_nchildren(ch); k++) {
                const cm_node *cat = cm_node_child_at(ch, k);
                cm_biz_category *nv = (cm_biz_category *)grow(r->categories, r->ncategories, sizeof(*nv));

                if (strcmp(cat->tag, "category") != 0 || nv == NULL)
                    continue;
                r->categories = nv;
                r->categories[r->ncategories].id = dupstr(cmi_attr(cat, "id"));
                r->categories[r->ncategories].name = content_str(cat);
                r->ncategories++;
            }
        } else if (strcmp(ch->tag, "business_hours") == 0) {
            size_t k;

            r->timezone = dupstr(cmi_attr(ch, "timezone"));
            for (k = 0; k < cm_node_nchildren(ch); k++) {
                const cm_node *h = cm_node_child_at(ch, k);
                cm_biz_hours *nv = (cm_biz_hours *)grow(r->hours, r->nhours, sizeof(*nv));

                if (strcmp(h->tag, "business_hours_config") != 0 || nv == NULL)
                    continue;
                r->hours = nv;
                r->hours[r->nhours].day = dupstr(cmi_attr(h, "day_of_week"));
                r->hours[r->nhours].mode = dupstr(cmi_attr(h, "mode"));
                r->hours[r->nhours].open_min = (int)attr_i64(h, "open_time");
                r->hours[r->nhours].close_min = (int)attr_i64(h, "close_time");
                r->nhours++;
            }
        }
    }
    drop(resp);
    *out = r;
    return CM_OK;
}

/* ---------------------------------------------------------------- calls */
cm_err cm_client_reject_call(cm_client *c, const cm_jid *from, const char *call_id)
{
    cm_node call, rej;
    char *id = cm_client_new_id(c);
    cm_err e;

    if (from == NULL || call_id == NULL || id == NULL) {
        free(id);
        return CM_ERR_ARG;
    }
    cmi_node(&call, "call");
    cm_node_set_attr_jid(&call, "to", from);
    cm_node_set_attr_str(&call, "id", id);
    free(id);
    cmi_node(&rej, "reject");
    cm_node_set_attr_str(&rej, "call-id", call_id);
    cm_node_set_attr_jid(&rej, "call-creator", from);
    cm_node_set_attr_str(&rej, "count", "0");
    cm_node_add_child(&call, &rej);
    e = cm_client_send_node(c, &call);
    cm_node_free(&call);
    return e;
}

/* ---------------------------------------------------------------- inbound nodes */
static void on_picture(cm_client *c, const cm_node *n, const cm_node *ch, int removed)
{
    cm_ext_picture ev;

    memset(&ev, 0, sizeof(ev));
    ev.jid = cmi_attr(ch, "jid");
    if (ev.jid == NULL)
        ev.jid = cmi_attr(n, "from");
    ev.author = cmi_attr(ch, "author");
    ev.picture_id = cmi_attr(ch, "id");
    ev.removed = removed;
    ev.ts = attr_i64(n, "t");
    cmi_emit_ext(c, CM_EXT_PICTURE, &ev);
}

static void handle_notification(cm_client *c, const cm_node *n)
{
    const char *type = cmi_attr(n, "type");
    const cm_node *ch = cm_node_nchildren(n) ? cm_node_child_at(n, 0) : NULL;

    if (type == NULL)
        return;
    if (strcmp(type, "server_sync") == 0) {
        cmi_appstate_server_sync(c, n);
    } else if (strcmp(type, "w:gp2") == 0) {
        cmi_groups_handle_notification(c, n);
    } else if (strcmp(type, "link_code_companion_reg") == 0) {
        cmi_paircode_notification(c, n);
    } else if (strcmp(type, "mediaretry") == 0) {
        cmi_media_handle_retry_notification(c, n);
    } else if (strcmp(type, "encrypt") == 0) {
        if (cm_node_child(n, "count") != NULL)
            cmi_upload_prekeys_if_needed(c);
    } else if (strcmp(type, "devices") == 0) {
        const cm_node *d = cm_node_child(n, "add");
        size_t i;

        if (d == NULL) d = cm_node_child(n, "remove");
        if (d == NULL) d = cm_node_child(n, "update");
        for (i = 0; d && i < 1; i++) {
            cm_jid j, nonad;
            const char *js = cmi_attr(n, "from");

            cm_jid_init(&j);
            cm_jid_init(&nonad);
            if (js && cm_jid_parse(&j, js) == CM_OK && cm_jid_to_non_ad(&nonad, &j) == CM_OK)
                cmi_devices_forget(c, &nonad);
            cm_jid_free(&j);
            cm_jid_free(&nonad);
        }
    } else if (strcmp(type, "picture") == 0) {
        size_t i;

        for (i = 0; i < cm_node_nchildren(n); i++) {
            const cm_node *x = cm_node_child_at(n, i);

            if (strcmp(x->tag, "set") == 0)
                on_picture(c, n, x, 0);
            else if (strcmp(x->tag, "delete") == 0)
                on_picture(c, n, x, 1);
        }
    } else if (strcmp(type, "status") == 0 && ch && strcmp(ch->tag, "set") == 0) {
        cm_ext_about ev;
        char *txt = content_str(ch);

        ev.jid = cmi_attr(n, "from");
        ev.status = txt ? txt : "";
        ev.ts = attr_i64(n, "t");
        cmi_emit_ext(c, CM_EXT_USER_ABOUT, &ev);
        free(txt);
    } else if (strcmp(type, "privacy_token") == 0) {
        cmi_tctoken_notification(c, n);
    } else if (strcmp(type, "account_sync") == 0) {
        if (ch && strcmp(ch->tag, "privacy") == 0) {
            cm_ext_privacy ev;

            ev.category = "";
            ev.value = "";
            cmi_emit_ext(c, CM_EXT_PRIVACY_CHANGED, &ev);
        }
    }
}

static void clean_dirty(cm_client *c, const char *type, const char *ts)
{
    cm_node cl, *resp = NULL;

    cmi_node(&cl, "clean");
    cm_node_set_attr_str(&cl, "type", type);
    if (ts)
        cm_node_set_attr_str(&cl, "timestamp", ts);
    cm_client_iq(c, "urn:xmpp:whatsapp:dirty", "set", "", &cl, 0, &resp);
    cm_node_free(&cl);
    drop(resp);
}

static void handle_ib(cm_client *c, const cm_node *n)
{
    size_t i;

    for (i = 0; i < cm_node_nchildren(n); i++) {
        const cm_node *ch = cm_node_child_at(n, i);

        if (strcmp(ch->tag, "dirty") == 0) {
            cm_ext_dirty ev;
            const char *t = cmi_attr(ch, "type");

            ev.type = t ? t : "";
            ev.ts = attr_i64(ch, "timestamp");
            cmi_emit_ext(c, CM_EXT_DIRTY, &ev);
            if (t && (strcmp(t, "account_sync") == 0 || strcmp(t, "groups") == 0))
                clean_dirty(c, t, cmi_attr(ch, "timestamp"));
        } else if (strcmp(ch->tag, "offline") == 0) {
            cmi_emit_ext(c, CM_EXT_OFFLINE_SYNC_DONE, NULL);
        }
    }
}

static void handle_call(cm_client *c, const cm_node *n)
{
    const cm_node *ch = cm_node_nchildren(n) ? cm_node_child_at(n, 0) : NULL;
    cm_ext_call ev;
    cm_node ack;
    int kind;

    if (ch == NULL)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.call_id = cmi_attr(ch, "call-id");
    ev.creator = cmi_attr(ch, "call-creator");
    ev.from = cmi_attr(n, "from");
    ev.ts = attr_i64(n, "t");
    ev.video = cm_node_child(ch, "video") != NULL;
    ev.kind = ch->tag;
    if (strcmp(ch->tag, "offer") == 0) kind = CM_EXT_CALL_OFFER;
    else if (strcmp(ch->tag, "accept") == 0) kind = CM_EXT_CALL_ACCEPT;
    else if (strcmp(ch->tag, "reject") == 0) kind = CM_EXT_CALL_REJECT;
    else if (strcmp(ch->tag, "terminate") == 0) kind = CM_EXT_CALL_TERMINATE;
    else kind = CM_EXT_CALL_OTHER;
    cmi_emit_ext(c, kind, &ev);

    if (cmi_node(&ack, "ack") == CM_OK) {
        cm_node_set_attr_str(&ack, "class", "call");
        cmi_set_attr_copy(&ack, n, "id", "id");
        cmi_set_attr_copy(&ack, n, "from", "to");
        cm_node_set_attr_str(&ack, "type", ch->tag);
        cm_client_send_node(c, &ack);
        cm_node_free(&ack);
    }
}

static void handle_presence(cm_client *c, const cm_node *n)
{
    cm_ext_presence ev;
    const char *t = cmi_attr(n, "type");

    ev.from = cmi_attr(n, "from");
    ev.unavailable = t != NULL && strcmp(t, "unavailable") == 0;
    ev.last_seen = attr_i64(n, "last");
    if (ev.from)
        cmi_emit_ext(c, CM_EXT_PRESENCE, &ev);
}

static void handle_chatstate(cm_client *c, const cm_node *n)
{
    const cm_node *ch = cm_node_nchildren(n) ? cm_node_child_at(n, 0) : NULL;
    cm_ext_chat_presence ev;
    const char *p;

    if (ch == NULL || cmi_attr(n, "from") == NULL)
        return;
    p = cmi_attr(n, "participant");
    ev.chat = cmi_attr(n, "from");
    ev.sender = p ? p : ev.chat;
    ev.state = ch->tag;
    ev.media = cmi_attr(ch, "media");
    if (ev.media == NULL)
        ev.media = "";
    cmi_emit_ext(c, CM_EXT_CHAT_PRESENCE, &ev);
}

void cmi_user_handle_node(cm_client *c, const cm_node *n)
{
    if (strcmp(n->tag, "notification") == 0) {
        handle_notification(c, n);
        cmi_ack(c, n);
    } else if (strcmp(n->tag, "ib") == 0) {
        handle_ib(c, n);
    } else if (strcmp(n->tag, "call") == 0) {
        handle_call(c, n);
    } else if (strcmp(n->tag, "presence") == 0) {
        handle_presence(c, n);
    } else if (strcmp(n->tag, "chatstate") == 0) {
        handle_chatstate(c, n);
    }
}

void cmi_user_on_connected(cm_client *c)
{
    (void)c;
}
