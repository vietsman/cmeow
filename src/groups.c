/* See include/common.h for license and attribution. Port of whatsmeow group.go (core group operations). */
#define _POSIX_C_SOURCE 200112L
#include "messaging_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GROUP_TTL_MS (60 * 60 * 1000LL)

/* ---------------------------------------------------------------- types */
static void part_free(cm_group_participant *p)
{
    cm_jid_free(&p->jid);
    cm_jid_free(&p->phone);
}

void cm_group_info_free(cm_group_info *g)
{
    size_t i;

    if (g == NULL)
        return;
    cm_jid_free(&g->jid);
    cm_jid_free(&g->owner);
    free(g->name);
    free(g->topic);
    free(g->topic_id);
    free(g->addressing_mode);
    for (i = 0; i < g->nparticipants; i++)
        part_free(&g->participants[i]);
    free(g->participants);
    memset(g, 0, sizeof(*g));
}

void cm_group_list_free(cm_group_list *l)
{
    size_t i;

    if (l == NULL)
        return;
    for (i = 0; i < l->n; i++)
        cm_group_info_free(&l->v[i]);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

static char *dupattr(const cm_node *n, const char *k)
{
    const char *v = cmi_attr(n, k);

    return v ? cm_strdup(v) : NULL;
}

static int64_t i64attr(const cm_node *n, const char *k)
{
    const char *v = cmi_attr(n, k);

    return v ? (int64_t)strtoll(v, NULL, 10) : 0;
}

cm_err cmi_parse_group_node(const cm_node *n, cm_group_info *g)
{
    const char *id = cmi_attr(n, "id");
    size_t i, np = 0;

    memset(g, 0, sizeof(*g));
    cm_jid_init(&g->jid);
    cm_jid_init(&g->owner);
    if (id == NULL)
        return CM_ERR_PROTO;
    if (strchr(id, '@') != NULL)
        cm_jid_parse(&g->jid, id);
    else
        cm_jid_set(&g->jid, id, CM_SERVER_GROUP);
    cmi_attr_jid(n, "creator", &g->owner);
    g->name = dupattr(n, "subject");
    g->name_set_at = i64attr(n, "s_t");
    g->created = i64attr(n, "creation");
    g->addressing_mode = dupattr(n, "addressing_mode");
    for (i = 0; i < cm_node_nchildren(n); i++)
        if (strcmp(cm_node_child_at(n, i)->tag, "participant") == 0)
            np++;
    if (np > 0) {
        g->participants = (cm_group_participant *)calloc(np, sizeof(cm_group_participant));
        if (g->participants == NULL)
            return CM_ERR_NOMEM;
    }
    for (i = 0; i < cm_node_nchildren(n); i++) {
        const cm_node *ch = cm_node_child_at(n, i);
        const char *t = ch->tag;

        if (strcmp(t, "participant") == 0) {
            cm_group_participant *p = &g->participants[g->nparticipants];
            const char *ty = cmi_attr(ch, "type");

            cm_jid_init(&p->jid);
            cm_jid_init(&p->phone);
            if (cmi_attr_jid(ch, "jid", &p->jid) != CM_OK)
                continue;
            if (cmi_attr_jid(ch, "phone_number", &p->phone) != CM_OK) {
                cm_jid_free(&p->phone);
                cm_jid_init(&p->phone);
            }
            p->is_super_admin = ty && strcmp(ty, "superadmin") == 0;
            p->is_admin = p->is_super_admin || (ty && strcmp(ty, "admin") == 0);
            g->nparticipants++;
        } else if (strcmp(t, "description") == 0) {
            const cm_node *body = cm_node_child(ch, "body");
            size_t bl = 0;
            const uint8_t *b = body ? cmi_bytes(body, &bl) : NULL;

            if (b) {
                g->topic = (char *)malloc(bl + 1);
                if (g->topic) {
                    memcpy(g->topic, b, bl);
                    g->topic[bl] = 0;
                }
                g->topic_id = dupattr(ch, "id");
                g->topic_set_at = i64attr(ch, "t");
            }
        } else if (strcmp(t, "announcement") == 0) {
            g->is_announce = 1;
        } else if (strcmp(t, "locked") == 0) {
            g->is_locked = 1;
        } else if (strcmp(t, "ephemeral") == 0) {
            const char *ex = cmi_attr(ch, "expiration");

            g->is_ephemeral = 1;
            g->disappearing_timer = ex ? (uint32_t)strtoul(ex, NULL, 10) : 0;
        } else if (strcmp(t, "membership_approval_mode") == 0) {
            g->is_join_approval = 1;
        }
    }
    return CM_OK;
}

/* ---------------------------------------------------------------- iq helper */
static cm_err group_iq(cm_client *c, const char *type, const cm_jid *to, cm_node *content, cm_node **resp)
{
    char *ts = NULL;
    cm_err e;

    if (to) {
        if ((e = cm_jid_to_string(to, &ts)) != CM_OK) {
            cm_node_free(content);
            return e;
        }
    }
    e = cm_client_iq(c, "w:g2", type, ts ? ts : "g.us", content, 0, resp);
    cm_node_free(content);
    free(ts);
    return e;
}

/* ---------------------------------------------------------------- cache */
cm_err cmi_group_get(cm_client *c, const cm_jid *g, const cm_group_info **out)
{
    struct cmi_mstate *m = cmi_ms(c);
    char *key = NULL;
    size_t i;
    cm_group_info info;
    cm_err e;
    void *nv;

    if ((e = cm_jid_to_string(g, &key)) != CM_OK)
        return e;
    for (i = 0; i < m->ngroups; i++)
        if (strcmp(m->groups[i].key, key) == 0) {
            if (m->groups[i].exp > cmi_now_ms()) {
                *out = &m->groups[i].gi;
                free(key);
                return CM_OK;
            }
            break;
        }
    e = cm_client_get_group_info(c, g, &info);
    if (e != CM_OK) {
        free(key);
        return e;
    }
    for (i = 0; i < info.nparticipants; i++)
        cmi_lid_learn_jids(c, &info.participants[i].jid, &info.participants[i].phone);
    for (i = 0; i < m->ngroups; i++)
        if (strcmp(m->groups[i].key, key) == 0) {
            cm_group_info_free(&m->groups[i].gi);
            m->groups[i].gi = info;
            m->groups[i].exp = cmi_now_ms() + GROUP_TTL_MS;
            *out = &m->groups[i].gi;
            free(key);
            return CM_OK;
        }
    nv = realloc(m->groups, (m->ngroups + 1) * sizeof(m->groups[0]));
    if (nv == NULL) {
        cm_group_info_free(&info);
        free(key);
        return CM_ERR_NOMEM;
    }
    m->groups = (__typeof__(m->groups))nv;
    m->groups[m->ngroups].key = key;
    m->groups[m->ngroups].gi = info;
    m->groups[m->ngroups].exp = cmi_now_ms() + GROUP_TTL_MS;
    *out = &m->groups[m->ngroups].gi;
    m->ngroups++;
    return CM_OK;
}

void cmi_group_forget(cm_client *c, const cm_jid *g)
{
    struct cmi_mstate *m = cmi_ms(c);
    char *key = NULL;
    size_t i;

    if (cm_jid_to_string(g, &key) != CM_OK)
        return;
    for (i = 0; i < m->ngroups; i++)
        if (strcmp(m->groups[i].key, key) == 0)
            m->groups[i].exp = 0;
    cmi_skdm_reset(c, key);
    free(key);
}

/* ---------------------------------------------------------------- queries */
cm_err cm_client_get_group_info(cm_client *c, const cm_jid *group, cm_group_info *out)
{
    cm_node q, *resp = NULL;
    const cm_node *gn;
    cm_err e;

    cmi_node(&q, "query");
    cm_node_set_attr_str(&q, "request", "interactive");
    if ((e = group_iq(c, "get", group, &q, &resp)) != CM_OK) {
        cmi_free_resp(resp);
        return e;
    }
    gn = cm_node_child(resp, "group");
    e = gn ? cmi_parse_group_node(gn, out) : CM_ERR_PROTO;
    cmi_free_resp(resp);
    return e;
}

cm_err cm_client_get_joined_groups(cm_client *c, cm_group_list *out)
{
    cm_node q, p, d, *resp = NULL;
    const cm_node *gs;
    size_t i;
    cm_err e;

    memset(out, 0, sizeof(*out));
    cmi_node(&q, "participating");
    cmi_node(&p, "participants");
    cm_node_add_child(&q, &p);
    cmi_node(&d, "description");
    cm_node_add_child(&q, &d);
    if ((e = group_iq(c, "get", NULL, &q, &resp)) != CM_OK) {
        cmi_free_resp(resp);
        return e;
    }
    gs = cm_node_child(resp, "groups");
    if (gs == NULL) {
        cmi_free_resp(resp);
        return CM_ERR_PROTO;
    }
    out->v = (cm_group_info *)calloc(cm_node_nchildren(gs) + 1, sizeof(cm_group_info));
    if (out->v == NULL) {
        cmi_free_resp(resp);
        return CM_ERR_NOMEM;
    }
    for (i = 0; i < cm_node_nchildren(gs); i++) {
        const cm_node *g = cm_node_child_at(gs, i);

        if (strcmp(g->tag, "group") == 0 && cmi_parse_group_node(g, &out->v[out->n]) == CM_OK)
            out->n++;
    }
    cmi_free_resp(resp);
    return CM_OK;
}

cm_err cm_client_create_group(cm_client *c, const char *name, const cm_jid *participants, size_t n,
                              cm_group_info *out)
{
    cm_node cr, *resp = NULL;
    cm_node mam, eph, mapm, gj;
    const cm_node *gn;
    size_t i;
    cm_err e;

    cmi_node(&cr, "create");
    if (name && name[0])
        cm_node_set_attr_str(&cr, "subject", name);
    cmi_node(&mam, "member_add_mode");
    cm_node_set_content_str(&mam, "all_member_add");
    cm_node_add_child(&cr, &mam);
    for (i = 0; i < n; i++) {
        cm_node pn;
        cm_jid nonad;

        cm_jid_init(&nonad);
        cm_jid_to_non_ad(&nonad, &participants[i]);
        cmi_node(&pn, "participant");
        cm_node_set_attr_jid(&pn, "jid", &nonad);
        cm_node_add_child(&cr, &pn);
        cm_jid_free(&nonad);
    }
    cmi_node(&eph, "ephemeral");
    cm_node_set_attr_str(&eph, "expiration", "0");
    cm_node_add_child(&cr, &eph);
    cmi_node(&mapm, "membership_approval_mode");
    cmi_node(&gj, "group_join");
    cm_node_set_attr_str(&gj, "state", "off");
    cm_node_add_child(&mapm, &gj);
    cm_node_add_child(&cr, &mapm);
    if ((e = group_iq(c, "set", NULL, &cr, &resp)) != CM_OK) {
        cmi_free_resp(resp);
        return e;
    }
    gn = cm_node_child(resp, "group");
    e = gn ? cmi_parse_group_node(gn, out) : CM_ERR_PROTO;
    cmi_free_resp(resp);
    return e;
}

cm_err cm_client_update_group_participants(cm_client *c, const cm_jid *group, const cm_jid *participants,
                                           size_t n, cm_participant_action action)
{
    static const char *const tags[] = {"add", "remove", "promote", "demote"};
    cm_node a, *resp = NULL;
    size_t i;
    cm_err e;

    cmi_node(&a, tags[action]);
    for (i = 0; i < n; i++) {
        cm_node p;

        cmi_node(&p, "participant");
        cm_node_set_attr_jid(&p, "jid", &participants[i]);
        cm_node_add_child(&a, &p);
    }
    e = group_iq(c, "set", group, &a, &resp);
    if (e == CM_OK) {
        const cm_node *ra = cm_node_child(resp, tags[action]);
        size_t k;

        if (ra == NULL)
            e = CM_ERR_PROTO;
        for (k = 0; ra && k < cm_node_nchildren(ra); k++) {
            const char *er = cmi_attr(cm_node_child_at(ra, k), "error");

            if (er && er[0] != '2' && er[0] != '0') {
                e = CM_ERR_PROTO; /* at least one participant was refused */
                break;
            }
        }
    }
    cmi_free_resp(resp);
    cmi_group_forget(c, group);
    return e;
}

static cm_err simple_set(cm_client *c, const cm_jid *group, cm_node *child)
{
    cm_node *resp = NULL;
    cm_err e = group_iq(c, "set", group, child, &resp);

    cmi_free_resp(resp);
    cmi_group_forget(c, group);
    return e;
}

cm_err cm_client_set_group_name(cm_client *c, const cm_jid *group, const char *name)
{
    cm_node s;

    cmi_node(&s, "subject");
    cm_node_set_content_bytes(&s, name, strlen(name));
    return simple_set(c, group, &s);
}

cm_err cm_client_set_group_topic(cm_client *c, const cm_jid *group, const char *topic)
{
    cm_node d, body;
    const cm_group_info *gi = NULL;
    uint8_t r[8];
    char id[17];
    size_t i;

    cmi_node(&d, "description");
    if (cmi_group_get(c, group, &gi) == CM_OK && gi->topic_id)
        cm_node_set_attr_str(&d, "prev", gi->topic_id);
    if (topic == NULL || topic[0] == 0) {
        cm_node_set_attr_str(&d, "delete", "true");
    } else {
        cm_random(r, 8);
        for (i = 0; i < 8; i++)
            sprintf(id + 2 * i, "%02X", r[i]);
        cm_node_set_attr_str(&d, "id", id);
        cmi_node(&body, "body");
        cm_node_set_content_bytes(&body, topic, strlen(topic));
        cm_node_add_child(&d, &body);
    }
    return simple_set(c, group, &d);
}

cm_err cm_client_set_group_announce(cm_client *c, const cm_jid *group, int announce)
{
    cm_node n;

    cmi_node(&n, announce ? "announcement" : "not_announcement");
    return simple_set(c, group, &n);
}

cm_err cm_client_set_group_locked(cm_client *c, const cm_jid *group, int locked)
{
    cm_node n;

    cmi_node(&n, locked ? "locked" : "unlocked");
    return simple_set(c, group, &n);
}

cm_err cm_client_set_group_ephemeral(cm_client *c, const cm_jid *group, uint32_t seconds)
{
    cm_node n;

    if (seconds == 0) {
        cmi_node(&n, "not_ephemeral");
    } else {
        char b[16];

        cmi_node(&n, "ephemeral");
        sprintf(b, "%lu", (unsigned long)seconds);
        cm_node_set_attr_str(&n, "expiration", b);
    }
    return simple_set(c, group, &n);
}

cm_err cm_client_get_group_invite_link(cm_client *c, const cm_jid *group, int reset, char **link)
{
    cm_node inv, *resp = NULL;
    const cm_node *in;
    const char *code;
    cm_err e;

    cmi_node(&inv, "invite");
    if ((e = group_iq(c, reset ? "set" : "get", group, &inv, &resp)) != CM_OK) {
        cmi_free_resp(resp);
        return e;
    }
    in = cm_node_child(resp, "invite");
    code = in ? cmi_attr(in, "code") : NULL;
    if (code == NULL) {
        cmi_free_resp(resp);
        return CM_ERR_PROTO;
    }
    *link = (char *)malloc(strlen(code) + 28);
    if (*link)
        sprintf(*link, "https://chat.whatsapp.com/%s", code);
    cmi_free_resp(resp);
    return *link ? CM_OK : CM_ERR_NOMEM;
}

cm_err cm_client_join_group_with_link(cm_client *c, const char *link, cm_jid *joined)
{
    static const char prefix[] = "https://chat.whatsapp.com/";
    cm_node inv, *resp = NULL;
    const cm_node *gn;
    cm_err e;

    if (strncmp(link, prefix, sizeof(prefix) - 1) == 0)
        link += sizeof(prefix) - 1;
    cmi_node(&inv, "invite");
    cm_node_set_attr_str(&inv, "code", link);
    if ((e = group_iq(c, "set", NULL, &inv, &resp)) != CM_OK) {
        cmi_free_resp(resp);
        return e;
    }
    gn = cm_node_child(resp, "membership_approval_request");
    if (gn == NULL)
        gn = cm_node_child(resp, "group");
    e = gn ? cmi_attr_jid(gn, "jid", joined) : CM_ERR_PROTO;
    cmi_free_resp(resp);
    return e;
}

cm_err cm_client_leave_group(cm_client *c, const cm_jid *group)
{
    cm_node lv, g, *resp = NULL;
    cm_err e;

    cmi_node(&lv, "leave");
    cmi_node(&g, "group");
    cm_node_set_attr_jid(&g, "id", group);
    cm_node_add_child(&lv, &g);
    e = group_iq(c, "set", NULL, &lv, &resp);
    cmi_free_resp(resp);
    cmi_group_forget(c, group);
    return e;
}

/* ---------------------------------------------------------------- notifications (w:gp2) */
void cmi_groups_handle_notification(cm_client *c, const cm_node *n)
{
    cm_jid group, author;
    const char *t = cmi_attr(n, "t");
    size_t i, k;

    cm_jid_init(&group);
    cm_jid_init(&author);
    if (cmi_attr_jid(n, "from", &group) != CM_OK)
        goto done;
    cmi_attr_jid(n, "participant", &author);
    cmi_group_forget(c, &group); /* membership / settings may have changed */
    for (i = 0; i < cm_node_nchildren(n); i++) {
        const cm_node *ch = cm_node_child_at(n, i);
        const char *tag = ch->tag;
        cm_group_notif ev;
        cm_jid *plist = NULL;
        size_t np = 0, cap;
        int kind = CM_EXT_GROUP_INFO;

        memset(&ev, 0, sizeof(ev));
        ev.group = &group;
        ev.author = &author;
        ev.timestamp = t ? (int64_t)strtoll(t, NULL, 10) : 0;
        ev.action = tag;
        if (strcmp(tag, "add") == 0 || strcmp(tag, "remove") == 0 || strcmp(tag, "promote") == 0 ||
            strcmp(tag, "demote") == 0 || strcmp(tag, "leave") == 0) {
            kind = CM_EXT_GROUP_PARTICIPANTS;
            cap = cm_node_nchildren(ch) + 1;
            plist = (cm_jid *)calloc(cap, sizeof(cm_jid));
            if (plist == NULL)
                continue;
            for (k = 0; k < cm_node_nchildren(ch); k++) {
                const cm_node *p = cm_node_child_at(ch, k);

                cm_jid_init(&plist[np]);
                if (strcmp(p->tag, "participant") == 0 && cmi_attr_jid(p, "jid", &plist[np]) == CM_OK)
                    np++;
                else
                    cm_jid_free(&plist[np]);
            }
            ev.participants = plist;
            ev.nparticipants = np;
            if (strcmp(tag, "add") == 0 || strcmp(tag, "remove") == 0)
                cmi_devices_forget(c, &group);
        } else if (strcmp(tag, "subject") == 0) {
            ev.text = cmi_attr(ch, "subject");
        } else if (strcmp(tag, "description") == 0) {
            const cm_node *body = cm_node_child(ch, "body");
            size_t bl = 0;
            const uint8_t *b = body ? cmi_bytes(body, &bl) : NULL;
            char *s = NULL;

            if (b && (s = (char *)malloc(bl + 1)) != NULL) {
                memcpy(s, b, bl);
                s[bl] = 0;
            }
            ev.text = s;
            cmi_emit_ext(c, kind, &ev);
            free(s);
            continue;
        } else if (strcmp(tag, "announcement") == 0 || strcmp(tag, "locked") == 0) {
            ev.flag = 1;
        } else if (strcmp(tag, "ephemeral") == 0) {
            const char *ex = cmi_attr(ch, "expiration");

            ev.flag = ex ? atoi(ex) : 0;
        } else if (strcmp(tag, "create") == 0) {
            /* full group info follows; consumers re-query with cm_client_get_group_info */
        } else if (strcmp(tag, "not_announcement") != 0 && strcmp(tag, "unlocked") != 0 &&
                   strcmp(tag, "not_ephemeral") != 0 && strcmp(tag, "invite") != 0 &&
                   strcmp(tag, "membership_approval_mode") != 0) {
            continue;
        }
        cmi_emit_ext(c, kind, &ev);
        for (k = 0; k < np; k++)
            cm_jid_free(&plist[k]);
        free(plist);
    }
done:
    cm_jid_free(&group);
    cm_jid_free(&author);
}
