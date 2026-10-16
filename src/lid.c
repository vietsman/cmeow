/* See include/common.h for license and attribution.
 * Port of whatsmeow store.LIDStore usage and Client.migrateSessionStore: phone-number users and
 * LID users are the same account; Signal sessions are kept under the LID address once it is known. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client_priv.h"

static int all_digits(const char *s)
{
    if (*s == '\0')
        return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

/* Moves "<pn>.<dev>" entries of m to "<lid>_1.<dev>" unless the target exists. */
static void migrate_map(cm_kvmap *m, const char *pn, const char *lid)
{
    size_t i, pl = strlen(pn);

    for (i = m->n; i-- > 0;) {
        char *oldk, nk[300];
        const char *rest;
        uint8_t *val;
        size_t len;

        if (i >= m->n || strncmp(m->e[i].key, pn, pl) != 0 || m->e[i].key[pl] != '.')
            continue;
        rest = m->e[i].key + pl + 1;
        if (!all_digits(rest) || snprintf(nk, sizeof nk, "%s_1.%s", lid, rest) >= (int)sizeof nk)
            continue;
        oldk = cm_strdup(m->e[i].key);
        if (oldk == NULL)
            continue;
        if (cm_kvmap_find(m, nk) == NULL) {
            val = (uint8_t *)cm_memdup(m->e[i].val, m->e[i].len);
            len = m->e[i].len;
            if (val != NULL) {
                if (cm_kvmap_put(m, nk, val, len) == CM_OK)
                    cm_kvmap_del(m, oldk);
                cm_cleanse(val, len);
                free(val);
            }
        } else {
            cm_kvmap_del(m, oldk);
        }
        free(oldk);
    }
}

void cmi_lid_learn(cm_client *c, const char *pn_user, const char *lid_user)
{
    if (pn_user == NULL || lid_user == NULL || strcmp(pn_user, lid_user) == 0)
        return;
    if (!cm_device_lid_put(c->dev, pn_user, lid_user))
        return;
    migrate_map(&c->dev->sessions, pn_user, lid_user);
    migrate_map(&c->dev->identities, pn_user, lid_user);
}

/* Learns from one pair where `a` is a JID and `other` a JID-valued attribute holding the other form. */
static void learn_pair(cm_client *c, const cm_jid *a, const cm_jid *other)
{
    const cm_jid *pn = NULL, *lid = NULL;

    if (a == NULL || other == NULL || cm_jid_is_empty(a) || cm_jid_is_empty(other))
        return;
    if (strcmp(a->server, CM_SERVER_HIDDEN_USER) == 0 && strcmp(other->server, CM_SERVER_DEFAULT_USER) == 0) {
        lid = a;
        pn = other;
    } else if (strcmp(a->server, CM_SERVER_DEFAULT_USER) == 0 && strcmp(other->server, CM_SERVER_HIDDEN_USER) == 0) {
        pn = a;
        lid = other;
    }
    if (pn && lid)
        cmi_lid_learn(c, pn->user, lid->user);
}

void cmi_lid_learn_attrs(cm_client *c, const cm_node *n)
{
    static const char *const pairs[][2] = {
        {"from", "sender_pn"}, {"from", "sender_lid"},
        {"participant", "participant_pn"}, {"participant", "participant_lid"},
        {"recipient", "peer_recipient_pn"}, {"recipient", "peer_recipient_lid"}
    };
    size_t i;

    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        cm_jid a, b;

        cm_jid_init(&a);
        cm_jid_init(&b);
        if (cmi_attr_jid(n, pairs[i][0], &a) == CM_OK && cmi_attr_jid(n, pairs[i][1], &b) == CM_OK)
            learn_pair(c, &a, &b);
        cm_jid_free(&a);
        cm_jid_free(&b);
    }
}

void cmi_lid_learn_jids(cm_client *c, const cm_jid *a, const cm_jid *b)
{
    learn_pair(c, a, b);
}

int cmi_lid_for_pn(cm_client *c, const cm_jid *pn, cm_jid *out)
{
    const char *l;
    cm_jid t;

    if (pn == NULL || strcmp(pn->server, CM_SERVER_DEFAULT_USER) != 0)
        return 0;
    l = cm_device_lid_for_pn(c->dev, pn->user);
    if (l == NULL)
        return 0;
    cm_jid_init(&t);
    if (cm_jid_set(&t, l, CM_SERVER_HIDDEN_USER) != CM_OK) {
        cm_jid_free(&t);
        return 0;
    }
    t.device = pn->device;
    cm_jid_free(out);
    *out = t;
    return 1;
}
