/* See include/common.h for license and attribution. Port of whatsmeow/types/jid.go */
#include "jid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *cm_jid_user(const cm_jid *j)   { return j->user ? j->user : ""; }
const char *cm_jid_server(const cm_jid *j) { return j->server ? j->server : ""; }

void cm_jid_init(cm_jid *j)
{
    j->user = NULL;
    j->server = NULL;
    j->raw_agent = 0;
    j->device = 0;
    j->integrator = 0;
}

void cm_jid_free(cm_jid *j)
{
    free(j->user);
    free(j->server);
    cm_jid_init(j);
}

/* Duplicate [s, s+n), mapping empty to NULL. */
static cm_err dup_part(char **dst, const char *s, size_t n)
{
    if (n == 0) {
        *dst = NULL;
        return CM_OK;
    }
    *dst = cm_strndup(s, n);
    return *dst ? CM_OK : CM_ERR_NOMEM;
}

cm_err cm_jid_set(cm_jid *j, const char *user, const char *server)
{
    cm_jid tmp;
    cm_err e;

    cm_jid_init(&tmp);
    e = dup_part(&tmp.user, user ? user : "", user ? strlen(user) : 0);
    if (e == CM_OK)
        e = dup_part(&tmp.server, server ? server : "", server ? strlen(server) : 0);
    if (e != CM_OK) {
        cm_jid_free(&tmp);
        return e;
    }
    cm_jid_free(j);
    *j = tmp;
    return CM_OK;
}

cm_err cm_jid_set_ad(cm_jid *j, const char *user, uint8_t agent, uint8_t device)
{
    const char *server;
    cm_err e;

    switch (agent) {
    case CM_DOMAIN_LID:
        server = CM_SERVER_HIDDEN_USER;
        agent = 0;
        break;
    case CM_DOMAIN_HOSTED:
        server = CM_SERVER_HOSTED;
        agent = 0;
        break;
    case CM_DOMAIN_HOSTED_LID:
        server = CM_SERVER_HOSTED_LID;
        agent = 0;
        break;
    case CM_DOMAIN_WHATSAPP:
    default:
        server = CM_SERVER_DEFAULT_USER;
        break;
    }
    e = cm_jid_set(j, user, server);
    if (e != CM_OK)
        return e;
    j->raw_agent = agent;
    j->device = device;
    return CM_OK;
}

cm_err cm_jid_copy(cm_jid *dst, const cm_jid *src)
{
    cm_jid tmp;
    cm_err e;

    cm_jid_init(&tmp);
    e = dup_part(&tmp.user, cm_jid_user(src), strlen(cm_jid_user(src)));
    if (e == CM_OK)
        e = dup_part(&tmp.server, cm_jid_server(src), strlen(cm_jid_server(src)));
    if (e != CM_OK) {
        cm_jid_free(&tmp);
        return e;
    }
    tmp.raw_agent = src->raw_agent;
    tmp.device = src->device;
    tmp.integrator = src->integrator;
    if (dst != src) {
        cm_jid_free(dst);
        *dst = tmp;
    } else {
        cm_jid_free(&tmp);
    }
    return CM_OK;
}

uint8_t cm_jid_actual_agent(const cm_jid *j)
{
    const char *s = cm_jid_server(j);

    if (strcmp(s, CM_SERVER_DEFAULT_USER) == 0)
        return CM_DOMAIN_WHATSAPP;
    if (strcmp(s, CM_SERVER_HIDDEN_USER) == 0)
        return CM_DOMAIN_LID;
    if (strcmp(s, CM_SERVER_HOSTED) == 0)
        return CM_DOMAIN_HOSTED;
    if (strcmp(s, CM_SERVER_HOSTED_LID) == 0)
        return CM_DOMAIN_HOSTED_LID;
    return j->raw_agent;
}

int cm_jid_is_empty(const cm_jid *j)
{
    return cm_jid_server(j)[0] == '\0';
}

int cm_jid_equal(const cm_jid *a, const cm_jid *b)
{
    return strcmp(cm_jid_user(a), cm_jid_user(b)) == 0 &&
           strcmp(cm_jid_server(a), cm_jid_server(b)) == 0 &&
           a->raw_agent == b->raw_agent &&
           a->device == b->device &&
           a->integrator == b->integrator;
}

int cm_jid_is_broadcast_list(const cm_jid *j)
{
    /* StatusBroadcastJID.User is "status" */
    return strcmp(cm_jid_server(j), CM_SERVER_BROADCAST) == 0 &&
           strcmp(cm_jid_user(j), "status") != 0;
}

static int all_digits(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    return 1;
}

int cm_jid_is_bot(const cm_jid *j)
{
    const char *u = cm_jid_user(j);
    size_t n = strlen(u);

    if (strcmp(cm_jid_server(j), CM_SERVER_BOT) == 0)
        return 1;
    if (strcmp(cm_jid_server(j), CM_SERVER_DEFAULT_USER) != 0 || j->device != 0)
        return 0;
    /* ^1313555\d{4}$ | ^131655500\d{2}$ */
    if (n == 11 && strncmp(u, "1313555", 7) == 0 && all_digits(u + 7, 4))
        return 1;
    if (n == 11 && strncmp(u, "131655500", 9) == 0 && all_digits(u + 9, 2))
        return 1;
    return 0;
}

static cm_err vfmt(char **out, const char *fmt, const char *user, unsigned a,
                   unsigned b, const char *server, int kind)
{
    int n;
    char *buf;

    /* kind 0: "%s.%u:%u@%s"  1: "%s:%u@%s"  2: "%s_%u" */
    switch (kind) {
    case 0: n = snprintf(NULL, 0, fmt, user, a, b, server); break;
    case 1: n = snprintf(NULL, 0, fmt, user, b, server); break;
    default: n = snprintf(NULL, 0, fmt, user, a); break;
    }
    if (n < 0)
        return CM_ERR_ARG;
    buf = (char *)malloc((size_t)n + 1);
    if (buf == NULL)
        return CM_ERR_NOMEM;
    switch (kind) {
    case 0: snprintf(buf, (size_t)n + 1, fmt, user, a, b, server); break;
    case 1: snprintf(buf, (size_t)n + 1, fmt, user, b, server); break;
    default: snprintf(buf, (size_t)n + 1, fmt, user, a); break;
    }
    *out = buf;
    return CM_OK;
}

cm_err cm_jid_to_ad_string(const cm_jid *j, char **out)
{
    return vfmt(out, "%s.%u:%u@%s", cm_jid_user(j), j->raw_agent, j->device,
                cm_jid_server(j), 0);
}

cm_err cm_jid_to_string(const cm_jid *j, char **out)
{
    const char *u = cm_jid_user(j);
    const char *s = cm_jid_server(j);

    if (s[0] == '\0') {
        *out = cm_strdup("");
        return *out ? CM_OK : CM_ERR_NOMEM;
    }
    if (j->raw_agent > 0)
        return vfmt(out, "%s.%u:%u@%s", u, j->raw_agent, j->device, s, 0);
    if (j->device > 0)
        return vfmt(out, "%s:%u@%s", u, 0, j->device, s, 1);
    if (u[0] != '\0') {
        size_t ul = strlen(u), sl = strlen(s);
        char *r = (char *)malloc(ul + 1 + sl + 1);
        if (r == NULL)
            return CM_ERR_NOMEM;
        memcpy(r, u, ul);
        r[ul] = '@';
        memcpy(r + ul + 1, s, sl + 1);
        *out = r;
        return CM_OK;
    }
    *out = cm_strdup(s);
    return *out ? CM_OK : CM_ERR_NOMEM;
}

cm_err cm_jid_signal_address_user(const cm_jid *j, char **out)
{
    uint8_t agent = cm_jid_actual_agent(j);

    if (agent != 0)
        return vfmt(out, "%s_%u", cm_jid_user(j), agent, 0, NULL, 2);
    *out = cm_strdup(cm_jid_user(j));
    return *out ? CM_OK : CM_ERR_NOMEM;
}

cm_err cm_jid_to_non_ad(cm_jid *out, const cm_jid *j)
{
    cm_err e = cm_jid_copy(out, j);
    if (e != CM_OK)
        return e;
    out->raw_agent = 0;
    out->device = 0;
    return CM_OK;
}

/*
 * Go's strconv.Atoi on [s, s+n): optional sign, one or more decimal digits,
 * nothing else, must fit in int64. Returns 0 on success.
 */
static int go_atoi(const char *s, size_t n, long long *out)
{
    size_t i = 0;
    int neg = 0;
    unsigned long long v = 0;
    const unsigned long long max_pos = 9223372036854775807ULL;

    if (n == 0)
        return -1;
    if (s[0] == '+' || s[0] == '-') {
        neg = s[0] == '-';
        i = 1;
        if (n == 1)
            return -1;
    }
    for (; i < n; i++) {
        unsigned d;
        if (s[i] < '0' || s[i] > '9')
            return -1;
        d = (unsigned)(s[i] - '0');
        /* stop well before unsigned long long overflows */
        if (v > (max_pos + 1) / 10)
            return -1;
        v = v * 10 + d;
    }
    if (neg) {
        if (v > max_pos + 1)
            return -1;
        *out = (v == max_pos + 1) ? (-9223372036854775807LL - 1) : -(long long)v;
    } else {
        if (v > max_pos)
            return -1;
        *out = (long long)v;
    }
    return 0;
}

cm_err cm_jid_parse(cm_jid *out, const char *str)
{
    const char *at, *user_end, *srv, *srv_end, *dot, *colon;
    size_t user_len;
    cm_jid tmp;
    long long agent = 0, device = 0;
    int has_agent = 0, has_device = 0;
    cm_err e;
    const char *u;

    cm_jid_init(&tmp);
    at = strchr(str, '@');
    if (at == NULL) {
        /* NewJID("", str) */
        e = cm_jid_set(&tmp, "", str);
        if (e != CM_OK)
            return e;
        cm_jid_free(out);
        *out = tmp;
        return CM_OK;
    }

    user_end = at;
    srv = at + 1;
    srv_end = strchr(srv, '@'); /* Go's Split: parts[1] stops at next '@' */
    if (srv_end == NULL)
        srv_end = srv + strlen(srv);
    user_len = (size_t)(user_end - str);

    {
        char *ub = cm_strndup(str, user_len);
        char *sb = cm_strndup(srv, (size_t)(srv_end - srv));
        if (ub == NULL || sb == NULL) {
            free(ub);
            free(sb);
            return CM_ERR_NOMEM;
        }
        u = ub;
        dot = strchr(u, '.');
        colon = strchr(u, ':');

        if (dot != NULL) {
            /* "user.agent[:device]" - exactly one dot */
            const char *ad = dot + 1;
            const char *c2;
            size_t agent_len;

            if (strchr(ad, '.') != NULL) {
                free(ub); free(sb);
                return CM_ERR_INVALID_JID; /* unexpected number of dots */
            }
            c2 = strchr(ad, ':');
            if (c2 != NULL && strchr(c2 + 1, ':') != NULL) {
                free(ub); free(sb);
                return CM_ERR_INVALID_JID; /* unexpected number of colons */
            }
            agent_len = c2 ? (size_t)(c2 - ad) : strlen(ad);
            if (go_atoi(ad, agent_len, &agent) != 0) {
                free(ub); free(sb);
                return CM_ERR_INVALID_JID;
            }
            has_agent = 1;
            if (c2 != NULL) {
                if (go_atoi(c2 + 1, strlen(c2 + 1), &device) != 0) {
                    free(ub); free(sb);
                    return CM_ERR_INVALID_JID;
                }
                has_device = 1;
            }
            e = cm_jid_set(&tmp, "", sb);
            if (e == CM_OK) {
                char *only = cm_strndup(u, (size_t)(dot - u));
                if (only == NULL) {
                    e = CM_ERR_NOMEM;
                } else {
                    e = dup_part(&tmp.user, only, strlen(only));
                    free(only);
                }
            }
        } else if (colon != NULL) {
            /* "user:device" - exactly one colon */
            if (strchr(colon + 1, ':') != NULL) {
                free(ub); free(sb);
                return CM_ERR_INVALID_JID;
            }
            if (go_atoi(colon + 1, strlen(colon + 1), &device) != 0) {
                free(ub); free(sb);
                return CM_ERR_INVALID_JID;
            }
            has_device = 1;
            e = cm_jid_set(&tmp, "", sb);
            if (e == CM_OK) {
                char *only = cm_strndup(u, (size_t)(colon - u));
                if (only == NULL) {
                    e = CM_ERR_NOMEM;
                } else {
                    e = dup_part(&tmp.user, only, strlen(only));
                    free(only);
                }
            }
        } else {
            e = cm_jid_set(&tmp, u, sb);
        }
        free(ub);
        free(sb);
    }
    if (e != CM_OK) {
        cm_jid_free(&tmp);
        return e;
    }
    if (has_agent)
        tmp.raw_agent = (uint8_t)agent;   /* Go: uint8(agent), truncating */
    if (has_device)
        tmp.device = (uint16_t)device;    /* Go: uint16(device), truncating */
    cm_jid_free(out);
    *out = tmp;
    return CM_OK;
}
