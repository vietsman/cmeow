/* See include/common.h for license and attribution. Port of whatsmeow/binary/node.go */
#include "node.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cm_value_init(cm_value *v)
{
    memset(v, 0, sizeof(*v));
    v->type = CM_V_NIL;
}

void cm_value_free(cm_value *v)
{
    size_t i;

    switch (v->type) {
    case CM_V_STR:
        free(v->u.str);
        break;
    case CM_V_JID:
        cm_jid_free(&v->u.jid);
        break;
    case CM_V_BYTES:
        free(v->u.bytes.data);
        break;
    case CM_V_NODES:
        for (i = 0; i < v->u.nodes.len; i++)
            cm_node_free(&v->u.nodes.items[i]);
        free(v->u.nodes.items);
        break;
    case CM_V_NIL:
        break;
    }
    cm_value_init(v);
}

void cm_node_init(cm_node *n)
{
    n->tag = NULL;
    n->attrs = NULL;
    n->nattrs = 0;
    n->cap_attrs = 0;
    cm_value_init(&n->content);
}

void cm_node_free(cm_node *n)
{
    size_t i;

    free(n->tag);
    for (i = 0; i < n->nattrs; i++) {
        free(n->attrs[i].key);
        cm_value_free(&n->attrs[i].val);
    }
    free(n->attrs);
    cm_value_free(&n->content);
    cm_node_init(n);
}

cm_err cm_value_clone(cm_value *dst, const cm_value *src)
{
    cm_value out;
    size_t i;
    cm_err e;

    cm_value_init(&out);
    switch (src->type) {
    case CM_V_NIL:
        break;
    case CM_V_STR:
        out.u.str = cm_strdup(src->u.str);
        if (out.u.str == NULL)
            return CM_ERR_NOMEM;
        break;
    case CM_V_JID:
        cm_jid_init(&out.u.jid);
        out.type = CM_V_JID; /* so a failed clone frees correctly */
        e = cm_jid_copy(&out.u.jid, &src->u.jid);
        if (e != CM_OK) {
            cm_value_free(&out);
            return e;
        }
        break;
    case CM_V_BYTES:
        out.u.bytes.data = (uint8_t *)cm_memdup(src->u.bytes.data, src->u.bytes.len);
        if (out.u.bytes.data == NULL)
            return CM_ERR_NOMEM;
        out.u.bytes.len = src->u.bytes.len;
        break;
    case CM_V_NODES:
        out.u.nodes.items = (cm_node *)calloc(src->u.nodes.len ? src->u.nodes.len : 1,
                                              sizeof(cm_node));
        if (out.u.nodes.items == NULL)
            return CM_ERR_NOMEM;
        out.u.nodes.cap = src->u.nodes.len ? src->u.nodes.len : 1;
        out.type = CM_V_NODES;
        for (i = 0; i < src->u.nodes.len; i++) {
            cm_node_init(&out.u.nodes.items[i]);
            out.u.nodes.len = i + 1;
            e = cm_node_clone(&out.u.nodes.items[i], &src->u.nodes.items[i]);
            if (e != CM_OK) {
                cm_value_free(&out);
                return e;
            }
        }
        break;
    }
    out.type = src->type;
    cm_value_free(dst);
    *dst = out;
    return CM_OK;
}

cm_err cm_node_clone(cm_node *dst, const cm_node *src)
{
    cm_node out;
    size_t i;
    cm_err e;

    cm_node_init(&out);
    if (src->tag != NULL) {
        out.tag = cm_strdup(src->tag);
        if (out.tag == NULL)
            return CM_ERR_NOMEM;
    }
    for (i = 0; i < src->nattrs; i++) {
        cm_value v;

        cm_value_init(&v);
        e = cm_value_clone(&v, &src->attrs[i].val);
        if (e == CM_OK)
            e = cm_node_set_attr_value(&out, src->attrs[i].key, &v);
        if (e != CM_OK) {
            cm_value_free(&v);
            cm_node_free(&out);
            return e;
        }
    }
    e = cm_value_clone(&out.content, &src->content);
    if (e != CM_OK) {
        cm_node_free(&out);
        return e;
    }
    cm_node_free(dst);
    *dst = out;
    return CM_OK;
}

cm_err cm_node_set_tag(cm_node *n, const char *tag)
{
    char *t = cm_strdup(tag);

    if (t == NULL)
        return CM_ERR_NOMEM;
    free(n->tag);
    n->tag = t;
    return CM_OK;
}

static cm_attr *find_attr(const cm_node *n, const char *key)
{
    size_t i;

    for (i = 0; i < n->nattrs; i++)
        if (strcmp(n->attrs[i].key, key) == 0)
            return &n->attrs[i];
    return NULL;
}

const cm_value *cm_node_get_attr(const cm_node *n, const char *key)
{
    const cm_attr *a = find_attr(n, key);
    return a ? &a->val : NULL;
}

cm_err cm_node_set_attr_value(cm_node *n, const char *key, cm_value *val)
{
    cm_attr *a = find_attr(n, key);
    char *k;

    if (a != NULL) {
        cm_value_free(&a->val);
        a->val = *val;
        cm_value_init(val);
        return CM_OK;
    }
    if (n->nattrs == n->cap_attrs) {
        size_t ncap = n->cap_attrs ? n->cap_attrs * 2 : 4;
        cm_attr *na;

        if (ncap > ((size_t)-1) / sizeof(cm_attr))
            return CM_ERR_NOMEM;
        na = (cm_attr *)realloc(n->attrs, ncap * sizeof(cm_attr));
        if (na == NULL)
            return CM_ERR_NOMEM;
        n->attrs = na;
        n->cap_attrs = ncap;
    }
    k = cm_strdup(key);
    if (k == NULL)
        return CM_ERR_NOMEM;
    n->attrs[n->nattrs].key = k;
    n->attrs[n->nattrs].val = *val;
    n->nattrs++;
    cm_value_init(val);
    return CM_OK;
}

cm_err cm_node_set_attr_str(cm_node *n, const char *key, const char *val)
{
    cm_value v;
    cm_err e;

    cm_value_init(&v);
    v.u.str = cm_strdup(val);
    if (v.u.str == NULL)
        return CM_ERR_NOMEM;
    v.type = CM_V_STR;
    e = cm_node_set_attr_value(n, key, &v);
    if (e != CM_OK)
        cm_value_free(&v);
    return e;
}

cm_err cm_node_set_attr_jid(cm_node *n, const char *key, const cm_jid *val)
{
    cm_value v;
    cm_err e;

    cm_value_init(&v);
    cm_jid_init(&v.u.jid);
    v.type = CM_V_JID;
    e = cm_jid_copy(&v.u.jid, val);
    if (e == CM_OK)
        e = cm_node_set_attr_value(n, key, &v);
    if (e != CM_OK)
        cm_value_free(&v);
    return e;
}

cm_err cm_node_set_attr_i64(cm_node *n, const char *key, int64_t val)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%" PRId64, val);
    return cm_node_set_attr_str(n, key, buf);
}

cm_err cm_node_set_attr_u64(cm_node *n, const char *key, uint64_t val)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%" PRIu64, val);
    return cm_node_set_attr_str(n, key, buf);
}

cm_err cm_node_set_attr_bool(cm_node *n, const char *key, int val)
{
    return cm_node_set_attr_str(n, key, val ? "true" : "false");
}

cm_err cm_node_set_content_str(cm_node *n, const char *s)
{
    cm_value v;

    cm_value_init(&v);
    v.u.str = cm_strdup(s);
    if (v.u.str == NULL)
        return CM_ERR_NOMEM;
    v.type = CM_V_STR;
    cm_value_free(&n->content);
    n->content = v;
    return CM_OK;
}

cm_err cm_node_set_content_bytes(cm_node *n, const void *data, size_t len)
{
    cm_value v;

    cm_value_init(&v);
    v.u.bytes.data = (uint8_t *)cm_memdup(data, len);
    if (v.u.bytes.data == NULL)
        return CM_ERR_NOMEM;
    v.u.bytes.len = len;
    v.type = CM_V_BYTES;
    cm_value_free(&n->content);
    n->content = v;
    return CM_OK;
}

cm_err cm_node_set_content_jid(cm_node *n, const cm_jid *j)
{
    cm_value v;
    cm_err e;

    cm_value_init(&v);
    cm_jid_init(&v.u.jid);
    v.type = CM_V_JID;
    e = cm_jid_copy(&v.u.jid, j);
    if (e != CM_OK) {
        cm_value_free(&v);
        return e;
    }
    cm_value_free(&n->content);
    n->content = v;
    return CM_OK;
}

cm_err cm_node_set_content_empty_list(cm_node *n)
{
    cm_value v;

    cm_value_init(&v);
    v.type = CM_V_NODES;
    cm_value_free(&n->content);
    n->content = v;
    return CM_OK;
}

cm_err cm_node_add_child(cm_node *n, cm_node *child)
{
    cm_value *c = &n->content;

    if (c->type == CM_V_NIL) {
        c->type = CM_V_NODES;
        c->u.nodes.items = NULL;
        c->u.nodes.len = 0;
        c->u.nodes.cap = 0;
    } else if (c->type != CM_V_NODES) {
        return CM_ERR_INVALID_TYPE;
    }
    if (c->u.nodes.len == c->u.nodes.cap) {
        size_t ncap = c->u.nodes.cap ? c->u.nodes.cap * 2 : 4;
        cm_node *ni;

        if (ncap > ((size_t)-1) / sizeof(cm_node))
            return CM_ERR_NOMEM;
        ni = (cm_node *)realloc(c->u.nodes.items, ncap * sizeof(cm_node));
        if (ni == NULL)
            return CM_ERR_NOMEM;
        c->u.nodes.items = ni;
        c->u.nodes.cap = ncap;
    }
    c->u.nodes.items[c->u.nodes.len++] = *child;
    cm_node_init(child);
    return CM_OK;
}

size_t cm_node_nchildren(const cm_node *n)
{
    return n->content.type == CM_V_NODES ? n->content.u.nodes.len : 0;
}

const cm_node *cm_node_child_at(const cm_node *n, size_t i)
{
    if (n->content.type != CM_V_NODES || i >= n->content.u.nodes.len)
        return NULL;
    return &n->content.u.nodes.items[i];
}

const cm_node *cm_node_child(const cm_node *n, const char *tag)
{
    size_t i, cnt = cm_node_nchildren(n);

    for (i = 0; i < cnt; i++) {
        const cm_node *c = &n->content.u.nodes.items[i];
        if (c->tag != NULL && strcmp(c->tag, tag) == 0)
            return c;
    }
    return NULL;
}
