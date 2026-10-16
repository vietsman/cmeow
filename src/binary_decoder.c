/* See include/common.h for license and attribution. Port of whatsmeow/binary/decoder.go */
#include "binary.h"
#include "token.h"

#include <stdlib.h>
#include <string.h>

#define CHECK(x)                          \
    do {                                  \
        cm_err e__ = (x);                 \
        if (e__ != CM_OK)                 \
            return e__;                   \
    } while (0)

typedef struct dec {
    const uint8_t *data;
    size_t len;
    size_t idx;
} dec;

static cm_err d_value(dec *d, int as_string, cm_value *out, unsigned depth);
static cm_err d_node(dec *d, cm_node *out, unsigned depth);

static cm_err d_need(const dec *d, size_t n)
{
    return (d->len - d->idx >= n) ? CM_OK : CM_ERR_EOF;
}

static cm_err d_u8(dec *d, unsigned *out)
{
    CHECK(d_need(d, 1));
    *out = d->data[d->idx++];
    return CM_OK;
}

static cm_err d_u16(dec *d, unsigned *out)
{
    CHECK(d_need(d, 2));
    *out = ((unsigned)d->data[d->idx] << 8) | d->data[d->idx + 1];
    d->idx += 2;
    return CM_OK;
}

static cm_err d_int20(dec *d, size_t *out)
{
    CHECK(d_need(d, 3));
    *out = (((size_t)d->data[d->idx] & 15) << 16) |
           ((size_t)d->data[d->idx + 1] << 8) | d->data[d->idx + 2];
    d->idx += 3;
    return CM_OK;
}

static cm_err d_u32(dec *d, uint32_t *out)
{
    CHECK(d_need(d, 4));
    *out = ((uint32_t)d->data[d->idx] << 24) | ((uint32_t)d->data[d->idx + 1] << 16) |
           ((uint32_t)d->data[d->idx + 2] << 8) | d->data[d->idx + 3];
    d->idx += 4;
    return CM_OK;
}

/* Copy n bytes into a C string; embedded NULs are not representable. */
static cm_err make_string(const uint8_t *p, size_t n, char **out)
{
    if (n != 0 && memchr(p, 0, n) != NULL)
        return CM_ERR_INVALID_TOKEN;
    *out = cm_strndup((const char *)p, n);
    return *out ? CM_OK : CM_ERR_NOMEM;
}

static cm_err unpack_nibble(unsigned v, char *out)
{
    if (v < 10)
        *out = (char)('0' + v);
    else if (v == 10)
        *out = '-';
    else if (v == 11)
        *out = '.';
    else if (v == 15)
        *out = '\0';
    else
        return CM_ERR_INVALID_TOKEN;
    return CM_OK;
}

static cm_err unpack_hex(unsigned v, char *out)
{
    if (v < 10)
        *out = (char)('0' + v);
    else if (v < 16)
        *out = (char)('A' + v - 10);
    else
        return CM_ERR_INVALID_TOKEN;
    return CM_OK;
}

static cm_err d_packed8(dec *d, unsigned tag, char **out)
{
    unsigned start;
    size_t n, i, outlen;
    char *buf;
    cm_err e;

    CHECK(d_u8(d, &start));
    n = start & 127;
    CHECK(d_need(d, n));
    buf = (char *)malloc(2 * n + 1);
    if (buf == NULL)
        return CM_ERR_NOMEM;
    for (i = 0; i < n; i++) {
        unsigned b = d->data[d->idx++];
        unsigned hi = (b & 0xF0) >> 4, lo = b & 0x0F;

        if (tag == CM_TOK_NIBBLE_8) {
            e = unpack_nibble(hi, &buf[2 * i]);
            if (e == CM_OK)
                e = unpack_nibble(lo, &buf[2 * i + 1]);
        } else {
            e = unpack_hex(hi, &buf[2 * i]);
            if (e == CM_OK)
                e = unpack_hex(lo, &buf[2 * i + 1]);
        }
        if (e != CM_OK) {
            free(buf);
            return e;
        }
    }
    outlen = 2 * n;
    if ((start >> 7) != 0) {
        if (outlen == 0) { /* Go would panic slicing [:-1] */
            free(buf);
            return CM_ERR_INVALID_TOKEN;
        }
        outlen--;
    }
    buf[outlen] = '\0';
    if (strlen(buf) != outlen) { /* embedded NUL */
        free(buf);
        return CM_ERR_INVALID_TOKEN;
    }
    *out = buf;
    return CM_OK;
}

static cm_err d_bytes_or_string(dec *d, size_t len, int as_string, cm_value *out)
{
    CHECK(d_need(d, len));
    if (as_string) {
        CHECK(make_string(d->data + d->idx, len, &out->u.str));
        out->type = CM_V_STR;
    } else {
        out->u.bytes.data = (uint8_t *)cm_memdup(d->data + d->idx, len);
        if (out->u.bytes.data == NULL)
            return CM_ERR_NOMEM;
        out->u.bytes.len = len;
        out->type = CM_V_BYTES;
    }
    d->idx += len;
    return CM_OK;
}

static cm_err d_list_size(dec *d, unsigned tag, size_t *out)
{
    unsigned v;

    switch (tag) {
    case CM_TOK_LIST_EMPTY:
        *out = 0;
        return CM_OK;
    case CM_TOK_LIST_8:
        CHECK(d_u8(d, &v));
        *out = v;
        return CM_OK;
    case CM_TOK_LIST_16:
        CHECK(d_u16(d, &v));
        *out = v;
        return CM_OK;
    default:
        return CM_ERR_INVALID_TOKEN;
    }
}

static cm_err d_list(dec *d, unsigned tag, cm_value *out, unsigned depth)
{
    size_t size, i;
    cm_node *items;

    CHECK(d_list_size(d, tag, &size));
    /* every node takes at least one byte: reject absurd sizes before allocating */
    if (size > d->len - d->idx)
        return CM_ERR_EOF;
    items = (cm_node *)calloc(size ? size : 1, sizeof(cm_node));
    if (items == NULL)
        return CM_ERR_NOMEM;
    out->type = CM_V_NODES;
    out->u.nodes.items = items;
    out->u.nodes.len = 0;
    out->u.nodes.cap = size ? size : 1;
    for (i = 0; i < size; i++) {
        cm_err e = d_node(d, &items[i], depth + 1);
        if (e != CM_OK) {
            cm_value_free(out);
            return e;
        }
        out->u.nodes.len = i + 1;
    }
    return CM_OK;
}

/* Reads a string-typed sub-value (read(true) in Go); *out is owned by caller. */
static cm_err d_str_or_nil(dec *d, cm_value *v, unsigned depth)
{
    cm_value_init(v);
    return d_value(d, 1, v, depth);
}

static cm_err d_jid_pair(dec *d, cm_value *out, unsigned depth)
{
    cm_value user, server;
    cm_err e;

    e = d_str_or_nil(d, &user, depth + 1);
    if (e != CM_OK)
        return e;
    e = d_str_or_nil(d, &server, depth + 1);
    if (e != CM_OK) {
        cm_value_free(&user);
        return e;
    }
    if (server.type == CM_V_NIL) {
        e = CM_ERR_INVALID_JID_TYPE;
    } else if (server.type != CM_V_STR || (user.type != CM_V_NIL && user.type != CM_V_STR)) {
        e = CM_ERR_INVALID_JID_TYPE; /* Go would panic on the type assertion */
    } else {
        cm_jid_init(&out->u.jid);
        out->type = CM_V_JID;
        e = cm_jid_set(&out->u.jid, user.type == CM_V_STR ? user.u.str : "", server.u.str);
        if (e != CM_OK)
            cm_value_free(out);
    }
    cm_value_free(&user);
    cm_value_free(&server);
    return e;
}

/* Shared body of the FB and interop JID forms. */
static cm_err d_dev_jid(dec *d, cm_value *out, unsigned depth, int interop)
{
    cm_value user, server;
    unsigned device, integrator = 0;
    const char *want = interop ? CM_SERVER_INTEROP : CM_SERVER_MESSENGER;
    cm_err e;

    e = d_str_or_nil(d, &user, depth + 1);
    if (e != CM_OK)
        return e;
    e = d_u16(d, &device);
    if (e == CM_OK && interop)
        e = d_u16(d, &integrator);
    if (e != CM_OK) {
        cm_value_free(&user);
        return e;
    }
    e = d_str_or_nil(d, &server, depth + 1);
    if (e != CM_OK) {
        cm_value_free(&user);
        return e;
    }
    if (server.type != CM_V_STR || strcmp(server.u.str, want) != 0 || user.type != CM_V_STR) {
        e = CM_ERR_INVALID_JID_TYPE;
    } else {
        cm_jid_init(&out->u.jid);
        out->type = CM_V_JID;
        e = cm_jid_set(&out->u.jid, user.u.str, server.u.str);
        if (e != CM_OK) {
            cm_value_free(out);
        } else {
            out->u.jid.device = (uint16_t)device;
            out->u.jid.integrator = (uint16_t)integrator;
        }
    }
    cm_value_free(&user);
    cm_value_free(&server);
    return e;
}

static cm_err d_ad_jid(dec *d, cm_value *out, unsigned depth)
{
    unsigned agent, device;
    cm_value user;
    cm_err e;

    CHECK(d_u8(d, &agent));
    CHECK(d_u8(d, &device));
    e = d_str_or_nil(d, &user, depth + 1);
    if (e != CM_OK)
        return e;
    if (user.type != CM_V_STR) {
        cm_value_free(&user);
        return CM_ERR_INVALID_JID_TYPE;
    }
    cm_jid_init(&out->u.jid);
    out->type = CM_V_JID;
    e = cm_jid_set_ad(&out->u.jid, user.u.str, (uint8_t)agent, (uint8_t)device);
    if (e != CM_OK)
        cm_value_free(out);
    cm_value_free(&user);
    return e;
}

/* d_value is read(string bool) in decoder.go. `out` must be initialised. */
static cm_err d_value(dec *d, int as_string, cm_value *out, unsigned depth)
{
    unsigned tag, i;
    size_t size;
    uint32_t size32;
    const char *tok;

    if (depth > CM_BINARY_MAX_DEPTH)
        return CM_ERR_DEPTH;
    CHECK(d_u8(d, &tag));

    switch (tag) {
    case CM_TOK_LIST_EMPTY:
        return CM_OK; /* nil */
    case CM_TOK_LIST_8:
    case CM_TOK_LIST_16:
        return d_list(d, tag, out, depth);
    case CM_TOK_BINARY_8:
        CHECK(d_u8(d, &i));
        return d_bytes_or_string(d, i, as_string, out);
    case CM_TOK_BINARY_20:
        CHECK(d_int20(d, &size));
        return d_bytes_or_string(d, size, as_string, out);
    case CM_TOK_BINARY_32:
        CHECK(d_u32(d, &size32));
        return d_bytes_or_string(d, size32, as_string, out);
    case CM_TOK_DICTIONARY_0:
    case CM_TOK_DICTIONARY_1:
    case CM_TOK_DICTIONARY_2:
    case CM_TOK_DICTIONARY_3:
        CHECK(d_u8(d, &i));
        tok = cm_token_get_double((int)(tag - CM_TOK_DICTIONARY_0), (int)i);
        if (tok == NULL)
            return CM_ERR_INVALID_TOKEN;
        out->u.str = cm_strdup(tok);
        if (out->u.str == NULL)
            return CM_ERR_NOMEM;
        out->type = CM_V_STR;
        return CM_OK;
    case CM_TOK_FB_JID:
        return d_dev_jid(d, out, depth, 0);
    case CM_TOK_INTEROP_JID:
        return d_dev_jid(d, out, depth, 1);
    case CM_TOK_JID_PAIR:
        return d_jid_pair(d, out, depth);
    case CM_TOK_AD_JID:
        return d_ad_jid(d, out, depth);
    case CM_TOK_NIBBLE_8:
    case CM_TOK_HEX_8:
        CHECK(d_packed8(d, tag, &out->u.str));
        out->type = CM_V_STR;
        return CM_OK;
    default:
        if (tag >= 1 && tag < cm_single_token_count) {
            out->u.str = cm_strdup(cm_single_tokens[tag]);
            if (out->u.str == NULL)
                return CM_ERR_NOMEM;
            out->type = CM_V_STR;
            return CM_OK;
        }
        return CM_ERR_INVALID_TOKEN;
    }
}

static cm_err d_node_inner(dec *d, cm_node *out, unsigned depth)
{
    unsigned size_tag;
    size_t list_size, pairs, i;
    cm_value v;

    CHECK(d_u8(d, &size_tag));
    CHECK(d_list_size(d, size_tag, &list_size));

    cm_value_init(&v);
    CHECK(d_value(d, 1, &v, depth));
    if (v.type != CM_V_STR) { /* Go: rawDesc.(string) would panic */
        cm_value_free(&v);
        return CM_ERR_INVALID_NODE;
    }
    out->tag = v.u.str; /* take ownership */
    if (list_size == 0 || out->tag[0] == '\0')
        return CM_ERR_INVALID_NODE;

    pairs = (list_size - 1) >> 1;
    for (i = 0; i < pairs; i++) {
        cm_value key, val;
        cm_err e;

        cm_value_init(&key);
        CHECK(d_value(d, 1, &key, depth));
        if (key.type != CM_V_STR) {
            cm_value_free(&key);
            return CM_ERR_NON_STRING_KEY;
        }
        cm_value_init(&val);
        e = d_value(d, 1, &val, depth);
        if (e == CM_OK)
            e = cm_node_set_attr_value(out, key.u.str, &val);
        cm_value_free(&key);
        if (e != CM_OK) {
            cm_value_free(&val);
            return e;
        }
    }
    if (list_size % 2 == 1)
        return CM_OK;
    return d_value(d, 0, &out->content, depth);
}

/* On any failure *out is freed and left empty. */
static cm_err d_node(dec *d, cm_node *out, unsigned depth)
{
    cm_err e;

    cm_node_init(out);
    e = d_node_inner(d, out, depth);
    if (e != CM_OK)
        cm_node_free(out);
    return e;
}

cm_err cm_binary_unmarshal(const uint8_t *data, size_t len, cm_node *out)
{
    dec d;
    cm_node tmp;
    cm_err e;

    if (out == NULL || (data == NULL && len != 0))
        return CM_ERR_ARG;
    d.data = data;
    d.len = len;
    d.idx = 0;
    e = d_node(&d, &tmp, 0);
    if (e != CM_OK)
        return e;
    if (d.idx != d.len) {
        cm_node_free(&tmp);
        return CM_ERR_TRAILING_DATA;
    }
    cm_node_free(out);
    *out = tmp;
    return CM_OK;
}
