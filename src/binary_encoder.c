/* See include/common.h for license and attribution. Port of whatsmeow/binary/encoder.go */
#include "binary.h"
#include "buf.h"
#include "token.h"

#include <stdlib.h>
#include <string.h>

#define CHECK(x)                          \
    do {                                  \
        cm_err e__ = (x);                 \
        if (e__ != CM_OK)                 \
            return e__;                   \
    } while (0)

static cm_err write_node(cm_buf *w, const cm_node *n);
static cm_err write_value(cm_buf *w, const cm_value *v);
static cm_err write_string(cm_buf *w, const char *s);

static void push_int16(cm_buf *w, unsigned v)
{
    cm_buf_put_u8(w, (uint8_t)((v >> 8) & 0xFF));
    cm_buf_put_u8(w, (uint8_t)(v & 0xFF));
}

static void push_int20(cm_buf *w, size_t v)
{
    cm_buf_put_u8(w, (uint8_t)((v >> 16) & 0x0F));
    cm_buf_put_u8(w, (uint8_t)((v >> 8) & 0xFF));
    cm_buf_put_u8(w, (uint8_t)(v & 0xFF));
}

static void push_int32(cm_buf *w, uint32_t v)
{
    cm_buf_put_u8(w, (uint8_t)((v >> 24) & 0xFF));
    cm_buf_put_u8(w, (uint8_t)((v >> 16) & 0xFF));
    cm_buf_put_u8(w, (uint8_t)((v >> 8) & 0xFF));
    cm_buf_put_u8(w, (uint8_t)(v & 0xFF));
}

static cm_err write_byte_length(cm_buf *w, size_t length)
{
    if (length < 256) {
        cm_buf_put_u8(w, CM_TOK_BINARY_8);
        cm_buf_put_u8(w, (uint8_t)length);
    } else if (length < ((size_t)1 << 20)) {
        cm_buf_put_u8(w, CM_TOK_BINARY_20);
        push_int20(w, length);
    } else if (length < (size_t)2147483647u) { /* math.MaxInt32 */
        cm_buf_put_u8(w, CM_TOK_BINARY_32);
        push_int32(w, (uint32_t)length);
    } else {
        return CM_ERR_TOO_LARGE;
    }
    return CM_OK;
}

static void write_list_start(cm_buf *w, size_t size)
{
    if (size == 0) {
        cm_buf_put_u8(w, CM_TOK_LIST_EMPTY);
    } else if (size < 256) {
        cm_buf_put_u8(w, CM_TOK_LIST_8);
        cm_buf_put_u8(w, (uint8_t)size);
    } else {
        cm_buf_put_u8(w, CM_TOK_LIST_16);
        push_int16(w, (unsigned)size);
    }
}

/* ---- packed nibble / hex strings ---- */

static int validate_nibble(const char *s, size_t n)
{
    size_t i;

    if (n > CM_TOK_PACKED_MAX)
        return 0;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!(c >= '0' && c <= '9') && c != '-' && c != '.')
            return 0;
    }
    return 1;
}

static int validate_hex(const char *s, size_t n)
{
    size_t i;

    if (n > CM_TOK_PACKED_MAX)
        return 0;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F'))
            return 0;
    }
    return 1;
}

static uint8_t pack_nibble(char c)
{
    if (c == '-')
        return 10;
    if (c == '.')
        return 11;
    if (c == 0)
        return 15;
    return (uint8_t)(c - '0'); /* validated beforehand */
}

static uint8_t pack_hex(char c)
{
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F')
        return (uint8_t)(10 + c - 'A');
    return 15; /* c == 0 */
}

static void write_packed(cm_buf *w, const char *s, size_t n, int data_type)
{
    uint8_t (*packer)(char) = (data_type == CM_TOK_NIBBLE_8) ? pack_nibble : pack_hex;
    uint8_t rounded = (uint8_t)((n + 1) / 2);
    size_t i;

    cm_buf_put_u8(w, (uint8_t)data_type);
    if (n % 2 != 0)
        rounded |= 128;
    cm_buf_put_u8(w, rounded);
    for (i = 0; i < n / 2; i++)
        cm_buf_put_u8(w, (uint8_t)((packer(s[2 * i]) << 4) | packer(s[2 * i + 1])));
    if (n % 2 != 0)
        cm_buf_put_u8(w, (uint8_t)((packer(s[n - 1]) << 4) | packer('\0')));
}

static cm_err write_string(cm_buf *w, const char *s)
{
    uint8_t dict, idx;
    size_t n = strlen(s);

    if (cm_token_index_single(s, &idx)) {
        cm_buf_put_u8(w, idx);
    } else if (cm_token_index_double(s, &dict, &idx)) {
        cm_buf_put_u8(w, (uint8_t)(CM_TOK_DICTIONARY_0 + dict));
        cm_buf_put_u8(w, idx);
    } else if (validate_nibble(s, n)) {
        write_packed(w, s, n, CM_TOK_NIBBLE_8);
    } else if (validate_hex(s, n)) {
        write_packed(w, s, n, CM_TOK_HEX_8);
    } else {
        CHECK(write_byte_length(w, n));
        cm_buf_put(w, s, n);
    }
    return CM_OK;
}

static cm_err write_bytes(cm_buf *w, const uint8_t *p, size_t n)
{
    CHECK(write_byte_length(w, n));
    cm_buf_put(w, p, n);
    return CM_OK;
}

static cm_err write_jid(cm_buf *w, const cm_jid *j)
{
    const char *server = cm_jid_server(j);
    const char *user = cm_jid_user(j);
    int is_default = strcmp(server, CM_SERVER_DEFAULT_USER) == 0;
    int is_hidden = strcmp(server, CM_SERVER_HIDDEN_USER) == 0;

    if (((is_default || is_hidden) && j->device > 0) ||
        strcmp(server, CM_SERVER_HOSTED) == 0 ||
        strcmp(server, CM_SERVER_HOSTED_LID) == 0) {
        cm_buf_put_u8(w, CM_TOK_AD_JID);
        cm_buf_put_u8(w, cm_jid_actual_agent(j));
        cm_buf_put_u8(w, (uint8_t)j->device);
        return write_string(w, user);
    }
    if (strcmp(server, CM_SERVER_MESSENGER) == 0) {
        cm_buf_put_u8(w, CM_TOK_FB_JID);
        CHECK(write_string(w, user));
        push_int16(w, j->device);
        return write_string(w, server);
    }
    if (strcmp(server, CM_SERVER_INTEROP) == 0) {
        cm_buf_put_u8(w, CM_TOK_INTEROP_JID);
        CHECK(write_string(w, user));
        push_int16(w, j->device);
        push_int16(w, j->integrator);
        return write_string(w, server);
    }
    cm_buf_put_u8(w, CM_TOK_JID_PAIR);
    if (user[0] == '\0')
        cm_buf_put_u8(w, CM_TOK_LIST_EMPTY);
    else
        CHECK(write_string(w, user));
    return write_string(w, server);
}

static cm_err write_value(cm_buf *w, const cm_value *v)
{
    size_t i;

    switch (v->type) {
    case CM_V_NIL:
        cm_buf_put_u8(w, CM_TOK_LIST_EMPTY);
        return CM_OK;
    case CM_V_STR:
        return write_string(w, v->u.str);
    case CM_V_JID:
        return write_jid(w, &v->u.jid);
    case CM_V_BYTES:
        return write_bytes(w, v->u.bytes.data, v->u.bytes.len);
    case CM_V_NODES:
        if (v->u.nodes.len > 65535)
            return CM_ERR_TOO_LARGE; /* does not fit a List16 size */
        write_list_start(w, v->u.nodes.len);
        for (i = 0; i < v->u.nodes.len; i++)
            CHECK(write_node(w, &v->u.nodes.items[i]));
        return CM_OK;
    }
    return CM_ERR_INVALID_TYPE;
}

/* Attributes whose value is nil or an empty string are not encoded. */
static int attr_skipped(const cm_value *v)
{
    return v->type == CM_V_NIL || (v->type == CM_V_STR && v->u.str[0] == '\0');
}

static cm_err write_node(cm_buf *w, const cm_node *n)
{
    size_t i, count = 0;
    size_t list_size;

    if (n->tag == NULL)
        return CM_ERR_INVALID_NODE;
    if (strcmp(n->tag, "0") == 0) {
        cm_buf_put_u8(w, CM_TOK_LIST_8);
        cm_buf_put_u8(w, CM_TOK_LIST_EMPTY);
        return CM_OK;
    }
    for (i = 0; i < n->nattrs; i++)
        if (!attr_skipped(&n->attrs[i].val))
            count++;
    list_size = 2 * count + 1 + (n->content.type != CM_V_NIL ? 1 : 0);
    if (list_size > 65535)
        return CM_ERR_TOO_LARGE;

    write_list_start(w, list_size);
    CHECK(write_string(w, n->tag));
    for (i = 0; i < n->nattrs; i++) {
        if (attr_skipped(&n->attrs[i].val))
            continue;
        CHECK(write_string(w, n->attrs[i].key));
        CHECK(write_value(w, &n->attrs[i].val));
    }
    if (n->content.type != CM_V_NIL)
        CHECK(write_value(w, &n->content));
    return CM_OK;
}

cm_err cm_binary_marshal(const cm_node *n, uint8_t **out, size_t *out_len)
{
    cm_buf w;
    cm_err e;

    if (n == NULL || out == NULL || out_len == NULL)
        return CM_ERR_ARG;
    cm_buf_init(&w);
    cm_buf_put_u8(&w, 0); /* "not compressed" flag */
    e = write_node(&w, n);
    if (e == CM_OK)
        e = w.err;
    if (e != CM_OK) {
        cm_buf_free(&w);
        return e;
    }
    *out = cm_buf_detach(&w, out_len);
    return CM_OK;
}
