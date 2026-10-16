/* See common.h for license and attribution. Port of whatsmeow/binary/node.go */
#ifndef CMEOW_NODE_H
#define CMEOW_NODE_H

#include "common.h"
#include "jid.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Whatsmeow's Node uses Go's `any` for attribute values and content. Here a
 * cm_value is an explicit tagged union covering the types the binary XML
 * format can actually carry.
 *
 * Ownership: every pointer inside a cm_value / cm_node is owned by it and is
 * released by cm_node_free / cm_value_free. Zero-initialise before use.
 */
typedef enum cm_vtype {
    CM_V_NIL = 0,
    CM_V_STR,
    CM_V_JID,
    CM_V_BYTES,
    CM_V_NODES
} cm_vtype;

struct cm_node;

typedef struct cm_value {
    cm_vtype type;
    union {
        char *str;
        cm_jid jid;
        struct {
            uint8_t *data;
            size_t len;
        } bytes;
        struct {
            struct cm_node *items;
            size_t len;
            size_t cap;
        } nodes;
    } u;
} cm_value;

typedef struct cm_attr {
    char *key;
    cm_value val;
} cm_attr;

typedef struct cm_node {
    char *tag;
    cm_attr *attrs; /* insertion ordered */
    size_t nattrs;
    size_t cap_attrs;
    cm_value content;
} cm_node;

void cm_value_init(cm_value *v);
void cm_value_free(cm_value *v);
cm_err cm_value_clone(cm_value *dst, const cm_value *src); /* dst must be init */

void cm_node_init(cm_node *n);
void cm_node_free(cm_node *n);
cm_err cm_node_clone(cm_node *dst, const cm_node *src); /* dst must be init */

cm_err cm_node_set_tag(cm_node *n, const char *tag);

/* Setting an existing key replaces its value. Values are copied. */
cm_err cm_node_set_attr_str(cm_node *n, const char *key, const char *val);
cm_err cm_node_set_attr_jid(cm_node *n, const char *key, const cm_jid *val);
cm_err cm_node_set_attr_i64(cm_node *n, const char *key, int64_t val);
cm_err cm_node_set_attr_u64(cm_node *n, const char *key, uint64_t val);
cm_err cm_node_set_attr_bool(cm_node *n, const char *key, int val);
/* Takes ownership of *val (which is reset to nil on success). */
cm_err cm_node_set_attr_value(cm_node *n, const char *key, cm_value *val);

/* Borrowed pointer, or NULL if the key is absent. */
const cm_value *cm_node_get_attr(const cm_node *n, const char *key);

cm_err cm_node_set_content_str(cm_node *n, const char *s);
cm_err cm_node_set_content_bytes(cm_node *n, const void *data, size_t len);
cm_err cm_node_set_content_jid(cm_node *n, const cm_jid *j);
/* Appends a child, taking ownership of *child (which is zeroed). Turns the
 * content into a node list if it was nil; fails if it held other data. */
cm_err cm_node_add_child(cm_node *n, cm_node *child);

/* Sets the content to an empty (but present) node list, like Go's
 * `Content: []Node{}`. It encodes as an empty list token, unlike nil content. */
cm_err cm_node_set_content_empty_list(cm_node *n);

/* GetChildren: number of children / child by index (NULL when not a list). */
size_t cm_node_nchildren(const cm_node *n);
const cm_node *cm_node_child_at(const cm_node *n, size_t i);
/* GetOptionalChildByTag: first child with the given tag; NULL if none. */
const cm_node *cm_node_child(const cm_node *n, const char *tag);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_NODE_H */
