/* See common.h for license and attribution. */
#ifndef CMEOW_BUF_H
#define CMEOW_BUF_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Growable byte buffer with a sticky error flag: once an allocation fails,
 * further appends are no-ops and `err` stays set, so callers can append
 * freely and check `err` once at the end.
 */
typedef struct cm_buf {
    uint8_t *data;
    size_t len;
    size_t cap;
    cm_err err;
} cm_buf;

void cm_buf_init(cm_buf *b);
void cm_buf_free(cm_buf *b);
void cm_buf_put_u8(cm_buf *b, uint8_t v);
void cm_buf_put(cm_buf *b, const void *p, size_t n);

/* Take ownership of the data (free with free()). The buffer is reset. */
uint8_t *cm_buf_detach(cm_buf *b, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_BUF_H */
