/* See include/common.h for license and attribution. */
#include "buf.h"

#include <stdlib.h>
#include <string.h>

void cm_buf_init(cm_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->err = CM_OK;
}

void cm_buf_free(cm_buf *b)
{
    free(b->data);
    cm_buf_init(b);
}

static int buf_reserve(cm_buf *b, size_t extra)
{
    size_t need, ncap;
    uint8_t *nd;

    if (b->err != CM_OK)
        return 0;
    if (extra > ((size_t)-1) - b->len) {
        b->err = CM_ERR_TOO_LARGE;
        return 0;
    }
    need = b->len + extra;
    if (need <= b->cap)
        return 1;
    ncap = b->cap ? b->cap : 64;
    while (ncap < need) {
        if (ncap > ((size_t)-1) / 2) {
            ncap = need;
            break;
        }
        ncap *= 2;
    }
    nd = (uint8_t *)realloc(b->data, ncap);
    if (nd == NULL) {
        b->err = CM_ERR_NOMEM;
        return 0;
    }
    b->data = nd;
    b->cap = ncap;
    return 1;
}

void cm_buf_put_u8(cm_buf *b, uint8_t v)
{
    if (buf_reserve(b, 1))
        b->data[b->len++] = v;
}

void cm_buf_put(cm_buf *b, const void *p, size_t n)
{
    if (n == 0)
        return;
    if (buf_reserve(b, n)) {
        memcpy(b->data + b->len, p, n);
        b->len += n;
    }
}

uint8_t *cm_buf_detach(cm_buf *b, size_t *len)
{
    uint8_t *d = b->data;
    if (len != NULL)
        *len = b->len;
    cm_buf_init(b);
    return d;
}
