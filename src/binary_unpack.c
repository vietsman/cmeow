/* See include/common.h for license and attribution. Port of whatsmeow/binary/unpack.go */
#include "binary.h"
#include "buf.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

cm_err cm_binary_unpack(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len)
{
    z_stream zs;
    cm_buf b;
    uint8_t chunk[16384];
    int zr;

    if (data == NULL || len == 0 || out == NULL || out_len == NULL)
        return CM_ERR_EOF; /* Go would panic on data[0] */

    if ((data[0] & 2) == 0) {
        uint8_t *copy = (uint8_t *)cm_memdup(data + 1, len - 1);
        if (copy == NULL)
            return CM_ERR_NOMEM;
        *out = copy;
        *out_len = len - 1;
        return CM_OK;
    }

    if (len - 1 > UINT_MAX)
        return CM_ERR_TOO_LARGE;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK)
        return CM_ERR_ZLIB;
    /* old zlib (e.g. the BB10 NDK) declares next_in non-const; it never writes through it */
    zs.next_in = (Bytef *)(uintptr_t)(data + 1);
    zs.avail_in = (uInt)(len - 1);

    cm_buf_init(&b);
    do {
        size_t produced;

        zs.next_out = chunk;
        zs.avail_out = (uInt)sizeof(chunk);
        zr = inflate(&zs, Z_NO_FLUSH);
        if (zr != Z_OK && zr != Z_STREAM_END) {
            /* Z_BUF_ERROR here means a truncated stream */
            inflateEnd(&zs);
            cm_buf_free(&b);
            return CM_ERR_ZLIB;
        }
        produced = sizeof(chunk) - zs.avail_out;
        if (b.len + produced > CM_BINARY_MAX_UNPACKED) {
            inflateEnd(&zs);
            cm_buf_free(&b);
            return CM_ERR_TOO_LARGE;
        }
        cm_buf_put(&b, chunk, produced);
        if (b.err != CM_OK) {
            cm_err e = b.err;
            inflateEnd(&zs);
            cm_buf_free(&b);
            return e;
        }
    } while (zr != Z_STREAM_END);
    inflateEnd(&zs);

    *out = cm_buf_detach(&b, out_len);
    if (*out == NULL) { /* empty result */
        *out = (uint8_t *)malloc(1);
        if (*out == NULL)
            return CM_ERR_NOMEM;
    }
    return CM_OK;
}
