/* See common.h for license and attribution. Port of whatsmeow/binary */
#ifndef CMEOW_BINARY_H
#define CMEOW_BINARY_H

#include "common.h"
#include "node.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum element nesting accepted by the decoder (defence against stack
 * exhaustion on hostile input; real traffic is far shallower). */
#define CM_BINARY_MAX_DEPTH 256

/* Upper bound for zlib-decompressed frames in cm_binary_unpack. */
#define CM_BINARY_MAX_UNPACKED (128u * 1024u * 1024u)

/*
 * Marshal: encode a node to WhatsApp's binary XML. The output starts with a
 * 0x00 byte (the "not compressed" flag), exactly like whatsmeow's Marshal.
 * *out is malloc()ed; release with free().
 */
cm_err cm_binary_marshal(const cm_node *n, uint8_t **out, size_t *out_len);

/*
 * Unmarshal: decode binary XML (WITHOUT the leading flag byte, i.e. the
 * output of cm_binary_unpack) into `out`, which must be initialised. On
 * failure `out` is left empty. Fails with CM_ERR_TRAILING_DATA if bytes remain.
 *
 * Deviation from whatsmeow: Go strings may contain NUL bytes, C strings cannot,
 * so strings with embedded NULs are rejected with CM_ERR_INVALID_TOKEN.
 */
cm_err cm_binary_unmarshal(const uint8_t *data, size_t len, cm_node *out);

/*
 * Unpack: strip the leading flag byte, zlib-inflating the rest when bit 1
 * (value 2) is set. *out is malloc()ed; release with free().
 */
cm_err cm_binary_unpack(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_BINARY_H */
