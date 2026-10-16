/*
 * cmeow - a C99 port of whatsmeow (https://github.com/tulir/whatsmeow)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Original Go implementation: Copyright (c) Tulir Asokan and contributors.
 */
#ifndef CMEOW_COMMON_H
#define CMEOW_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cm_err {
    CM_OK = 0,
    CM_ERR_NOMEM,
    CM_ERR_EOF,              /* ran out of input */
    CM_ERR_INVALID_TOKEN,    /* unknown / malformed binary XML token */
    CM_ERR_INVALID_JID,      /* JID string could not be parsed */
    CM_ERR_INVALID_JID_TYPE, /* JID tag with unexpected contents */
    CM_ERR_NON_STRING_KEY,   /* attribute key was not a string */
    CM_ERR_INVALID_NODE,     /* empty / malformed node */
    CM_ERR_INVALID_TYPE,     /* value type not valid in this position */
    CM_ERR_TOO_LARGE,        /* length exceeds protocol or safety limit */
    CM_ERR_TRAILING_DATA,    /* bytes left over after decoding */
    CM_ERR_DEPTH,            /* nesting too deep */
    CM_ERR_ZLIB,             /* zlib decompression failed */
    CM_ERR_ARG,              /* invalid argument */
    CM_ERR_CRYPTO,           /* crypto primitive failed (not an auth failure) */
    CM_ERR_AUTH,             /* AEAD tag / MAC / signature verification failed */
    CM_ERR_PROTO,            /* malformed or unexpected protocol message */
    CM_ERR_IO,               /* socket / transport error */
    CM_ERR_TIMEOUT,          /* operation timed out */
    CM_ERR_CLOSED            /* connection closed */
} cm_err;

/* Human readable, static string for an error code. */
const char *cm_strerror(cm_err e);

/*
 * strdup/strndup/memdup replacements. strdup is POSIX, not C99, so we
 * carry our own. All return NULL on allocation failure.
 */
char *cm_strdup(const char *s);
char *cm_strndup(const char *s, size_t n);
void *cm_memdup(const void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_COMMON_H */
