/* See include/common.h for license and attribution. */
#include "common.h"

#include <stdlib.h>
#include <string.h>

const char *cm_strerror(cm_err e)
{
    switch (e) {
    case CM_OK:                  return "ok";
    case CM_ERR_NOMEM:           return "out of memory";
    case CM_ERR_EOF:             return "unexpected end of data";
    case CM_ERR_INVALID_TOKEN:   return "invalid token";
    case CM_ERR_INVALID_JID:     return "invalid JID";
    case CM_ERR_INVALID_JID_TYPE:return "invalid JID type";
    case CM_ERR_NON_STRING_KEY:  return "attribute key is not a string";
    case CM_ERR_INVALID_NODE:    return "invalid node";
    case CM_ERR_INVALID_TYPE:    return "invalid value type";
    case CM_ERR_TOO_LARGE:       return "length too large";
    case CM_ERR_TRAILING_DATA:   return "leftover bytes after decoding";
    case CM_ERR_DEPTH:           return "nesting too deep";
    case CM_ERR_ZLIB:            return "zlib error";
    case CM_ERR_ARG:             return "invalid argument";
    case CM_ERR_CRYPTO:          return "crypto operation failed";
    case CM_ERR_AUTH:            return "authentication failed";
    case CM_ERR_PROTO:           return "protocol error";
    case CM_ERR_IO:              return "I/O error";
    case CM_ERR_TIMEOUT:         return "timed out";
    case CM_ERR_CLOSED:          return "connection closed";
    }
    return "unknown error";
}

void *cm_memdup(const void *p, size_t n)
{
    void *r = malloc(n ? n : 1);
    if (r != NULL && n != 0)
        memcpy(r, p, n);
    return r;
}

char *cm_strndup(const char *s, size_t n)
{
    char *r = (char *)malloc(n + 1);
    if (r == NULL)
        return NULL;
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

char *cm_strdup(const char *s)
{
    return cm_strndup(s, strlen(s));
}
