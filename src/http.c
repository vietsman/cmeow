/* See include/common.h for license and attribution. */
#define _POSIX_C_SOURCE 200112L
#include "http.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HDR_MAX 16384

typedef struct hio {
    cm_io io;
    int timeout_ms;
    int timed_out;
} hio;

static long h_read(hio *h, uint8_t *b, size_t n)
{
    for (;;) {
        long r = h->io.ops->read(h->io.ctx, b, n);
        int w;

        if (r != CM_IO_AGAIN)
            return r;
        if (h->io.ops->pending && h->io.ops->pending(h->io.ctx))
            continue;
        w = cm_io_wait(&h->io, 0, h->timeout_ms);
        if (w == 0)
            h->timed_out = 1;
        if (w <= 0)
            return CM_IO_FAIL;
    }
}

static cm_err h_write_all(hio *h, const uint8_t *b, size_t n)
{
    while (n > 0) {
        long r = h->io.ops->write(h->io.ctx, b, n);

        if (r == CM_IO_AGAIN) {
            int w = cm_io_wait(&h->io, 1, h->timeout_ms);

            if (w == 0) {
                h->timed_out = 1;
                return CM_ERR_TIMEOUT;
            }
            if (w < 0)
                return CM_ERR_IO;
            continue;
        }
        if (r <= 0)
            return CM_ERR_IO;
        b += r;
        n -= (size_t)r;
    }
    return CM_OK;
}

char *cm_url_escape(const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t i, o = 0, n = strlen(s);
    char *r = (char *)malloc(n * 3 + 1);

    if (r == NULL)
        return NULL;
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];

        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            r[o++] = (char)ch;
        } else {
            r[o++] = '%';
            r[o++] = hex[ch >> 4];
            r[o++] = hex[ch & 15];
        }
    }
    r[o] = 0;
    return r;
}

static int has_crlf(const char *s)
{
    return strchr(s, '\r') != NULL || strchr(s, '\n') != NULL;
}

typedef struct purl {
    int tls;
    char host[256], port[8];
    const char *path; /* includes query, starts with '/' */
} purl;

static cm_err parse_url(const char *u, purl *p)
{
    const char *h, *e, *colon;
    size_t hl;

    if (strncmp(u, "https://", 8) == 0) {
        p->tls = 1;
        h = u + 8;
    } else if (strncmp(u, "http://", 7) == 0) {
        p->tls = 0;
        h = u + 7;
    } else {
        return CM_ERR_ARG;
    }
    e = h + strcspn(h, "/?#");
    colon = memchr(h, ':', (size_t)(e - h));
    hl = (size_t)((colon ? colon : e) - h);
    if (hl == 0 || hl >= sizeof(p->host))
        return CM_ERR_ARG;
    memcpy(p->host, h, hl);
    p->host[hl] = 0;
    if (colon) {
        size_t pl = (size_t)(e - colon - 1);

        if (pl == 0 || pl >= sizeof(p->port))
            return CM_ERR_ARG;
        memcpy(p->port, colon + 1, pl);
        p->port[pl] = 0;
    } else {
        strcpy(p->port, p->tls ? "443" : "80");
    }
    p->path = (*e == '/') ? e : (*e == '?' ? e : "/");
    if (*e == '?') /* "host?x" -> "/?x" handled by caller building the line */
        p->path = e;
    return CM_OK;
}

/* strcasecmp-free header compare */
static int hdr_is(const char *line, const char *name)
{
    size_t n = strlen(name);
    size_t i;

    for (i = 0; i < n; i++)
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i]))
            return 0;
    return line[n] == ':';
}

cm_err cm_http_do(const cm_http_req *req, const cm_http_opts *opts, cm_http_resp *resp,
                  cm_http_body_cb on_body, void *ud)
{
    purl u;
    hio h;
    cm_err e;
    char *head = NULL;
    size_t hl = 0, hcap = 0, i;
    uint8_t buf[8192];
    int chunked = 0;
    int64_t clen = -1, got = 0;
    long r;
    size_t hdr_end = 0, have = 0;
    char *p;
    int to = opts && opts->timeout_ms > 0 ? opts->timeout_ms : 30000;

    memset(&h, 0, sizeof(h));
    memset(resp, 0, sizeof(*resp));
    resp->content_length = -1;
    if (req->method == NULL || req->url == NULL || has_crlf(req->method) || has_crlf(req->url) ||
        strchr(req->url, ' ') != NULL)
        return CM_ERR_ARG;
    for (i = 0; i < req->nheaders; i++)
        if (has_crlf(req->headers[i]))
            return CM_ERR_ARG;
    if ((e = parse_url(req->url, &u)) != CM_OK)
        return e;
    h.timeout_ms = to;
    e = u.tls ? cm_io_tls_connect(&h.io, u.host, u.port, opts ? opts->ca_file : NULL, to)
              : cm_io_tcp_connect(&h.io, u.host, u.port, to);
    if (e != CM_OK)
        return e;

    /* request head */
    hcap = 512 + strlen(req->url) + 64;
    for (i = 0; i < req->nheaders; i++)
        hcap += strlen(req->headers[i]) + 2;
    head = (char *)malloc(hcap);
    if (head == NULL) {
        cm_io_close(&h.io);
        return CM_ERR_NOMEM;
    }
    hl = (size_t)sprintf(head, "%s %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept: */*\r\n", req->method,
                         u.path[0] == '?' ? "/" : "", u.path, u.host);
    if (req->body_len > 0 || strcmp(req->method, "POST") == 0)
        hl += (size_t)sprintf(head + hl, "Content-Length: %llu\r\n", (unsigned long long)req->body_len);
    for (i = 0; i < req->nheaders; i++)
        hl += (size_t)sprintf(head + hl, "%s\r\n", req->headers[i]);
    memcpy(head + hl, "\r\n", 2);
    hl += 2;
    e = h_write_all(&h, (const uint8_t *)head, hl);
    free(head);
    if (e != CM_OK)
        goto out;
    if (req->body != NULL && req->body_len > 0) {
        e = h_write_all(&h, req->body, (size_t)req->body_len);
    } else if (req->body_read != NULL && req->body_len > 0) {
        uint64_t sent = 0;

        while (sent < req->body_len && e == CM_OK) {
            size_t want = req->body_len - sent > sizeof(buf) ? sizeof(buf) : (size_t)(req->body_len - sent);
            long n = req->body_read(req->body_ud, buf, want);

            if (n <= 0) {
                e = CM_ERR_IO;
                break;
            }
            e = h_write_all(&h, buf, (size_t)n);
            sent += (uint64_t)n;
        }
    }
    if (e != CM_OK)
        goto out;

    /* response head */
    {
        char *hb = (char *)malloc(HDR_MAX + sizeof(buf));
        size_t pos;

        if (hb == NULL) {
            e = CM_ERR_NOMEM;
            goto out;
        }
        have = 0;
        for (;;) {
            char *q;

            if (have >= HDR_MAX) {
                free(hb);
                e = CM_ERR_PROTO;
                goto out;
            }
            r = h_read(&h, (uint8_t *)hb + have, HDR_MAX - have > sizeof(buf) ? sizeof(buf) : HDR_MAX - have);
            if (r <= 0) {
                free(hb);
                e = h.timed_out ? CM_ERR_TIMEOUT : CM_ERR_IO;
                goto out;
            }
            have += (size_t)r;
            q = NULL;
            for (pos = 3; pos < have; pos++)
                if (hb[pos] == '\n' && hb[pos - 1] == '\r' && hb[pos - 2] == '\n' && hb[pos - 3] == '\r') {
                    q = hb + pos + 1;
                    break;
                }
            if (q) {
                hdr_end = (size_t)(q - hb);
                break;
            }
        }
        hb[hdr_end - 2] = 0; /* terminate before the blank line */
        if (strncmp(hb, "HTTP/1.", 7) != 0 || strlen(hb) < 12) {
            free(hb);
            e = CM_ERR_PROTO;
            goto out;
        }
        resp->status = atoi(hb + 9);
        p = strstr(hb, "\r\n");
        while (p) {
            char *nl;

            p += 2;
            if (*p == 0)
                break;
            nl = strstr(p, "\r\n");
            if (nl)
                *nl = 0;
            if (hdr_is(p, "Content-Length")) {
                clen = (int64_t)strtoll(p + 15, NULL, 10);
            } else if (hdr_is(p, "Transfer-Encoding")) {
                if (strstr(p + 18, "chunked") != NULL)
                    chunked = 1;
            } else if (hdr_is(p, "Retry-After")) {
                resp->retry_after = atoi(p + 12);
            }
            p = nl;
        }
        resp->content_length = chunked ? -1 : clen;
        /* leftover bytes after the head */
        memcpy(buf, hb + hdr_end, have - hdr_end > sizeof(buf) ? sizeof(buf) : have - hdr_end);
        have -= hdr_end;
        if (have > sizeof(buf)) /* cannot happen: reads were capped at sizeof(buf) */
            have = sizeof(buf);
        free(hb);
    }
    if (strcmp(req->method, "HEAD") == 0 || resp->status == 204 || resp->status == 304 || resp->status / 100 == 1)
        goto out;

    if (!chunked) {
        /* identity body: until content-length or close */
        for (;;) {
            size_t n = have;

            if (n == 0) {
                if (clen >= 0 && got >= clen)
                    break;
                r = h_read(&h, buf, sizeof(buf));
                if (r == 0)
                    break;
                if (r < 0) {
                    e = h.timed_out ? CM_ERR_TIMEOUT : CM_ERR_IO;
                    goto out;
                }
                n = (size_t)r;
            }
            if (clen >= 0 && got + (int64_t)n > clen)
                n = (size_t)(clen - got);
            got += (int64_t)n;
            if (on_body && n > 0 && on_body(ud, resp->status, buf, n) != 0) {
                e = CM_ERR_IO;
                goto out;
            }
            have = 0;
            if (clen >= 0 && got >= clen)
                break;
        }
        if (clen >= 0 && got < clen)
            e = CM_ERR_IO; /* truncated */
    } else {
        /* chunked: state machine over the byte stream */
        enum { SZ, EXT, SZLF, DATA, DATACR, DATALF, TRAIL } st = SZ;
        uint64_t csz = 0;
        int digits = 0, done = 0;

        for (;;) {
            size_t k = 0, n = have;

            if (n == 0) {
                r = h_read(&h, buf, sizeof(buf));
                if (r <= 0) {
                    e = r == 0 ? CM_ERR_IO : (h.timed_out ? CM_ERR_TIMEOUT : CM_ERR_IO);
                    goto out;
                }
                n = (size_t)r;
            }
            while (k < n && !done) {
                uint8_t ch = buf[k];

                switch (st) {
                case SZ:
                    if (isxdigit(ch)) {
                        csz = csz * 16 + (uint64_t)(isdigit(ch) ? ch - '0' : (tolower(ch) - 'a' + 10));
                        digits++;
                        if (csz > ((uint64_t)1 << 40)) {
                            e = CM_ERR_PROTO;
                            goto out;
                        }
                        k++;
                    } else if (digits == 0) {
                        e = CM_ERR_PROTO;
                        goto out;
                    } else {
                        st = ch == '\r' ? SZLF : EXT;
                        if (ch == '\r')
                            k++;
                    }
                    break;
                case EXT:
                    if (ch == '\r')
                        st = SZLF;
                    k++;
                    break;
                case SZLF:
                    if (ch != '\n') {
                        e = CM_ERR_PROTO;
                        goto out;
                    }
                    k++;
                    if (csz == 0)
                        st = TRAIL;
                    else
                        st = DATA;
                    break;
                case DATA: {
                    size_t take = n - k > csz ? (size_t)csz : n - k;

                    if (on_body && on_body(ud, resp->status, buf + k, take) != 0) {
                        e = CM_ERR_IO;
                        goto out;
                    }
                    k += take;
                    csz -= take;
                    if (csz == 0)
                        st = DATACR;
                    break;
                }
                case DATACR:
                    if (ch != '\r') {
                        e = CM_ERR_PROTO;
                        goto out;
                    }
                    k++;
                    st = DATALF;
                    break;
                case DATALF:
                    if (ch != '\n') {
                        e = CM_ERR_PROTO;
                        goto out;
                    }
                    k++;
                    st = SZ;
                    csz = 0;
                    digits = 0;
                    break;
                case TRAIL:
                    /* ignore trailers; the last chunk is complete once we reach here */
                    done = 1;
                    break;
                }
            }
            have = 0;
            if (done || st == TRAIL)
                break;
        }
    }
out:
    cm_io_close(&h.io);
    return e;
}
