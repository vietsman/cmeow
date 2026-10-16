/* See include/common.h for license and attribution. */
#ifndef CMEOW_WS_H
#define CMEOW_WS_H

#include "common.h"
#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal RFC 6455 client on top of wslay (framing) and a cm_io transport.
 * Replaces gorilla/coder websocket usage in whatsmeow's socket package.
 * Single-threaded: all progress happens inside cm_ws_pump().
 */
typedef struct cm_ws cm_ws;

/* Called for every complete binary message. Returning an error stops the pump. */
typedef cm_err (*cm_ws_msg_cb)(void *user, const uint8_t *data, size_t len);

/* Sec-WebSocket-Accept value for a client key (out is NUL terminated, 29 bytes). */
cm_err cm_ws_accept_key(const char *client_key, char out[29]);

/*
 * Performs the HTTP upgrade over io. On success takes ownership of io.
 * On failure io is left untouched for the caller to close.
 * origin may be NULL.
 */
cm_err cm_ws_connect(cm_ws **out, cm_io *io, const char *host, const char *path,
                     const char *origin, int timeout_ms);

/* Queue a binary message (copied). Flushed by cm_ws_pump(). */
cm_err cm_ws_send(cm_ws *ws, const uint8_t *data, size_t len);

/*
 * Flush queued output, wait up to timeout_ms for input, deliver messages.
 * CM_OK: something happened; CM_ERR_TIMEOUT: nothing happened;
 * CM_ERR_CLOSED: peer closed; CM_ERR_IO: transport/protocol failure;
 * otherwise the error returned by the callback.
 */
cm_err cm_ws_pump(cm_ws *ws, int timeout_ms, cm_ws_msg_cb cb, void *user);

/* Block (up to timeout_ms per wait) until all queued output is written. */
cm_err cm_ws_flush(cm_ws *ws, int timeout_ms);

/* Start a clean close (sends a close frame; keep pumping to finish). */
void cm_ws_close(cm_ws *ws);

/* Releases everything, including the transport. */
void cm_ws_free(cm_ws *ws);

#ifdef __cplusplus
}
#endif
#endif
