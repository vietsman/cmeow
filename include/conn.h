/* See include/common.h for license and attribution. */
#ifndef CMEOW_CONN_H
#define CMEOW_CONN_H

#include "handshake.h"
#include "net.h"
#include "noise.h"
#include "ws.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Port of whatsmeow's FrameSocket + NoiseSocket + Client.doHandshake glue:
 * websocket -> 3-byte length frames -> Noise transport encryption.
 * One poll-driven object instead of goroutines.
 */
typedef struct cm_conn cm_conn;

/* Called for each decrypted frame (binary XML, still packed). */
typedef cm_err (*cm_conn_frame_cb)(void *user, const uint8_t *frame, size_t len);

typedef struct cm_conn_params {
    const char *host;      /* default "web.whatsapp.com" */
    const char *path;      /* default "/ws/chat" */
    const char *origin;    /* default CM_WA_ORIGIN */
    const cm_keypair *noise_key;
    const uint8_t *client_payload; /* marshalled waWa6.ClientPayload */
    size_t client_payload_len;
    int64_t now_unix;
    const uint8_t *root_pub; /* NULL = real WhatsApp certificate root */
    int timeout_ms;          /* per I/O wait during the handshake */
} cm_conn_params;

/*
 * Runs the websocket upgrade and the Noise XX handshake over io (taking
 * ownership on success). err may be NULL.
 */
cm_err cm_conn_open(cm_conn **out, cm_io *io, const cm_conn_params *p, cm_hs_error *err);

/* Encrypt, frame and queue plaintext (e.g. a packed binary node). */
cm_err cm_conn_send(cm_conn *c, const uint8_t *data, size_t len);

/* See cm_ws_pump. Decrypted frames are delivered through cb. */
cm_err cm_conn_pump(cm_conn *c, int timeout_ms, cm_conn_frame_cb cb, void *user);

void cm_conn_close(cm_conn *c);
void cm_conn_free(cm_conn *c);

#ifdef __cplusplus
}
#endif
#endif
