/* See include/common.h for license and attribution. */
#ifndef CMEOW_CLIENT_H
#define CMEOW_CLIENT_H

#include "binary.h"
#include "conn.h"
#include "node.h"
#include "store.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Port of whatsmeow.Client for a single-threaded, poll-driven program.
 *
 * Usage: create a client around a device, set an event callback, connect, then
 * call cm_client_run() (or cm_client_run_once() from your own loop). All
 * callbacks and all blocking helpers run on the thread that calls run.
 *
 * Blocking helpers (cm_client_iq, cm_client_send_text, ...) wait for the
 * server's reply by pumping the socket; unrelated nodes that arrive meanwhile
 * are queued and handled afterwards, so they are safe to call from event
 * callbacks.
 */

typedef enum cm_event_type {
    CM_EVT_CONNECTED,          /* logged in and prekeys uploaded */
    CM_EVT_DISCONNECTED,       /* socket closed (err says why) */
    CM_EVT_QR,                 /* qr: a pairing code to render */
    CM_EVT_PAIR_SUCCESS,       /* jid, lid, platform, business_name */
    CM_EVT_PAIR_ERROR,         /* err */
    CM_EVT_LOGGED_OUT,         /* reason */
    CM_EVT_STREAM_ERROR,       /* reason (code) */
    CM_EVT_MESSAGE,            /* decrypted message, see fields */
    CM_EVT_UNDECRYPTABLE,      /* message could not be decrypted (err) */
    CM_EVT_KEEPALIVE_TIMEOUT,
    CM_EVT_QR_TIMEOUT          /* every QR code of this pairing session expired; reconnect for new ones */
} cm_event_type;

typedef struct cm_event {
    cm_event_type type;
    cm_err err;
    const char *reason;
    const char *qr;
    int qr_timeout_ms;          /* CM_EVT_QR: how long this code stays valid (60 s first, then 20 s) */
    const cm_jid *jid;
    const cm_jid *lid;
    const char *platform;
    const char *business_name;
    /* CM_EVT_MESSAGE / CM_EVT_UNDECRYPTABLE */
    const cm_jid *chat;
    const cm_jid *sender;
    const char *id;
    int64_t timestamp;
    const char *push_name;
    int is_from_me;
    int is_group;
    const char *text;           /* conversation / extendedTextMessage text, or NULL */
    const uint8_t *message;     /* serialized waE2E.Message */
    size_t message_len;
} cm_event;

typedef void (*cm_event_cb)(void *user, const cm_event *evt);

/*
 * Extension events: modules beyond the core (groups, appstate, user, media, ...)
 * report through this second callback. `kind` ranges are reserved per module
 * (see CM_EXT_* in the module headers); `data` points to a module-defined
 * struct valid only during the call.
 */
typedef void (*cm_ext_cb)(void *user, int kind, const void *data);

typedef struct cm_client cm_client;

typedef struct cm_client_opts {
    const char *ca_file;     /* PEM bundle for TLS verification (NULL = OpenSSL default paths) */
    const char *host;        /* default web.whatsapp.com */
    const char *port;        /* default 443 */
    int plain_tcp;           /* testing only: skip TLS */
    const uint8_t *root_pub; /* testing only: certificate root override */
    int timeout_ms;          /* connect / handshake step timeout (default 20000) */
    cm_io *connect_io;       /* testing only: use this transport for the next connect */
} cm_client_opts;

/* The client takes no ownership of dev. */
cm_client *cm_client_new(cm_device *dev, const cm_client_opts *opts);
void cm_client_free(cm_client *c);
void cm_client_set_event_cb(cm_client *c, cm_event_cb cb, void *user);
void cm_client_set_ext_cb(cm_client *c, cm_ext_cb cb, void *user);
/* Called whenever the device changed and should be persisted (pairing, prekeys, sessions). */
void cm_client_set_save_path(cm_client *c, const char *path);

cm_err cm_client_connect(cm_client *c);
void cm_client_disconnect(cm_client *c);
int cm_client_is_connected(const cm_client *c);
int cm_client_is_logged_in(const cm_client *c);

/* One iteration: socket I/O for up to timeout_ms, queued handlers, timers.
 * Returns CM_ERR_CLOSED once the connection is gone. */
cm_err cm_client_run_once(cm_client *c, int timeout_ms);
cm_err cm_client_run(cm_client *c); /* until disconnected */

/* Send a node (marshalled and encrypted). */
cm_err cm_client_send_node(cm_client *c, const cm_node *n);

/*
 * Info query: wraps content (may be NULL; ownership of children is taken) into
 * <iq id xmlns type to> and waits for the reply. On CM_OK *resp is the
 * <iq type="result"> node (caller frees with cm_node_free + free). An error
 * reply gives CM_ERR_PROTO and (if resp != NULL) the error node.
 */
cm_err cm_client_iq(cm_client *c, const char *xmlns, const char *type, const char *to,
                    cm_node *content, int timeout_ms, cm_node **resp);

/* Request IDs are "<prefix><counter>"; returns malloc()ed. */
char *cm_client_new_id(cm_client *c);

/* Sends <iq xmlns=passive type=set><active/></iq>. */
cm_err cm_client_set_passive(cm_client *c, int passive);

/* Send a plain text message to a user JID (1:1 chats only; see README). */
cm_err cm_client_send_text(cm_client *c, const cm_jid *to, const char *text, char **msg_id);

/* Send a read/delivery style receipt-free presence: available / unavailable. */
cm_err cm_client_send_presence(cm_client *c, int available);

/* QR code text for a pair-device ref (store.Device must be unpaired). */
cm_err cm_client_make_qr(const cm_client *c, const char *ref, char **out);

cm_device *cm_client_device(cm_client *c);

#ifdef __cplusplus
}
#endif
#endif
