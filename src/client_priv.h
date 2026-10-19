/* Internal to cmeow's client implementation. */
#ifndef CMEOW_CLIENT_PRIV_H
#define CMEOW_CLIENT_PRIV_H

#include "client.h"

#include <curve.h>
#include <group_cipher.h>
#include <group_session_builder.h>
#include <protocol.h>
#include <session_builder.h>
#include <session_cipher.h>
#include <session_pre_key.h>

struct cmi_waiter {
    char *id;
    cm_node *resp; /* heap node when done */
    int done;
    cm_err err;
};

struct cm_client {
    cm_device *dev;
    cm_client_opts opts;
    char *host, *port, *save_path, *ca_file, *tmp_dir;
    cm_conn *conn;
    cm_event_cb cb;
    void *ud;
    cm_ext_cb ext_cb;
    void *ext_ud;

    char *id_prefix;
    uint64_t id_counter;

    struct cmi_waiter *waiters;
    size_t nwaiters, capwaiters;

    cm_node *queue;
    size_t qn, qcap;

    int logged_in;
    int reconnect;       /* reconnect after the current iteration (515 stream error) */
    int expect_close;
    int64_t server_offset; /* server time - local time, seconds */

    int64_t next_keepalive_ms;
    int64_t keepalive_deadline_ms;
    char *keepalive_id;
    int keepalive_errors;
    int64_t last_keepalive_ok_ms;

    /* QR codes still to be shown (whatsmeow qrchan timing: first 60 s, others 20 s each) */
    char **qr_pending;
    size_t nqr_pending, qr_pos;
    int64_t next_qr_ms;

    /* per-module private state, owned/freed by the module (see cmi_*_free) */
    void *mod_messaging, *mod_media, *mod_appstate, *mod_user;
};

int64_t cmi_now_ms(void);
void cmi_emit(cm_client *c, const cm_event *e);
void cmi_save(cm_client *c);

/* node helpers */
cm_err cmi_node(cm_node *n, const char *tag); /* init + set tag */
const char *cmi_attr(const cm_node *n, const char *key);                  /* string attr or NULL */
cm_err cmi_attr_jid(const cm_node *n, const char *key, cm_jid *out);      /* out must be init; CM_ERR_INVALID_TYPE if absent */
const uint8_t *cmi_bytes(const cm_node *n, size_t *len);                  /* content bytes or NULL */
cm_err cmi_node_jid_attr(cm_node *n, const char *key, const cm_jid *j);

/* extension events, see cm_ext_cb. Kind ranges: messaging 100-199, appstate 200-299,
 * user/notification 300-399, media 400-499, groups 500-599, newsletter 600-699. */
void cmi_emit_ext(cm_client *c, int kind, const void *data);

/* Dispatch hook for nodes the core does not handle itself (src/dispatch_ext.c). Returns 1 if handled. */
int cmi_ext_dispatch(cm_client *c, const cm_node *n);

/* Cross-module entry points (each is implemented by exactly one module; stubs exist until then). */
/* messaging.c: <receipt> nodes (delivery/read/retry) */
void cmi_messaging_handle_receipt(cm_client *c, const cm_node *n);
/* groups.c: w:gp2 group notifications; called by the notification handler */
void cmi_groups_handle_notification(cm_client *c, const cm_node *n);
/* appstate.c: server_sync notification / key-share message from the primary device */
void cmi_appstate_server_sync(cm_client *c, const cm_node *sync_child);
void cmi_appstate_on_key_share(cm_client *c, const uint8_t *protocol_message, size_t len);
/* appstate.c: any decoded waE2E.ProtocolMessage (key share, snapshot recovery response); pm is a
 * WAWebProtobufsE2E__ProtocolMessage* */
void cmi_appstate_on_protocol_message(cm_client *c, const void *pm);
/* user.c: notification / presence / chatstate / ib / call dispatch */
void cmi_user_handle_node(cm_client *c, const cm_node *n);

/* module teardown, called from cm_client_free; each frees its own c->mod_* */
void cmi_messaging_free(cm_client *c);
void cmi_media_free(cm_client *c);
void cmi_appstate_free(cm_client *c);
void cmi_user_free(cm_client *c);
/* called after every successful login (CONNECTED); modules may send iqs here */
void cmi_messaging_on_connected(cm_client *c);
void cmi_appstate_on_connected(cm_client *c);
void cmi_user_on_connected(cm_client *c);

/* message.c */
void cmi_handle_message(cm_client *c, const cm_node *n);
void cmi_ack(cm_client *c, const cm_node *n);

/* like cm_client_iq but the children of container become the iq children */
cm_err cm_client_iq_multi(cm_client *c, const char *xmlns, const char *type, const char *to,
                          cm_node *container, int timeout_ms, cm_node **resp);
cm_err cmi_send_wait(cm_client *c, const cm_node *n, const char *id, int timeout_ms, cm_node **resp);
cm_err cmi_build_sessions(cm_client *c, const cm_jid *jids, size_t n);

/* lid.c: LID <-> phone-number mapping and session migration (PN sessions move to the LID address) */
void cmi_lid_learn(cm_client *c, const char *pn_user, const char *lid_user);
void cmi_lid_learn_attrs(cm_client *c, const cm_node *n); /* sender_pn/sender_lid/participant_*... */
void cmi_lid_learn_jids(cm_client *c, const cm_jid *a, const cm_jid *b); /* one pn, one lid, any order */
/* If pn is a PN JID with a known LID, replaces *out (must be init) by the LID JID (same device); returns 1. */
int cmi_lid_for_pn(cm_client *c, const cm_jid *pn, cm_jid *out);

/* history.c: a decoded waE2E.HistorySyncNotification* (downloads, inflates, applies, emits CM_EXT_HISTORY_SYNC) */
void cmi_history_on_notification(cm_client *c, const void *notif, const char *carrier_id);

/* tctoken.c: trusted-contact privacy tokens */
void cmi_tctoken_notification(cm_client *c, const cm_node *n);
const uint8_t *cmi_tctoken_for(cm_client *c, const cm_jid *jid, size_t *len); /* borrowed, or NULL */
void cmi_tctoken_issue(cm_client *c, const cm_jid *jid);

/* paircode.c (state lives in c->mod_user) */
void cmi_paircode_free(cm_client *c);
void cmi_paircode_notification(cm_client *c, const cm_node *n);

/* prekeys.c */
cm_err cmi_upload_prekeys_if_needed(cm_client *c);

#endif
