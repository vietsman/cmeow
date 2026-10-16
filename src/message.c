/* See include/common.h for license and attribution.
 * Port (subset) of whatsmeow message.go, receipt.go, send.go: 1:1 and group receive,
 * 1:1 text send. */
#define _POSIX_C_SOURCE 200112L
#include "messaging_priv.h"
#include "messaging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "waE2E/WAWebProtobufsE2E.pb-c.h"

typedef WAWebProtobufsE2E__Message E2EMsg;

/* ---------------------------------------------------------------- acks */
static void add_attr_copy(cm_node *dst, const cm_node *src, const char *from_key, const char *to_key)
{
    const cm_value *v = cm_node_get_attr(src, from_key);
    cm_value cp;

    if (v == NULL)
        return;
    cm_value_init(&cp);
    if (cm_value_clone(&cp, v) != CM_OK)
        return;
    if (cm_node_set_attr_value(dst, to_key, &cp) != CM_OK)
        cm_value_free(&cp);
}

/* ack for receipts / notifications (class = tag) */
void cmi_ack(cm_client *c, const cm_node *n)
{
    cm_node a;

    if (cmi_node(&a, "ack") != CM_OK)
        return;
    cm_node_set_attr_str(&a, "class", n->tag);
    add_attr_copy(&a, n, "id", "id");
    add_attr_copy(&a, n, "from", "to");
    add_attr_copy(&a, n, "participant", "participant");
    add_attr_copy(&a, n, "recipient", "recipient");
    add_attr_copy(&a, n, "type", "type");
    cm_client_send_node(c, &a);
    cm_node_free(&a);
}

static void send_receipt(cm_client *c, const cm_node *n, int from_me)
{
    cm_node r;

    if (cmi_node(&r, "receipt") != CM_OK)
        return;
    add_attr_copy(&r, n, "id", "id");
    add_attr_copy(&r, n, "from", "to");
    add_attr_copy(&r, n, "recipient", "recipient");
    add_attr_copy(&r, n, "participant", "participant");
    if (from_me)
        cm_node_set_attr_str(&r, "type", "sender");
    cm_client_send_node(c, &r);
    cm_node_free(&r);
}

/* ---------------------------------------------------------------- decrypt */
#define addr_of cmi_addr_of

static cm_err decrypt_dm(cm_client *c, const uint8_t *ct, size_t len, int prekey, const cm_jid *from,
                         uint8_t **out, size_t *out_len)
{
    signal_protocol_address a;
    char *name;
    session_cipher *sc = NULL;
    signal_buffer *pt = NULL;
    int r;
    cm_err e = CM_ERR_CRYPTO;

    addr_of(from, &name, &a);
    if (session_cipher_create(&sc, c->dev->sstore, &a, c->dev->sctx) < 0)
        goto out;
    if (prekey) {
        pre_key_signal_message *m = NULL;

        if (pre_key_signal_message_deserialize(&m, ct, len, c->dev->sctx) < 0)
            goto out;
        r = session_cipher_decrypt_pre_key_signal_message(sc, m, NULL, &pt);
        SIGNAL_UNREF(m);
    } else {
        signal_message *m = NULL;

        if (signal_message_deserialize(&m, ct, len, c->dev->sctx) < 0)
            goto out;
        r = session_cipher_decrypt_signal_message(sc, m, NULL, &pt);
        SIGNAL_UNREF(m);
    }
    if (r < 0) {
        e = r == SG_ERR_UNTRUSTED_IDENTITY ? CM_ERR_AUTH : CM_ERR_CRYPTO;
        goto out;
    }
    *out = (uint8_t *)cm_memdup(signal_buffer_data(pt), signal_buffer_len(pt));
    *out_len = signal_buffer_len(pt);
    e = *out ? CM_OK : CM_ERR_NOMEM;
out:
    if (pt) signal_buffer_free(pt);
    if (sc) session_cipher_free(sc);
    free(name);
    return e;
}

static void sk_name(signal_protocol_sender_key_name *k, const char *group, size_t gl,
                    signal_protocol_address *a)
{
    k->group_id = group;
    k->group_id_len = gl;
    k->sender = *a;
}

static cm_err decrypt_group(cm_client *c, const uint8_t *ct, size_t len, const cm_jid *sender,
                            const char *group, uint8_t **out, size_t *out_len)
{
    signal_protocol_address a;
    signal_protocol_sender_key_name kn;
    char *name;
    group_cipher *gc = NULL;
    sender_key_message *m = NULL;
    signal_buffer *pt = NULL;
    cm_err e = CM_ERR_CRYPTO;

    addr_of(sender, &name, &a);
    sk_name(&kn, group, strlen(group), &a);
    if (group_cipher_create(&gc, c->dev->sstore, &kn, c->dev->sctx) < 0 ||
        sender_key_message_deserialize(&m, ct, len, c->dev->sctx) < 0)
        goto out;
    if (group_cipher_decrypt(gc, m, NULL, &pt) < 0)
        goto out;
    *out = (uint8_t *)cm_memdup(signal_buffer_data(pt), signal_buffer_len(pt));
    *out_len = signal_buffer_len(pt);
    e = *out ? CM_OK : CM_ERR_NOMEM;
out:
    if (m) SIGNAL_UNREF(m);
    if (pt) signal_buffer_free(pt);
    if (gc) group_cipher_free(gc);
    free(name);
    return e;
}

static void process_skdm(cm_client *c, const cm_jid *sender, const char *group,
                         const uint8_t *data, size_t len)
{
    signal_protocol_address a;
    signal_protocol_sender_key_name kn;
    char *name;
    sender_key_distribution_message *m = NULL;
    group_session_builder *b = NULL;

    addr_of(sender, &name, &a);
    sk_name(&kn, group, strlen(group), &a);
    if (sender_key_distribution_message_deserialize(&m, data, len, c->dev->sctx) >= 0 &&
        group_session_builder_create(&b, c->dev->sstore, c->dev->sctx) >= 0)
        group_session_builder_process_session(b, &kn, m);
    if (m) SIGNAL_UNREF(m);
    if (b) group_session_builder_free(b);
    free(name);
}

static int unpad(const uint8_t *p, size_t *len, int version)
{
    if (version == 3)
        return 1;
    if (*len == 0 || p[*len - 1] == 0 || p[*len - 1] > *len)
        return 0;
    *len -= p[*len - 1];
    return 1;
}

static void deliver(cm_client *c, const cm_node *n, const cm_jid *chat, const cm_jid *sender,
                    int from_me, int is_group, const uint8_t *msg, size_t mlen)
{
    E2EMsg *m = waweb_protobufs_e2_e__message__unpack(NULL, mlen, msg);
    const char *text = NULL;
    cm_event ev;
    const char *t = cmi_attr(n, "t");
    const char *notify = cmi_attr(n, "notify");

    memset(&ev, 0, sizeof(ev));
    if (m != NULL) {
        E2EMsg *inner = m;

        if (m->devicesentmessage != NULL && m->devicesentmessage->message != NULL)
            inner = m->devicesentmessage->message;
        if (inner->conversation != NULL)
            text = inner->conversation;
        else if (inner->extendedtextmessage != NULL)
            text = inner->extendedtextmessage->text;
        if (inner->protocolmessage != NULL) {
            cmi_appstate_on_protocol_message(c, inner->protocolmessage);
            if (inner->protocolmessage->historysyncnotification != NULL && from_me)
                cmi_history_on_notification(c, inner->protocolmessage->historysyncnotification, cmi_attr(n, "id"));
            if (cmi_attr(n, "category") != NULL && strcmp(cmi_attr(n, "category"), "peer") == 0)
                cm_client_send_protocol_receipt(c, cmi_attr(n, "id"), "peer_msg");
        }
        if (m->senderkeydistributionmessage != NULL && m->senderkeydistributionmessage->groupid != NULL &&
            m->senderkeydistributionmessage->has_axolotlsenderkeydistributionmessage)
            process_skdm(c, sender, m->senderkeydistributionmessage->groupid,
                         m->senderkeydistributionmessage->axolotlsenderkeydistributionmessage.data,
                         m->senderkeydistributionmessage->axolotlsenderkeydistributionmessage.len);
    }
    ev.type = CM_EVT_MESSAGE;
    ev.chat = chat;
    ev.sender = sender;
    ev.id = cmi_attr(n, "id");
    ev.timestamp = t ? (int64_t)strtoll(t, NULL, 10) : 0;
    ev.push_name = notify;
    ev.is_from_me = from_me;
    ev.is_group = is_group;
    ev.text = text;
    ev.message = msg;
    ev.message_len = mlen;
    /* the skdm-only carrier messages have no user-visible content; still reported, text==NULL */
    cmi_emit(c, &ev);
    if (m)
        waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
}

void cmi_handle_message(cm_client *c, const cm_node *n)
{
    cm_jid from, participant, chat, sender, recipient;
    int is_group, from_me = 0, any = 0;
    size_t i;
    const char *own = c->dev->has_id ? c->dev->id.user : "";
    const char *own_lid = c->dev->lid.user ? c->dev->lid.user : "";
    cm_event ev;

    cm_jid_init(&from); cm_jid_init(&participant); cm_jid_init(&chat); cm_jid_init(&sender);
    cm_jid_init(&recipient);
    if (cmi_attr_jid(n, "from", &from) != CM_OK || cmi_attr(n, "id") == NULL) {
        memset(&ev, 0, sizeof(ev));
        ev.type = CM_EVT_UNDECRYPTABLE;
        ev.err = CM_ERR_PROTO;
        cmi_emit(c, &ev);
        goto out;
    }
    cmi_lid_learn_attrs(c, n);
    is_group = strcmp(from.server, CM_SERVER_GROUP) == 0 || strcmp(from.server, CM_SERVER_BROADCAST) == 0;
    cm_jid_copy(&chat, &from);
    if (is_group) {
        cmi_attr_jid(n, "participant", &participant);
        cm_jid_copy(&sender, &participant);
        from_me = participant.user && (strcmp(participant.user, own) == 0 || strcmp(participant.user, own_lid) == 0);
    } else {
        cm_jid_copy(&sender, &from);
        if (from.user && (strcmp(from.user, own) == 0 || (own_lid[0] && strcmp(from.user, own_lid) == 0))) {
            from_me = 1;
            if (cmi_attr_jid(n, "recipient", &recipient) == CM_OK) {
                cm_jid_free(&chat);
                cm_jid_init(&chat);
                cm_jid_copy(&chat, &recipient);
            }
        }
    }

    for (i = 0; i < cm_node_nchildren(n); i++) {
        const cm_node *enc = cm_node_child_at(n, i);
        const char *type, *v;
        const uint8_t *ct;
        size_t clen, plen = 0;
        uint8_t *pt = NULL;
        cm_err e = CM_ERR_PROTO;

        if (strcmp(enc->tag, "enc") != 0)
            continue;
        type = cmi_attr(enc, "type");
        v = cmi_attr(enc, "v");
        ct = cmi_bytes(enc, &clen);
        if (type == NULL || ct == NULL)
            continue;
        any = 1;
        if (strcmp(type, "pkmsg") == 0 || strcmp(type, "msg") == 0) {
            cm_jid dsender;

            cm_jid_init(&dsender);
            cm_jid_copy(&dsender, &sender);
            cmi_lid_for_pn(c, &sender, &dsender); /* sessions live under the LID address */
            e = decrypt_dm(c, ct, clen, type[0] == 'p', &dsender, &pt, &plen);
            cm_jid_free(&dsender);
        } else if (is_group && strcmp(type, "skmsg") == 0) {
            e = decrypt_group(c, ct, clen, &sender, chat.user ? chat.user : "", &pt, &plen);
        }
        else
            continue;
        if (e == CM_OK && !unpad(pt, &plen, v ? atoi(v) : 2))
            e = CM_ERR_PROTO;
        if (e != CM_OK) {
            memset(&ev, 0, sizeof(ev));
            ev.type = CM_EVT_UNDECRYPTABLE;
            ev.err = e;
            ev.chat = &chat;
            ev.sender = &sender;
            ev.id = cmi_attr(n, "id");
            cmi_emit(c, &ev);
            cmi_send_retry_receipt(c, n, e == CM_ERR_AUTH ? 0 : 0);
        } else {
            deliver(c, n, &chat, &sender, from_me, is_group, pt, plen);
        }
        free(pt);
    }
    (void)any;
    cmi_save(c); /* sessions / consumed prekeys changed */
    send_receipt(c, n, from_me);
out:
    cm_jid_free(&from); cm_jid_free(&participant); cm_jid_free(&chat); cm_jid_free(&sender);
    cm_jid_free(&recipient);
}

