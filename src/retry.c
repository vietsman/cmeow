/* See include/common.h for license and attribution. Port of whatsmeow retry.go (WhatsApp-protocol part). */
#define _POSIX_C_SOURCE 200112L
#include "messaging_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "waE2E/WAWebProtobufsE2E.pb-c.h"

typedef WAWebProtobufsE2E__Message E2EMsg;

static void key_child(cm_node *parent, const char *tag, uint32_t id, const uint8_t pub[32], const uint8_t *sig)
{
    cm_node k, a, v, s;
    uint8_t idb[3];

    idb[0] = (uint8_t)(id >> 16); idb[1] = (uint8_t)(id >> 8); idb[2] = (uint8_t)id;
    cmi_node(&k, tag);
    cmi_node(&a, "id");
    cm_node_set_content_bytes(&a, idb, 3);
    cm_node_add_child(&k, &a);
    cmi_node(&v, "value");
    cm_node_set_content_bytes(&v, pub, 32);
    cm_node_add_child(&k, &v);
    if (sig) {
        cmi_node(&s, "signature");
        cm_node_set_content_bytes(&s, sig, 64);
        cm_node_add_child(&k, &s);
    }
    cm_node_add_child(parent, &k);
}

/* Sent when a message could not be decrypted. */
void cmi_send_retry_receipt(cm_client *c, const cm_node *msg, int force_identity)
{
    const char *id = cmi_attr(msg, "id"), *t = cmi_attr(msg, "t");
    cm_node r, retry, reg;
    uint8_t rid[4];
    char cnt[16];
    int count = 1;
    const cm_node *first;

    if (id == NULL || cmi_attr(msg, "from") == NULL)
        return;
    /* a retry-response that still failed carries its own counter */
    first = cm_node_nchildren(msg) == 1 ? cm_node_child_at(msg, 0) : NULL;
    count = cmi_retry_count_inc(c, id);
    if (first && strcmp(first->tag, "enc") == 0 && count == 1) {
        const char *ec = cmi_attr(first, "count");

        if (ec && atoi(ec) > 0) {
            count = atoi(ec) + 1;
        }
    }
    if (count >= 5)
        return;
    if (cmi_node(&r, "receipt") != CM_OK)
        return;
    cmi_set_attr_copy(&r, msg, "id", "id");
    cmi_set_attr_copy(&r, msg, "from", "to");
    cmi_set_attr_copy(&r, msg, "participant", "participant");
    cmi_set_attr_copy(&r, msg, "recipient", "recipient");
    cm_node_set_attr_str(&r, "type", "retry");
    cmi_node(&retry, "retry");
    sprintf(cnt, "%d", count);
    cm_node_set_attr_str(&retry, "count", cnt);
    cm_node_set_attr_str(&retry, "id", id);
    cm_node_set_attr_str(&retry, "t", t ? t : "0");
    cm_node_set_attr_str(&retry, "v", "1");
    cm_node_add_child(&r, &retry);
    rid[0] = (uint8_t)(c->dev->registration_id >> 24); rid[1] = (uint8_t)(c->dev->registration_id >> 16);
    rid[2] = (uint8_t)(c->dev->registration_id >> 8); rid[3] = (uint8_t)c->dev->registration_id;
    cmi_node(&reg, "registration");
    cm_node_set_content_bytes(&reg, rid, 4);
    cm_node_add_child(&r, &reg);
    if ((count > 1 || force_identity) && c->dev->account != NULL) {
        cm_prekey *pks = NULL;
        uint32_t np = 0;

        if (cm_device_get_or_gen_prekeys(c->dev, 1, &pks, &np) == CM_OK && np > 0) {
            cm_node keys, ty, idn, di;
            uint8_t dj = 5;

            cmi_node(&keys, "keys");
            cmi_node(&ty, "type");
            cm_node_set_content_bytes(&ty, &dj, 1);
            cm_node_add_child(&keys, &ty);
            cmi_node(&idn, "identity");
            cm_node_set_content_bytes(&idn, c->dev->identity_key.pub, 32);
            cm_node_add_child(&keys, &idn);
            key_child(&keys, "key", pks[0].id, pks[0].key.pub, NULL);
            key_child(&keys, "skey", c->dev->signed_prekey.id, c->dev->signed_prekey.key.pub,
                      c->dev->signed_prekey.signature);
            cmi_node(&di, "device-identity");
            cm_node_set_content_bytes(&di, c->dev->account, c->dev->account_len);
            cm_node_add_child(&keys, &di);
            cm_node_add_child(&r, &keys);
            cmi_save(c);
        }
        free(pks);
    }
    cm_client_send_node(c, &r);
    cm_node_free(&r);
}

/* A peer asked us to re-send a message. */
void cmi_handle_retry_receipt(cm_client *c, const cm_node *n)
{
    const cm_node *rc = cm_node_child(n, "retry");
    const char *mid, *rt, *cnt, *edit_attr;
    cm_jid from, part, recipient, sender, chat;
    const uint8_t *orig;
    size_t olen = 0;
    E2EMsg *m = NULL;
    uint8_t *plain = NULL;
    size_t plen = 0;
    int is_group, from_me = 0, pk = 0, count;
    char key[160];
    const char *mediatype = "", *type;
    cm_node out, enc;
    const char *own = c->dev->has_id ? c->dev->id.user : "";
    cm_err e;

    cm_jid_init(&from); cm_jid_init(&part); cm_jid_init(&recipient); cm_jid_init(&sender); cm_jid_init(&chat);
    if (rc == NULL || cmi_attr_jid(n, "from", &from) != CM_OK)
        goto done;
    mid = cmi_attr(rc, "id");
    rt = cmi_attr(rc, "t");
    cnt = cmi_attr(rc, "count");
    if (mid == NULL)
        goto done;
    count = cnt ? atoi(cnt) : 1;
    orig = cmi_find_sent(c, mid, &olen);
    if (orig == NULL)
        goto done; /* no longer cached */
    is_group = strcmp(from.server, CM_SERVER_GROUP) == 0;
    if (is_group) {
        cmi_attr_jid(n, "participant", &part);
        cm_jid_copy(&sender, &part);
        cm_jid_copy(&chat, &from);
    } else {
        cm_jid_copy(&sender, &from);
        cm_jid_copy(&chat, &from);
        if (from.user && strcmp(from.user, own) == 0) {
            from_me = 1;
            if (cmi_attr_jid(n, "recipient", &recipient) == CM_OK) {
                cm_jid_free(&chat);
                cm_jid_init(&chat);
                cm_jid_copy(&chat, &recipient);
            }
        }
    }
    snprintf(key, sizeof(key), "in:%.60s:%.60s", sender.user ? sender.user : "", mid);
    if (cmi_retry_count_inc(c, key) >= 10)
        goto done;

    m = waweb_protobufs_e2_e__message__unpack(NULL, olen, orig);
    if (m == NULL)
        goto done;
    type = cmi_msg_type(m, &mediatype);
    edit_attr = NULL;
    if (m->protocolmessage && m->protocolmessage->has_type)
        edit_attr = m->protocolmessage->type == WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__MESSAGE_EDIT ? "1" :
                    (m->protocolmessage->key && m->protocolmessage->key->fromme ? "7" : "8");

    if (is_group) {
        signal_protocol_address sa;
        signal_protocol_sender_key_name kn;
        group_session_builder *gb = NULL;
        sender_key_distribution_message *skdm = NULL;
        char *gs = NULL, *sname = NULL;
        cm_jid own_dev;
        WAWebProtobufsE2E__SenderKeyDistributionMessage sk = WAWEB_PROTOBUFS_E2_E__SENDER_KEY_DISTRIBUTION_MESSAGE__INIT;
        signal_buffer *ser;

        cm_jid_init(&own_dev);
        cm_jid_copy(&own_dev, &c->dev->id);
        cm_jid_to_string(&from, &gs);
        if (gs) {
            const cm_group_info *gi = NULL;

            if (cmi_group_get(c, &from, &gi) == CM_OK && gi->addressing_mode && strcmp(gi->addressing_mode, "lid") == 0 &&
                !cm_jid_is_empty(&c->dev->lid)) {
                cm_jid_free(&own_dev);
                cm_jid_init(&own_dev);
                cm_jid_copy(&own_dev, &c->dev->lid);
                own_dev.device = c->dev->id.device;
            }
            cmi_addr_of(&own_dev, &sname, &sa);
            kn.group_id = gs;
            kn.group_id_len = strlen(gs);
            kn.sender = sa;
            if (group_session_builder_create(&gb, c->dev->sstore, c->dev->sctx) >= 0 &&
                group_session_builder_create_session(gb, &skdm, &kn) >= 0) {
                ser = ciphertext_message_get_serialized((ciphertext_message *)skdm);
                sk.groupid = gs;
                sk.has_axolotlsenderkeydistributionmessage = 1;
                sk.axolotlsenderkeydistributionmessage.data = signal_buffer_data(ser);
                sk.axolotlsenderkeydistributionmessage.len = signal_buffer_len(ser);
                m->senderkeydistributionmessage = &sk;
                plen = waweb_protobufs_e2_e__message__get_packed_size(m);
                plain = (uint8_t *)malloc(plen ? plen : 1);
                if (plain)
                    waweb_protobufs_e2_e__message__pack(m, plain);
                m->senderkeydistributionmessage = NULL;
            }
        }
        if (skdm) SIGNAL_UNREF(skdm);
        if (gb) group_session_builder_free(gb);
        free(gs);
        free(sname);
        cm_jid_free(&own_dev);
    } else if (from_me) {
        E2EMsg w = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
        WAWebProtobufsE2E__DeviceSentMessage dsm = WAWEB_PROTOBUFS_E2_E__DEVICE_SENT_MESSAGE__INIT;
        char *d = NULL;

        if (cm_jid_to_string(&chat, &d) == CM_OK) {
            dsm.destinationjid = d;
            dsm.message = m;
            w.devicesentmessage = &dsm;
            plen = waweb_protobufs_e2_e__message__get_packed_size(&w);
            plain = (uint8_t *)malloc(plen ? plen : 1);
            if (plain)
                waweb_protobufs_e2_e__message__pack(&w, plain);
        }
        free(d);
    } else {
        plain = (uint8_t *)cm_memdup(orig, olen);
        plen = olen;
    }
    if (plain == NULL)
        goto done;

    /* make sure we have a (fresh) session with the requester */
    if (cm_node_child(n, "keys") != NULL) {
        cmi_process_bundle(c, &sender, n);
    } else {
        signal_protocol_address a;
        char *nm = NULL;
        int have;

        cmi_addr_of(&sender, &nm, &a);
        have = signal_protocol_session_contains_session(c->dev->sstore, &a);
        free(nm);
        if (!have || count >= 2)
            cmi_build_sessions(c, &sender, 1);
    }
    e = cmi_encrypt_for(c, plain, plen, &sender, mediatype, &enc, &pk);
    if (e != CM_OK)
        goto done;
    {
        char cs[16];

        sprintf(cs, "%d", count);
        cm_node_set_attr_str(&enc, "count", cs);
    }
    cmi_node(&out, "message");
    cmi_set_attr_copy(&out, n, "from", "to");
    cm_node_set_attr_str(&out, "type", type);
    cm_node_set_attr_str(&out, "id", mid);
    cm_node_set_attr_str(&out, "t", rt ? rt : "0");
    if (!is_group)
        cm_node_set_attr_str(&out, "device_fanout", "false");
    cmi_set_attr_copy(&out, n, "participant", "participant");
    cmi_set_attr_copy(&out, n, "recipient", "recipient");
    if (edit_attr)
        cm_node_set_attr_str(&out, "edit", edit_attr);
    cm_node_add_child(&out, &enc);
    if (pk && c->dev->account) {
        cm_node di;

        cmi_node(&di, "device-identity");
        cm_node_set_content_bytes(&di, c->dev->account, c->dev->account_len);
        cm_node_add_child(&out, &di);
    }
    cm_client_send_node(c, &out);
    cm_node_free(&out);
    cmi_save(c);
done:
    if (m)
        waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
    free(plain);
    cm_jid_free(&from); cm_jid_free(&part); cm_jid_free(&recipient); cm_jid_free(&sender); cm_jid_free(&chat);
}
