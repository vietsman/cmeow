/* See include/common.h for license and attribution. Port of whatsmeow send.go / broadcast.go. */
#define _POSIX_C_SOURCE 200112L
#include "messaging_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "waE2E/WAWebProtobufsE2E.pb-c.h"

typedef WAWebProtobufsE2E__Message E2EMsg;

void cm_send_resp_free(cm_send_resp *r)
{
    if (r) {
        free(r->id);
        free(r->phash);
        memset(r, 0, sizeof(*r));
    }
}

/* ---------------------------------------------------------------- padding / encryption */
cm_err cmi_pad(const uint8_t *in, size_t len, uint8_t **out, size_t *olen)
{
    uint8_t pad, *p;

    if (cm_random(&pad, 1) != CM_OK)
        return CM_ERR_CRYPTO;
    pad &= 0xf;
    if (pad == 0)
        pad = 0xf;
    p = (uint8_t *)malloc(len + pad);
    if (p == NULL)
        return CM_ERR_NOMEM;
    memcpy(p, in, len);
    memset(p + len, pad, pad);
    *out = p;
    *olen = len + pad;
    return CM_OK;
}

cm_err cmi_encrypt_for(cm_client *c, const uint8_t *plain, size_t plen, const cm_jid *to, const char *mediatype,
                       cm_node *enc_out, int *is_prekey)
{
    signal_protocol_address a;
    char *name;
    session_cipher *sc = NULL;
    ciphertext_message *ct = NULL;
    uint8_t *padded = NULL;
    size_t padlen = 0;
    signal_buffer *ser;
    cm_err e = CM_ERR_CRYPTO;

    cmi_addr_of(to, &name, &a);
    if (!signal_protocol_session_contains_session(c->dev->sstore, &a)) {
        free(name);
        return CM_ERR_PROTO;
    }
    if ((e = cmi_pad(plain, plen, &padded, &padlen)) != CM_OK) {
        free(name);
        return e;
    }
    e = CM_ERR_CRYPTO;
    if (session_cipher_create(&sc, c->dev->sstore, &a, c->dev->sctx) < 0 ||
        session_cipher_encrypt(sc, padded, padlen, &ct) < 0)
        goto out;
    ser = ciphertext_message_get_serialized(ct);
    *is_prekey = ciphertext_message_get_type(ct) == CIPHERTEXT_PREKEY_TYPE;
    if ((e = cmi_node(enc_out, "enc")) != CM_OK)
        goto out;
    cm_node_set_attr_str(enc_out, "v", "2");
    cm_node_set_attr_str(enc_out, "type", *is_prekey ? "pkmsg" : "msg");
    if (mediatype != NULL && mediatype[0])
        cm_node_set_attr_str(enc_out, "mediatype", mediatype);
    e = cm_node_set_content_bytes(enc_out, signal_buffer_data(ser), signal_buffer_len(ser));
out:
    if (ct) SIGNAL_UNREF(ct);
    if (sc) session_cipher_free(sc);
    free(padded);
    free(name);
    return e;
}

/* ---------------------------------------------------------------- message classification */
const char *cmi_msg_type(const void *vm, const char **mediatype)
{
    const E2EMsg *m = (const E2EMsg *)vm;
    const char *mt = "";
    const char *type = "text";

    if (m->devicesentmessage && m->devicesentmessage->message)
        m = m->devicesentmessage->message;
    if (m->reactionmessage || m->encreactionmessage) {
        type = "reaction";
    } else if (m->imagemessage) {
        type = "media"; mt = "image";
    } else if (m->stickermessage) {
        type = "media"; mt = "sticker";
    } else if (m->videomessage) {
        type = "media"; mt = m->videomessage->has_gifplayback && m->videomessage->gifplayback ? "gif" : "video";
    } else if (m->audiomessage) {
        type = "media"; mt = m->audiomessage->has_ptt && m->audiomessage->ptt ? "ptt" : "audio";
    } else if (m->documentmessage) {
        type = "media"; mt = "document";
    } else if (m->contactmessage) {
        type = "media"; mt = "vcard";
    } else if (m->locationmessage) {
        type = "media"; mt = "location";
    } else if (m->livelocationmessage) {
        type = "media"; mt = "livelocation";
    }
    if (mediatype)
        *mediatype = mt;
    return type;
}

static const char *edit_attr_of(const E2EMsg *m)
{
    if (m->protocolmessage && m->protocolmessage->has_type) {
        if (m->protocolmessage->type == WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__MESSAGE_EDIT)
            return "1";
        if (m->protocolmessage->type == WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__REVOKE) {
            if (m->protocolmessage->key && m->protocolmessage->key->has_fromme && m->protocolmessage->key->fromme)
                return "7";
            return "8";
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- packing */
static uint8_t *pack_msg(const E2EMsg *m, size_t *len)
{
    uint8_t *out;

    *len = waweb_protobufs_e2_e__message__get_packed_size(m);
    out = (uint8_t *)malloc(*len ? *len : 1);
    if (out)
        waweb_protobufs_e2_e__message__pack(m, out);
    return out;
}

static uint8_t *pack_dsm(E2EMsg *inner, const cm_jid *dest, size_t *len)
{
    E2EMsg w = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__DeviceSentMessage dsm = WAWEB_PROTOBUFS_E2_E__DEVICE_SENT_MESSAGE__INIT;
    char *d = NULL;
    uint8_t *out;

    if (cm_jid_to_string(dest, &d) != CM_OK)
        return NULL;
    dsm.destinationjid = d;
    dsm.message = inner;
    w.devicesentmessage = &dsm;
    out = pack_msg(&w, len);
    free(d);
    return out;
}

static uint8_t *pack_skdm(const char *group, const uint8_t *skdm, size_t skdm_len, size_t *len)
{
    E2EMsg w = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__SenderKeyDistributionMessage s = WAWEB_PROTOBUFS_E2_E__SENDER_KEY_DISTRIBUTION_MESSAGE__INIT;

    s.groupid = (char *)group;
    s.has_axolotlsenderkeydistributionmessage = 1;
    s.axolotlsenderkeydistributionmessage.data = (uint8_t *)skdm;
    s.axolotlsenderkeydistributionmessage.len = skdm_len;
    w.senderkeydistributionmessage = &s;
    return pack_msg(&w, len);
}

/* ---------------------------------------------------------------- hashes */
static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* participantListHashV2: "2:" + rawstd-base64(sha256(sorted AD strings concatenated)[:6]) */
static char *phash_v2(const cmi_jidlist *devs)
{
    char **v = (char **)calloc(devs->n + 1, sizeof(char *));
    size_t i, total = 0, o = 0;
    char *cat = NULL, *out = NULL;
    uint8_t h[32];

    if (v == NULL)
        return NULL;
    for (i = 0; i < devs->n; i++) {
        if (cm_jid_to_ad_string(&devs->v[i], &v[i]) != CM_OK)
            goto done;
        total += strlen(v[i]);
    }
    qsort(v, devs->n, sizeof(char *), cmp_str);
    cat = (char *)malloc(total + 1);
    if (cat == NULL)
        goto done;
    for (i = 0; i < devs->n; i++) {
        size_t l = strlen(v[i]);

        memcpy(cat + o, v[i], l);
        o += l;
    }
    if (cm_sha256(cat, total, h) != CM_OK)
        goto done;
    out = (char *)malloc(3 + 8 + 1);
    if (out) {
        out[0] = '2'; out[1] = ':';
        for (i = 0; i < 2; i++) {
            uint32_t w = (uint32_t)h[3 * i] << 16 | (uint32_t)h[3 * i + 1] << 8 | h[3 * i + 2];

            out[2 + 4 * i] = B64[(w >> 18) & 63];
            out[3 + 4 * i] = B64[(w >> 12) & 63];
            out[4 + 4 * i] = B64[(w >> 6) & 63];
            out[5 + 4 * i] = B64[w & 63];
        }
        out[10] = 0;
    }
done:
    for (i = 0; i < devs->n; i++)
        free(v[i]);
    free(v);
    free(cat);
    return out;
}

/* ---------------------------------------------------------------- common node bits */
static void add_identity(cm_client *c, cm_node *msg)
{
    cm_node di;

    if (c->dev->account == NULL)
        return;
    cmi_node(&di, "device-identity");
    cm_node_set_content_bytes(&di, c->dev->account, c->dev->account_len);
    cm_node_add_child(msg, &di);
}

static void ensure_sessions(cm_client *c, const cmi_jidlist *devs, const cm_jid *skip)
{
    cmi_jidlist need = {0, 0, 0};
    size_t i;

    for (i = 0; i < devs->n; i++) {
        char *name = NULL;
        signal_protocol_address a;

        if (skip && cm_jid_equal(&devs->v[i], skip))
            continue;
        cmi_addr_of(&devs->v[i], &name, &a);
        if (!signal_protocol_session_contains_session(c->dev->sstore, &a))
            cmi_jl_add(&need, &devs->v[i]);
        free(name);
    }
    if (need.n > 0)
        cmi_build_sessions(c, need.v, need.n);
    cmi_jl_free(&need);
}

/* waits for the server ack; handles error / phash feedback */
static cm_err finish_send(cm_client *c, cm_node *msg, const char *id, const char *to_group,
                          int timeout_ms, cm_send_resp *resp, const char *phash)
{
    cm_node *ack = NULL;
    cm_err e = cmi_send_wait(c, msg, id, timeout_ms > 0 ? timeout_ms : 75000, &ack);

    if (e == CM_OK && ack != NULL) {
        const char *err = cmi_attr(ack, "error"), *t = cmi_attr(ack, "t"), *ph = cmi_attr(ack, "phash");

        if (err != NULL) {
            e = CM_ERR_PROTO;
            if (to_group)
                cmi_skdm_reset(c, to_group);
        } else {
            if (resp && t)
                resp->timestamp = (int64_t)strtoll(t, NULL, 10);
            if (to_group && phash && ph && strcmp(ph, phash) != 0)
                cmi_skdm_reset(c, to_group); /* server thinks the participant list differs */
        }
    }
    cmi_free_resp(ack);
    return e;
}

/* ---------------------------------------------------------------- DM */
static cm_err send_dm(cm_client *c, const cm_jid *to, E2EMsg *m, const uint8_t *plain, size_t plen,
                      const char *id, const char *edit, int timeout_ms, cm_send_resp *resp)
{
    cm_device *d = c->dev;
    cmi_jidlist devs = {0, 0, 0};
    cm_jid users[2], enc_to, own;
    uint8_t *dsm = NULL;
    size_t dlen = 0, i;
    cm_node msg, parts;
    const char *mediatype = "", *type = cmi_msg_type(m, &mediatype);
    int include_identity = 0;
    cm_err e;

    cm_jid_init(&users[0]); cm_jid_init(&users[1]); cm_jid_init(&enc_to); cm_jid_init(&own);
    /* once the LID of a phone-number user is known, sessions and device lists use the LID */
    if ((e = cm_jid_copy(&enc_to, to)) != CM_OK || (e = cm_jid_copy(&own, &d->id)) != CM_OK)
        goto out;
    cmi_lid_for_pn(c, to, &enc_to);
    if (strcmp(enc_to.server, CM_SERVER_HIDDEN_USER) == 0 && !cm_jid_is_empty(&d->lid)) {
        cm_jid_free(&own);
        cm_jid_init(&own);
        if ((e = cm_jid_copy(&own, &d->lid)) != CM_OK)
            goto out;
        own.device = d->id.device;
    }
    if ((e = cm_jid_to_non_ad(&users[0], &enc_to)) != CM_OK || (e = cm_jid_to_non_ad(&users[1], &own)) != CM_OK)
        goto out;
    if ((dsm = pack_dsm(m, to, &dlen)) == NULL) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    if ((e = cmi_get_devices(c, users, 2, &devs)) != CM_OK)
        goto out;
    ensure_sessions(c, &devs, &own);

    cmi_node(&msg, "message");
    cm_node_set_attr_str(&msg, "id", id);
    cm_node_set_attr_str(&msg, "type", type);
    cm_node_set_attr_jid(&msg, "to", to);
    if (edit)
        cm_node_set_attr_str(&msg, "edit", edit);
    cmi_node(&parts, "participants");
    for (i = 0; i < devs.n; i++) {
        cm_node toN, enc;
        int pk = 0;
        int mine = strcmp(devs.v[i].user ? devs.v[i].user : "", own.user ? own.user : "") == 0;
        const char *mt = (!mine && mediatype[0]) ? mediatype : (mine && mediatype[0] ? mediatype : "");

        if (cm_jid_equal(&devs.v[i], &own))
            continue;
        if (cmi_encrypt_for(c, mine ? dsm : plain, mine ? dlen : plen, &devs.v[i], mt, &enc, &pk) != CM_OK)
            continue;
        if (edit && enc.tag) /* revoke/edit/reaction: do not show a decrypt failure */
            cm_node_set_attr_str(&enc, "decrypt-fail", "hide");
        else if (strcmp(type, "reaction") == 0)
            cm_node_set_attr_str(&enc, "decrypt-fail", "hide");
        include_identity |= pk;
        cmi_node(&toN, "to");
        cm_node_set_attr_jid(&toN, "jid", &devs.v[i]);
        cm_node_add_child(&toN, &enc);
        cm_node_add_child(&parts, &toN);
    }
    if (cm_node_nchildren(&parts) == 0) {
        cm_node_free(&parts);
        cm_node_free(&msg);
        e = CM_ERR_PROTO;
        goto out;
    }
    cm_node_add_child(&msg, &parts);
    if (include_identity)
        add_identity(c, &msg);
    {
        size_t tl = 0;
        const uint8_t *tk = cmi_tctoken_for(c, &enc_to, &tl);

        if (tk != NULL) {
            cm_node tn;

            if (cmi_node(&tn, "tctoken") == CM_OK) {
                cm_node_set_content_bytes(&tn, tk, tl);
                cm_node_add_child(&msg, &tn);
            }
        }
    }
    cmi_remember_sent(c, id, to, plain, plen);
    e = finish_send(c, &msg, id, NULL, timeout_ms, resp, NULL);
    if (e == CM_OK)
        cmi_tctoken_issue(c, &enc_to);
    cm_node_free(&msg);
    cmi_save(c);
out:
    free(dsm);
    cmi_jl_free(&devs);
    cm_jid_free(&users[0]); cm_jid_free(&users[1]); cm_jid_free(&enc_to); cm_jid_free(&own);
    return e;
}

/* ---------------------------------------------------------------- group / broadcast */
static void sender_key_name(signal_protocol_sender_key_name *k, const char *group, const cm_jid *own,
                            signal_protocol_address *a, char **name)
{
    cmi_addr_of(own, name, a);
    k->group_id = group;
    k->group_id_len = strlen(group);
    k->sender = *a;
}

static cm_err send_group(cm_client *c, const cm_jid *to, E2EMsg *m, const uint8_t *plain, size_t plen,
                         const cmi_jidlist *participants, const cm_jid *own, const char *id,
                         const char *edit, int timeout_ms, cm_send_resp *resp)
{
    cm_device *d = c->dev;
    cmi_jidlist devs = {0, 0, 0}, users = {0, 0, 0};
    char *gstr = NULL, *phash = NULL, *sname = NULL;
    signal_protocol_address sa;
    signal_protocol_sender_key_name kn;
    group_session_builder *gb = NULL;
    group_cipher *gc = NULL;
    sender_key_distribution_message *skdm = NULL;
    ciphertext_message *ct = NULL;
    uint8_t *skdm_plain = NULL, *padded = NULL;
    size_t skdm_plain_len = 0, padlen = 0, i;
    signal_buffer *ser;
    cm_node msg, parts, skmsg;
    const char *mediatype = "", *type = cmi_msg_type(m, &mediatype);
    int include_identity = 0;
    cm_err e;

    (void)m;
    if ((e = cm_jid_to_string(to, &gstr)) != CM_OK)
        return e;
    for (i = 0; i < participants->n; i++) {
        cm_jid u;

        cm_jid_init(&u);
        if (cm_jid_to_non_ad(&u, &participants->v[i]) == CM_OK)
            cmi_jl_add(&users, &u);
        cm_jid_free(&u);
    }
    if ((e = cmi_get_devices(c, users.v, users.n, &devs)) != CM_OK)
        goto out;
    {   /* drop hosted devices as whatsmeow does */
        size_t w = 0;

        for (i = 0; i < devs.n; i++) {
            if (strcmp(devs.v[i].server, CM_SERVER_HOSTED) == 0 || strcmp(devs.v[i].server, CM_SERVER_HOSTED_LID) == 0) {
                cm_jid_free(&devs.v[i]);
            } else {
                if (w != i)
                    devs.v[w] = devs.v[i];
                w++;
            }
        }
        devs.n = w;
    }
    ensure_sessions(c, &devs, own);

    sender_key_name(&kn, gstr, own, &sa, &sname);
    if (group_session_builder_create(&gb, d->sstore, d->sctx) < 0 ||
        group_session_builder_create_session(gb, &skdm, &kn) < 0 ||
        group_cipher_create(&gc, d->sstore, &kn, d->sctx) < 0) {
        e = CM_ERR_CRYPTO;
        goto out;
    }
    ser = ciphertext_message_get_serialized((ciphertext_message *)skdm);
    skdm_plain = pack_skdm(gstr, signal_buffer_data(ser), signal_buffer_len(ser), &skdm_plain_len);
    if (skdm_plain == NULL) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    if ((e = cmi_pad(plain, plen, &padded, &padlen)) != CM_OK)
        goto out;
    if (group_cipher_encrypt(gc, padded, padlen, &ct) < 0) {
        e = CM_ERR_CRYPTO;
        goto out;
    }
    ser = ciphertext_message_get_serialized(ct);

    phash = phash_v2(&devs);
    cmi_node(&msg, "message");
    cm_node_set_attr_str(&msg, "id", id);
    cm_node_set_attr_str(&msg, "type", type);
    cm_node_set_attr_jid(&msg, "to", to);
    if (phash)
        cm_node_set_attr_str(&msg, "phash", phash);
    if (edit)
        cm_node_set_attr_str(&msg, "edit", edit);
    cmi_node(&parts, "participants");
    for (i = 0; i < devs.n; i++) {
        cm_node toN, enc;
        int pk = 0;

        if (cm_jid_equal(&devs.v[i], own) || cm_jid_equal(&devs.v[i], &d->id))
            continue;
        if (cmi_skdm_has(c, gstr, &devs.v[i]))
            continue;
        if (cmi_encrypt_for(c, skdm_plain, skdm_plain_len, &devs.v[i], "", &enc, &pk) != CM_OK)
            continue;
        include_identity |= pk;
        cmi_skdm_mark(c, gstr, &devs.v[i]);
        cmi_node(&toN, "to");
        cm_node_set_attr_jid(&toN, "jid", &devs.v[i]);
        cm_node_add_child(&toN, &enc);
        cm_node_add_child(&parts, &toN);
    }
    if (cm_node_nchildren(&parts) > 0)
        cm_node_add_child(&msg, &parts);
    else
        cm_node_free(&parts);
    cmi_node(&skmsg, "enc");
    cm_node_set_attr_str(&skmsg, "v", "2");
    cm_node_set_attr_str(&skmsg, "type", "skmsg");
    if (mediatype[0])
        cm_node_set_attr_str(&skmsg, "mediatype", mediatype);
    if (edit || strcmp(type, "reaction") == 0)
        cm_node_set_attr_str(&skmsg, "decrypt-fail", "hide");
    cm_node_set_content_bytes(&skmsg, signal_buffer_data(ser), signal_buffer_len(ser));
    cm_node_add_child(&msg, &skmsg);
    if (include_identity)
        add_identity(c, &msg);
    cmi_remember_sent(c, id, to, plain, plen);
    e = finish_send(c, &msg, id, gstr, timeout_ms, resp, phash);
    if (e == CM_OK && resp && phash) {
        resp->phash = phash;
        phash = NULL;
    }
    cm_node_free(&msg);
    cmi_save(c);
out:
    if (ct) SIGNAL_UNREF(ct);
    if (skdm) SIGNAL_UNREF(skdm);
    if (gc) group_cipher_free(gc);
    if (gb) group_session_builder_free(gb);
    free(sname);
    free(skdm_plain);
    free(padded);
    free(phash);
    free(gstr);
    cmi_jl_free(&devs);
    cmi_jl_free(&users);
    return e;
}

/* ---------------------------------------------------------------- public send */
static cm_err send_impl(cm_client *c, const cm_jid *to, const uint8_t *msg, size_t len, const cm_send_opts *o,
                        const cmi_jidlist *bcast_to, cm_send_resp *resp)
{
    E2EMsg *m;
    char *id;
    const char *edit;
    cm_err e;

    if (!c->logged_in || !c->dev->has_id)
        return CM_ERR_CLOSED;
    if (strcmp(to->server, CM_SERVER_NEWSLETTER) == 0)
        return CM_ERR_ARG; /* newsletters are not end-to-end encrypted; see user.h */
    m = waweb_protobufs_e2_e__message__unpack(NULL, len, msg);
    if (m == NULL)
        return CM_ERR_PROTO;
    id = (o && o->id) ? cm_strdup(o->id) : cmi_gen_msg_id();
    if (id == NULL) {
        waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
        return CM_ERR_NOMEM;
    }
    edit = (o && o->edit) ? o->edit : edit_attr_of(m);

    if (strcmp(to->server, CM_SERVER_GROUP) == 0) {
        const cm_group_info *gi = NULL;
        cmi_jidlist parts = {0, 0, 0};
        cm_jid own;
        size_t i;
        int lid;

        cm_jid_init(&own);
        e = cmi_group_get(c, to, &gi);
        if (e == CM_OK) {
            lid = gi->addressing_mode && strcmp(gi->addressing_mode, "lid") == 0 && !cm_jid_is_empty(&c->dev->lid);
            if (lid) {
                cm_jid_copy(&own, &c->dev->lid);
                own.device = c->dev->id.device;
            } else {
                cm_jid_copy(&own, &c->dev->id);
            }
            for (i = 0; i < gi->nparticipants; i++)
                cmi_jl_add(&parts, &gi->participants[i].jid);
            e = send_group(c, to, m, msg, len, &parts, &own, id, edit, o ? o->timeout_ms : 0, resp);
            if (e != CM_OK)
                cmi_group_forget(c, to);
        }
        cmi_jl_free(&parts);
        cm_jid_free(&own);
    } else if (strcmp(to->server, CM_SERVER_BROADCAST) == 0) {
        if (bcast_to == NULL || bcast_to->n == 0)
            e = CM_ERR_ARG;
        else
            e = send_group(c, to, m, msg, len, bcast_to, &c->dev->id, id, edit, o ? o->timeout_ms : 0, resp);
    } else {
        e = send_dm(c, to, m, msg, len, id, edit, o ? o->timeout_ms : 0, resp);
    }
    if (e == CM_OK && resp) {
        resp->id = id;
        id = NULL;
    }
    free(id);
    waweb_protobufs_e2_e__message__free_unpacked(m, NULL);
    return e;
}

cm_err cm_client_send_message(cm_client *c, const cm_jid *to, const uint8_t *msg, size_t len,
                              const cm_send_opts *opts, cm_send_resp *resp)
{
    if (resp)
        memset(resp, 0, sizeof(*resp));
    return send_impl(c, to, msg, len, opts, NULL, resp);
}

/* Status / broadcast-list send with an explicit recipient list (broadcast.go). */
cm_err cm_client_send_broadcast(cm_client *c, const cm_jid *bcast, const cm_jid *recipients, size_t n,
                                const uint8_t *msg, size_t len, const cm_send_opts *opts, cm_send_resp *resp)
{
    cmi_jidlist l = {0, 0, 0};
    size_t i;
    cm_err e;

    for (i = 0; i < n; i++)
        cmi_jl_add(&l, &recipients[i]);
    if (resp)
        memset(resp, 0, sizeof(*resp));
    e = send_impl(c, bcast, msg, len, opts, &l, resp);
    cmi_jl_free(&l);
    return e;
}

/* ---------------------------------------------------------------- builders */
uint8_t *cm_message_build_text(const char *text, size_t *len)
{
    E2EMsg m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;

    m.conversation = (char *)text;
    return pack_msg(&m, len);
}

static void fill_key(WACommon__MessageKey *k, const char *remote, int from_me, const char *id, const char *part)
{
    k->remotejid = (char *)remote;
    k->has_fromme = 1;
    k->fromme = from_me;
    k->id = (char *)id;
    k->participant = (char *)part;
}

uint8_t *cm_message_build_reply(const char *text, const char *quoted_id, const cm_jid *quoted_sender,
                                const uint8_t *quoted_msg, size_t quoted_len, size_t *len)
{
    E2EMsg m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT, *q = NULL;
    WAWebProtobufsE2E__ExtendedTextMessage et = WAWEB_PROTOBUFS_E2_E__EXTENDED_TEXT_MESSAGE__INIT;
    WAWebProtobufsE2E__ContextInfo ci = WAWEB_PROTOBUFS_E2_E__CONTEXT_INFO__INIT;
    char *sender = NULL;
    uint8_t *out;

    if (cm_jid_to_string(quoted_sender, &sender) != CM_OK)
        return NULL;
    if (quoted_msg != NULL)
        q = waweb_protobufs_e2_e__message__unpack(NULL, quoted_len, quoted_msg);
    ci.stanzaid = (char *)quoted_id;
    ci.participant = sender;
    ci.quotedmessage = q;
    et.text = (char *)text;
    et.contextinfo = &ci;
    m.extendedtextmessage = &et;
    out = pack_msg(&m, len);
    if (q)
        waweb_protobufs_e2_e__message__free_unpacked(q, NULL);
    free(sender);
    return out;
}

uint8_t *cm_message_build_reaction(const cm_jid *chat, const cm_jid *sender, const char *target_id,
                                   int from_me, const char *emoji, size_t *len)
{
    E2EMsg m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__ReactionMessage r = WAWEB_PROTOBUFS_E2_E__REACTION_MESSAGE__INIT;
    WACommon__MessageKey k = WACOMMON__MESSAGE_KEY__INIT;
    char *cs = NULL, *ss = NULL;
    uint8_t *out = NULL;
    int64_t now = (int64_t)time(NULL) * 1000;

    if (cm_jid_to_string(chat, &cs) != CM_OK)
        return NULL;
    if (sender && !cm_jid_is_empty(sender) && strcmp(chat->server, CM_SERVER_GROUP) == 0 && !from_me)
        cm_jid_to_string(sender, &ss);
    fill_key(&k, cs, from_me, target_id, ss);
    r.key = &k;
    r.text = (char *)emoji;
    r.has_sendertimestampms = 1;
    r.sendertimestampms = now;
    m.reactionmessage = &r;
    out = pack_msg(&m, len);
    free(cs);
    free(ss);
    return out;
}

uint8_t *cm_message_build_revoke(const cm_jid *chat, const cm_jid *sender, const char *target_id,
                                 int from_me, size_t *len)
{
    E2EMsg m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__ProtocolMessage p = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__INIT;
    WACommon__MessageKey k = WACOMMON__MESSAGE_KEY__INIT;
    char *cs = NULL, *ss = NULL;
    uint8_t *out;

    if (cm_jid_to_string(chat, &cs) != CM_OK)
        return NULL;
    if (sender && !cm_jid_is_empty(sender) && strcmp(chat->server, CM_SERVER_GROUP) == 0 && !from_me)
        cm_jid_to_string(sender, &ss);
    fill_key(&k, cs, from_me, target_id, ss);
    p.key = &k;
    p.has_type = 1;
    p.type = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__REVOKE;
    m.protocolmessage = &p;
    out = pack_msg(&m, len);
    free(cs);
    free(ss);
    return out;
}

uint8_t *cm_message_build_edit(const cm_jid *chat, const char *target_id, const char *new_text, size_t *len)
{
    E2EMsg m = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT, nm = WAWEB_PROTOBUFS_E2_E__MESSAGE__INIT;
    WAWebProtobufsE2E__ProtocolMessage p = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__INIT;
    WACommon__MessageKey k = WACOMMON__MESSAGE_KEY__INIT;
    char *cs = NULL;
    uint8_t *out;

    if (cm_jid_to_string(chat, &cs) != CM_OK)
        return NULL;
    fill_key(&k, cs, 1, target_id, NULL);
    nm.conversation = (char *)new_text;
    p.key = &k;
    p.has_type = 1;
    p.type = WAWEB_PROTOBUFS_E2_E__PROTOCOL_MESSAGE__TYPE__MESSAGE_EDIT;
    p.editedmessage = &nm;
    p.has_timestampms = 1;
    p.timestampms = (int64_t)time(NULL) * 1000;
    m.protocolmessage = &p;
    out = pack_msg(&m, len);
    free(cs);
    return out;
}

static cm_err send_built(cm_client *c, const cm_jid *to, uint8_t *msg, size_t len, char **msg_id)
{
    cm_send_resp r;
    cm_err e;

    if (msg == NULL)
        return CM_ERR_NOMEM;
    e = cm_client_send_message(c, to, msg, len, NULL, &r);
    free(msg);
    if (e == CM_OK && msg_id) {
        *msg_id = r.id;
        r.id = NULL;
    }
    cm_send_resp_free(&r);
    return e;
}

cm_err cm_client_send_text(cm_client *c, const cm_jid *to, const char *text, char **msg_id)
{
    size_t l = 0;
    uint8_t *b = cm_message_build_text(text, &l);

    return send_built(c, to, b, l, msg_id);
}

cm_err cm_client_send_group_text(cm_client *c, const cm_jid *group, const char *text, char **msg_id)
{
    return cm_client_send_text(c, group, text, msg_id);
}

cm_err cm_client_send_revoke(cm_client *c, const cm_jid *chat, const cm_jid *sender, const char *target_id,
                             int from_me, char **msg_id)
{
    size_t l = 0;
    uint8_t *b = cm_message_build_revoke(chat, sender, target_id, from_me, &l);

    return send_built(c, chat, b, l, msg_id);
}

cm_err cm_client_send_edit(cm_client *c, const cm_jid *chat, const char *target_id, const char *new_text,
                           char **msg_id)
{
    size_t l = 0;
    uint8_t *b = cm_message_build_edit(chat, target_id, new_text, &l);

    return send_built(c, chat, b, l, msg_id);
}

cm_err cm_client_send_reaction(cm_client *c, const cm_jid *chat, const cm_jid *sender, const char *target_id,
                               int from_me, const char *emoji, char **msg_id)
{
    size_t l = 0;
    uint8_t *b = cm_message_build_reaction(chat, sender, target_id, from_me, emoji, &l);

    return send_built(c, chat, b, l, msg_id);
}

/* ---------------------------------------------------------------- peer messages (to our own primary device) */
cm_err cm_client_send_peer_message(cm_client *c, const uint8_t *msg, size_t len, const char *push_priority,
                                   char **msg_id)
{
    cm_jid to;
    cm_node n, meta, enc;
    cmi_jidlist one = {0, 0, 0};
    char *id = cmi_gen_msg_id();
    int pk = 0;
    cm_err e;

    if (!c->logged_in || !c->dev->has_id)
        return CM_ERR_CLOSED;
    if (id == NULL)
        return CM_ERR_NOMEM;
    cm_jid_init(&to);
    if ((e = cm_jid_to_non_ad(&to, &c->dev->id)) != CM_OK)
        goto out;
    cmi_jl_add(&one, &to);
    ensure_sessions(c, &one, NULL);
    if ((e = cmi_encrypt_for(c, msg, len, &to, "", &enc, &pk)) != CM_OK)
        goto out;
    cmi_node(&n, "message");
    cm_node_set_attr_str(&n, "id", id);
    cm_node_set_attr_str(&n, "type", "text");
    cm_node_set_attr_str(&n, "category", "peer");
    cm_node_set_attr_jid(&n, "to", &to);
    if (push_priority)
        cm_node_set_attr_str(&n, "push_priority", push_priority);
    cmi_node(&meta, "meta");
    cm_node_set_attr_str(&meta, "appdata", "default");
    cm_node_add_child(&n, &meta);
    cm_node_add_child(&n, &enc);
    if (pk)
        add_identity(c, &n);
    e = cm_client_send_node(c, &n);
    cm_node_free(&n);
    cmi_save(c);
    if (e == CM_OK && msg_id) {
        *msg_id = id;
        id = NULL;
    }
out:
    free(id);
    cmi_jl_free(&one);
    cm_jid_free(&to);
    return e;
}

cm_err cm_client_send_protocol_receipt(cm_client *c, const char *id, const char *type)
{
    cm_node r;
    cm_jid own;
    cm_err e;

    if (id == NULL || id[0] == 0)
        return CM_OK;
    if (!c->dev->has_id)
        return CM_ERR_CLOSED;
    cm_jid_init(&own);
    cm_jid_to_non_ad(&own, &c->dev->id);
    if ((e = cmi_node(&r, "receipt")) == CM_OK) {
        cm_node_set_attr_str(&r, "id", id);
        cm_node_set_attr_str(&r, "type", type);
        cm_node_set_attr_jid(&r, "to", &own);
        e = cm_client_send_node(c, &r);
        cm_node_free(&r);
    }
    cm_jid_free(&own);
    return e;
}
