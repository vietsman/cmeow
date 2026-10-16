/* See include/common.h for license and attribution.
 * Port of whatsmeow history_sync.go: the phone sends the chat history as zlib-compressed
 * waHistorySync.HistorySync blobs announced by a HistorySyncNotification protocol message. */
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "media.h"
#include "messaging.h"
#include "user.h"
#include "client_priv.h"
#include "waE2E/WAWebProtobufsE2E.pb-c.h"
#include "waHistorySync/WAWebProtobufsHistorySync.pb-c.h"

#define MAX_HISTORY_BYTES ((size_t)512 << 20)

static cm_err inflate_all(const uint8_t *in, size_t n, uint8_t **out, size_t *olen)
{
    z_stream z;
    size_t cap = n * 4 + 4096, len = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    int r;

    if (buf == NULL)
        return CM_ERR_NOMEM;
    memset(&z, 0, sizeof z);
    if (inflateInit(&z) != Z_OK) {
        free(buf);
        return CM_ERR_ZLIB;
    }
    z.next_in = (Bytef *)in;
    z.avail_in = (uInt)n;
    do {
        if (len == cap) {
            uint8_t *nb;

            if (cap >= MAX_HISTORY_BYTES) {
                inflateEnd(&z);
                free(buf);
                return CM_ERR_TOO_LARGE;
            }
            cap *= 2;
            nb = (uint8_t *)realloc(buf, cap);
            if (nb == NULL) {
                inflateEnd(&z);
                free(buf);
                return CM_ERR_NOMEM;
            }
            buf = nb;
        }
        z.next_out = buf + len;
        z.avail_out = (uInt)(cap - len);
        r = inflate(&z, Z_NO_FLUSH);
        len = cap - z.avail_out;
        if (r != Z_OK && r != Z_STREAM_END) {
            inflateEnd(&z);
            free(buf);
            return CM_ERR_ZLIB;
        }
    } while (r != Z_STREAM_END);
    inflateEnd(&z);
    *out = buf;
    *olen = len;
    return CM_OK;
}

static void learn_mappings(cm_client *c, const WAWebProtobufsHistorySync__HistorySync *hs)
{
    size_t i;

    for (i = 0; i < hs->n_phonenumbertolidmappings; i++) {
        const WAWebProtobufsHistorySync__PhoneNumberToLIDMapping *m = hs->phonenumbertolidmappings[i];
        cm_jid a, b;

        if (m == NULL || m->pnjid == NULL || m->lidjid == NULL)
            continue;
        cm_jid_init(&a);
        cm_jid_init(&b);
        if (cm_jid_parse(&a, m->pnjid) == CM_OK && cm_jid_parse(&b, m->lidjid) == CM_OK)
            cmi_lid_learn_jids(c, &a, &b);
        cm_jid_free(&a);
        cm_jid_free(&b);
    }
    for (i = 0; i < hs->n_conversations; i++) {
        const WAWebProtobufsHistorySync__Conversation *cv = hs->conversations[i];
        cm_jid a, b;

        if (cv == NULL || cv->id == NULL || cv->pnjid == NULL)
            continue;
        cm_jid_init(&a);
        cm_jid_init(&b);
        if (cm_jid_parse(&a, cv->id) == CM_OK && cm_jid_parse(&b, cv->pnjid) == CM_OK)
            cmi_lid_learn_jids(c, &a, &b);
        cm_jid_free(&a);
        cm_jid_free(&b);
    }
}

static void emit_pushnames(cm_client *c, const WAWebProtobufsHistorySync__HistorySync *hs)
{
    size_t i;

    for (i = 0; i < hs->n_pushnames; i++) {
        const WAWebProtobufsHistorySync__Pushname *p = hs->pushnames[i];
        cm_ext_about ev;

        if (p == NULL || p->id == NULL || p->pushname == NULL)
            continue;
        ev.jid = p->id;
        ev.status = p->pushname;
        ev.ts = 0;
        cmi_emit_ext(c, CM_EXT_PUSH_NAME, &ev);
    }
}

void cmi_history_on_notification(cm_client *c, const void *notif_v, const char *carrier_id)
{
    const WAWebProtobufsE2E__HistorySyncNotification *hn = (const WAWebProtobufsE2E__HistorySyncNotification *)notif_v;
    uint8_t *blob = NULL, *plain = NULL;
    size_t blen = 0, plen = 0;
    int own_blob = 0;
    WAWebProtobufsHistorySync__HistorySync *hs;
    cm_err e;

    if (hn == NULL)
        return;
    if (hn->has_initialhistbootstrapinlinepayload && hn->initialhistbootstrapinlinepayload.len > 0) {
        blob = hn->initialhistbootstrapinlinepayload.data;
        blen = hn->initialhistbootstrapinlinepayload.len;
    } else if (hn->directpath != NULL) {
        cm_download_info info;

        memset(&info, 0, sizeof info);
        info.direct_path = hn->directpath;
        info.media_key = hn->has_mediakey ? hn->mediakey.data : NULL;
        info.media_key_len = hn->has_mediakey ? hn->mediakey.len : 0;
        info.enc_sha256 = hn->has_fileencsha256 && hn->fileencsha256.len == 32 ? hn->fileencsha256.data : NULL;
        info.file_sha256 = hn->has_filesha256 && hn->filesha256.len == 32 ? hn->filesha256.data : NULL;
        info.type = CM_MEDIA_HISTORY;
        if (cm_client_download(c, &info, &blob, &blen) != CM_OK)
            return;
        own_blob = 1;
    } else {
        return;
    }
    e = inflate_all(blob, blen, &plain, &plen);
    if (own_blob)
        free(blob);
    if (e != CM_OK)
        return;
    hs = waweb_protobufs_history_sync__history_sync__unpack(NULL, plen, plain);
    free(plain);
    if (hs == NULL)
        return;
    learn_mappings(c, hs);
    emit_pushnames(c, hs);
    {
        cm_ext_history ev;

        ev.history_sync = hs;
        ev.sync_type = (int)hs->synctype;
        ev.chunk_order = hs->has_chunkorder ? hs->chunkorder : 0;
        ev.progress = hs->has_progress ? hs->progress : 0;
        cmi_emit_ext(c, CM_EXT_HISTORY_SYNC, &ev);
    }
    waweb_protobufs_history_sync__history_sync__free_unpacked(hs, NULL);
    cmi_save(c);
    if (carrier_id != NULL)
        cm_client_send_protocol_receipt(c, carrier_id, "hist_sync");
}
