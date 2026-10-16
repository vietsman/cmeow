/* See include/common.h for license and attribution. Port of whatsmeow/store/clientpayload.go */
#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "waCompanionReg/WACompanionReg.pb-c.h"
#include "waWa6/WAWebProtobufsWa6.pb-c.h"

static uint32_t g_ver[3] = {2, 3000, 1049558099u};

void cm_set_wa_version(uint32_t a, uint32_t b, uint32_t c)
{
    if (a == 0 && b == 0 && c == 0)
        return;
    g_ver[0] = a;
    g_ver[1] = b;
    g_ver[2] = c;
}

static void ver_hash(uint8_t out[16])
{
    char s[48];
    unsigned int n = 16;

    sprintf(s, "%lu.%lu.%lu", (unsigned long)g_ver[0], (unsigned long)g_ver[1], (unsigned long)g_ver[2]);
    EVP_Digest(s, strlen(s), out, &n, EVP_md5(), NULL);
}

static cm_err pack_device_props(uint8_t **out, size_t *len)
{
    WACompanionReg__DeviceProps dp = WACOMPANION_REG__DEVICE_PROPS__INIT;
    WACompanionReg__DeviceProps__AppVersion av = WACOMPANION_REG__DEVICE_PROPS__APP_VERSION__INIT;
    WACompanionReg__DeviceProps__HistorySyncConfig hs =
        WACOMPANION_REG__DEVICE_PROPS__HISTORY_SYNC_CONFIG__INIT;

    av.has_primary = 1; av.primary = 0;
    av.has_secondary = 1; av.secondary = 1;
    av.has_tertiary = 1; av.tertiary = 0;
    hs.has_storagequotamb = 1; hs.storagequotamb = 10240;
    hs.has_inlineinitialpayloadine2eemsg = 1; hs.inlineinitialpayloadine2eemsg = 1;
    hs.has_supportcallloghistory = 1; hs.supportcallloghistory = 1;
    hs.has_supportbotuseragentchathistory = 1; hs.supportbotuseragentchathistory = 1;
    hs.has_supportcagreactionsandpolls = 1; hs.supportcagreactionsandpolls = 1;
    hs.has_supportbizhostedmsg = 1; hs.supportbizhostedmsg = 1;
    hs.has_supportrecentsyncchunkmessagecounttuning = 1; hs.supportrecentsyncchunkmessagecounttuning = 1;
    hs.has_supporthostedgroupmsg = 1; hs.supporthostedgroupmsg = 1;
    hs.has_supportfbidbotchathistory = 1; hs.supportfbidbotchathistory = 1;
    hs.has_supportmessageassociation = 1; hs.supportmessageassociation = 1;
    hs.has_supportgrouphistory = 1; hs.supportgrouphistory = 1;
    hs.has_thumbnailsyncdayslimit = 1; hs.thumbnailsyncdayslimit = 60;
    hs.has_supportmanushistory = 1; hs.supportmanushistory = 1;
    hs.has_supporthatchhistory = 1; hs.supporthatchhistory = 1;
    dp.os = (char *)"whatsmeow";
    dp.version = &av;
    dp.has_platformtype = 1;
    dp.platformtype = WACOMPANION_REG__DEVICE_PROPS__PLATFORM_TYPE__UNKNOWN;
    dp.has_requirefullsync = 1;
    dp.requirefullsync = 0;
    dp.historysyncconfig = &hs;
    *len = wacompanion_reg__device_props__get_packed_size(&dp);
    *out = (uint8_t *)malloc(*len);
    if (*out == NULL)
        return CM_ERR_NOMEM;
    wacompanion_reg__device_props__pack(&dp, *out);
    return CM_OK;
}

cm_err cm_device_client_payload(const cm_device *d, uint8_t **out, size_t *len)
{
    WAWebProtobufsWa6__ClientPayload p = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__INIT;
    WAWebProtobufsWa6__ClientPayload__UserAgent ua = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__USER_AGENT__INIT;
    WAWebProtobufsWa6__ClientPayload__UserAgent__AppVersion av =
        WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__USER_AGENT__APP_VERSION__INIT;
    WAWebProtobufsWa6__ClientPayload__WebInfo wi = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__WEB_INFO__INIT;
    WAWebProtobufsWa6__ClientPayload__DevicePairingRegistrationData reg =
        WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__DEVICE_PAIRING_REGISTRATION_DATA__INIT;
    uint8_t regid[4], skid[3], keytype = 5, bh[16], *props = NULL;
    size_t props_len = 0;
    cm_err e = CM_OK;

    av.has_primary = av.has_secondary = av.has_tertiary = 1;
    av.primary = g_ver[0]; av.secondary = g_ver[1]; av.tertiary = g_ver[2];
    ua.has_platform = 1;
    ua.platform = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__USER_AGENT__PLATFORM__WEB;
    ua.has_releasechannel = 1;
    ua.releasechannel = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__USER_AGENT__RELEASE_CHANNEL__RELEASE;
    ua.appversion = &av;
    ua.mcc = (char *)"000";
    ua.mnc = (char *)"000";
    ua.osversion = (char *)"0.1";
    ua.manufacturer = (char *)"";
    ua.device = (char *)"Desktop";
    ua.osbuildnumber = (char *)"0.1";
    ua.localelanguageiso6391 = (char *)"en";
    ua.localecountryiso31661alpha2 = (char *)"US";
    wi.has_websubplatform = 1;
    wi.websubplatform = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__WEB_INFO__WEB_SUB_PLATFORM__WEB_BROWSER;
    p.useragent = &ua;
    p.webinfo = &wi;
    p.has_connecttype = 1;
    p.connecttype = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__CONNECT_TYPE__WIFI_UNKNOWN;
    p.has_connectreason = 1;
    p.connectreason = WAWEB_PROTOBUFS_WA6__CLIENT_PAYLOAD__CONNECT_REASON__USER_ACTIVATED;

    if (d->has_id) {
        if (cm_jid_is_empty(&d->id))
            return CM_ERR_ARG;
        p.has_username = 1;
        p.username = strtoull(d->id.user, NULL, 10);
        p.has_device = 1;
        p.device = d->id.device;
        p.has_passive = 1; p.passive = 1;
        p.has_pull = 1; p.pull = 1;
        p.has_liddbmigrated = 1; p.liddbmigrated = 1;
        p.has_lc = 1; p.lc = 1;
    } else {
        e = pack_device_props(&props, &props_len);
        if (e != CM_OK)
            return e;
        regid[0] = (uint8_t)(d->registration_id >> 24); regid[1] = (uint8_t)(d->registration_id >> 16);
        regid[2] = (uint8_t)(d->registration_id >> 8);  regid[3] = (uint8_t)d->registration_id;
        skid[0] = (uint8_t)(d->signed_prekey.id >> 16); skid[1] = (uint8_t)(d->signed_prekey.id >> 8);
        skid[2] = (uint8_t)d->signed_prekey.id;
        ver_hash(bh);
#define BIN(field, ptr, n) do { reg.has_##field = 1; reg.field.data = (uint8_t *)(ptr); reg.field.len = (n); } while (0)
        BIN(eregid, regid, 4);
        BIN(ekeytype, &keytype, 1);
        BIN(eident, d->identity_key.pub, 32);
        BIN(eskeyid, skid, 3);
        BIN(eskeyval, d->signed_prekey.key.pub, 32);
        BIN(eskeysig, d->signed_prekey.signature, 64);
        BIN(buildhash, bh, 16);
        BIN(deviceprops, props, props_len);
#undef BIN
        p.devicepairingdata = &reg;
        p.has_passive = 1; p.passive = 0;
        p.has_pull = 1; p.pull = 0;
    }
    *len = waweb_protobufs_wa6__client_payload__get_packed_size(&p);
    *out = (uint8_t *)malloc(*len ? *len : 1);
    if (*out == NULL)
        e = CM_ERR_NOMEM;
    else
        waweb_protobufs_wa6__client_payload__pack(&p, *out);
    free(props);
    return e;
}
