/* Mock WhatsApp server half of Noise_XX + cert chain; shared by tests. */
#define NOW INT64_C(1700000000)
/* knobs to break one thing at a time */
struct opts {
    int bad_inter_sig, bad_leaf_sig, wrong_leaf_key, wrong_issuer_serial;
    int inter_wrong_issuer, inter_not_before_future, inter_expired;
    int leaf_not_before_future, leaf_expired, short_sig, missing_leaf, garbage_cert;
    int tamper_static, short_ephemeral, no_static, no_payload, short_inter_key;
};

struct server {
    cm_keypair root, inter, leaf_static, eph;
    cm_noise_hs nh;
};

static uint8_t *pack_details(uint32_t serial, uint32_t issuer, const uint8_t *key, size_t keylen,
                             uint64_t nb, uint64_t na, size_t *len)
{
    WACert__CertChain__NoiseCertificate__Details d = WACERT__CERT_CHAIN__NOISE_CERTIFICATE__DETAILS__INIT;
    uint8_t *buf;

    d.has_serial = 1;
    d.serial = serial;
    d.has_issuerserial = 1;
    d.issuerserial = issuer;
    d.has_key = 1;
    d.key.data = (uint8_t *)key;
    d.key.len = keylen;
    d.has_notbefore = 1;
    d.notbefore = nb;
    d.has_notafter = 1;
    d.notafter = na;
    *len = protobuf_c_message_get_packed_size(&d.base);
    buf = (uint8_t *)malloc(*len);
    protobuf_c_message_pack(&d.base, buf);
    return buf;
}

static uint8_t *make_cert(const struct server *sv, const struct opts *o, size_t *out_len)
{
    size_t ilen, llen, n;
    uint64_t i_nb = 1000, i_na = 4000000000ULL, l_nb = 1000, l_na = 4000000000ULL;
    uint8_t *idet, *ldet, *buf;
    uint8_t isig[64], lsig[64];
    WACert__CertChain chain = WACERT__CERT_CHAIN__INIT;
    WACert__CertChain__NoiseCertificate ic = WACERT__CERT_CHAIN__NOISE_CERTIFICATE__INIT;
    WACert__CertChain__NoiseCertificate lc = WACERT__CERT_CHAIN__NOISE_CERTIFICATE__INIT;

    if (o->inter_not_before_future) i_nb = (uint64_t)NOW + 1000;
    if (o->inter_expired) i_na = (uint64_t)NOW - 1;
    if (o->leaf_not_before_future) l_nb = (uint64_t)NOW + 1000;
    if (o->leaf_expired) l_na = (uint64_t)NOW - 1;

    idet = pack_details(7, o->inter_wrong_issuer ? 9 : 0, sv->inter.pub, o->short_inter_key ? 31 : 32,
                        i_nb, i_na, &ilen);
    ldet = pack_details(8, o->wrong_issuer_serial ? 99 : 7,
                        o->wrong_leaf_key ? sv->eph.pub : sv->leaf_static.pub, 32, l_nb, l_na, &llen);

    cm_xeddsa_sign(sv->root.priv, idet, ilen, isig);
    cm_xeddsa_sign(sv->inter.priv, ldet, llen, lsig);
    if (o->bad_inter_sig) isig[10] ^= 1;
    if (o->bad_leaf_sig) lsig[10] ^= 1;

    ic.has_details = 1;
    ic.details.data = idet;
    ic.details.len = ilen;
    ic.has_signature = 1;
    ic.signature.data = isig;
    ic.signature.len = o->short_sig ? 63 : 64;
    lc.has_details = 1;
    lc.details.data = ldet;
    lc.details.len = llen;
    lc.has_signature = 1;
    lc.signature.data = lsig;
    lc.signature.len = 64;
    chain.intermediate = &ic;
    chain.leaf = o->missing_leaf ? NULL : &lc;
    n = wacert__cert_chain__get_packed_size(&chain);
    buf = (uint8_t *)malloc(n);
    wacert__cert_chain__pack(&chain, buf);
    free(idet);
    free(ldet);
    *out_len = n;
    if (o->garbage_cert) {
        memset(buf, 0xFF, n);
    }
    return buf;
}

/* Builds the ServerHello frame for the given ClientHello frame. */
static uint8_t *server_hello(struct server *sv, const struct opts *o, const uint8_t *hello,
                             size_t hello_len, size_t *out_len, const uint8_t cli_eph_out[32])
{
    WAWebProtobufsWa6__HandshakeMessage *in =
        waweb_protobufs_wa6__handshake_message__unpack(NULL, hello_len, hello);
    WAWebProtobufsWa6__HandshakeMessage msg = WAWEB_PROTOBUFS_WA6__HANDSHAKE_MESSAGE__INIT;
    WAWebProtobufsWa6__HandshakeMessage__ServerHello sh =
        WAWEB_PROTOBUFS_WA6__HANDSHAKE_MESSAGE__SERVER_HELLO__INIT;
    uint8_t hdr[4], *cert, *cert_ct, static_ct[48], *out;
    size_t cert_len;
    const uint8_t *e;

    (void)cli_eph_out;
    if (in == NULL || in->clienthello == NULL || in->clienthello->ephemeral.len != 32) {
        if (in)
            waweb_protobufs_wa6__handshake_message__free_unpacked(in, NULL);
        return NULL;
    }
    e = in->clienthello->ephemeral.data;
    cm_conn_header(hdr);
    cm_noise_start(&sv->nh, CM_NOISE_START_PATTERN, CM_NOISE_START_PATTERN_LEN, hdr, 4);
    cm_noise_authenticate(&sv->nh, e, 32);
    cm_noise_authenticate(&sv->nh, sv->eph.pub, 32);
    cm_noise_mix_shared_secret(&sv->nh, sv->eph.priv, e);
    cm_noise_encrypt(&sv->nh, sv->leaf_static.pub, 32, static_ct);
    cm_noise_mix_shared_secret(&sv->nh, sv->leaf_static.priv, e);
    cert = make_cert(sv, o, &cert_len);
    cert_ct = (uint8_t *)malloc(cert_len + 16);
    cm_noise_encrypt(&sv->nh, cert, cert_len, cert_ct);
    free(cert);
    if (o->tamper_static)
        static_ct[3] ^= 1;

    sh.has_ephemeral = 1;
    sh.ephemeral.data = sv->eph.pub;
    sh.ephemeral.len = o->short_ephemeral ? 31 : 32;
    if (!o->no_static) {
        sh.has_static_ = 1;
        sh.static_.data = static_ct;
        sh.static_.len = 48;
    }
    if (!o->no_payload) {
        sh.has_payload = 1;
        sh.payload.data = cert_ct;
        sh.payload.len = cert_len + 16;
    }
    msg.serverhello = &sh;
    *out_len = waweb_protobufs_wa6__handshake_message__get_packed_size(&msg);
    out = (uint8_t *)malloc(*out_len);
    waweb_protobufs_wa6__handshake_message__pack(&msg, out);
    free(cert_ct);
    waweb_protobufs_wa6__handshake_message__free_unpacked(in, NULL);
    return out;
}

static void make_server(struct server *sv)
{
    memset(sv, 0, sizeof(*sv));
    cm_keypair_generate(&sv->root);
    cm_keypair_generate(&sv->inter);
    cm_keypair_generate(&sv->leaf_static);
    cm_keypair_generate(&sv->eph);
}

