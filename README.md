# cmeow

A C99 port of [whatsmeow](https://github.com/tulir/whatsmeow) (Go, MPL-2.0), the
WhatsApp Web multi-device client library.

**Status: feature-complete port of the core client, unverified against a live server.**
cmeow connects (TLS websocket, Noise), logs in, uploads prekeys, pairs by QR,
sends and receives 1:1 and group messages (Signal sessions and sender keys, LID/PN aware),
handles retry receipts, receipts/read marks, media upload/download/retry, groups
(info/create/participants/settings/invite links), app state (snapshots, patches,
LTHash and MAC validation, mutations), presence, profile pictures, blocklist,
privacy settings, notifications and calls (events). Nothing has been run
against real WhatsApp servers; see "Not verified" and "Known limitations".

## Port status

| whatsmeow package / file | cmeow | Status |
|---|---|---|
| `binary`, `types/jid.go` | `binary.h`, `node.h`, `jid.h` | done; differential-tested against the Go codec while it was ported, now covered by self-contained tests |
| `socket` (frame/Noise socket, handshake, cert check) | `noise.h`, `handshake.h`, `conn.h` | done, tested |
| websocket + TLS transport | `ws.h` (wslay), `net.h` (OpenSSL) | done, loopback + TLS smoke tested |
| `proto` | `src/proto/` (protobuf-c, generated) | done |
| `store` core (Device, identities, sessions, prekeys, sender keys, app-state key table) | `store.h` | done as in-memory tables + single-file persistence; libsignal glue tested with two devices |
| `store/clientpayload.go` | `cm_device_client_payload` | done (not compared byte-for-byte with Go) |
| `client.go`, `request.go`, `keepalive.go`, `connectionevents.go` | `client.h` | done for connect / iq / keepalive / success / failure / stream:error (515 reconnect); tested with a scripted server |
| `prekeys.go` | `prekeys.c` | upload + count tested; bundle fetch/session build written, untested vs. server |
| `pair.go` | `client.c` | QR event tested; pair-success verification written, untested |
| `message.go`, `receipt.go` (receive) | `message.c` | 1:1 (pkmsg/msg) and group (skmsg + SKDM) decrypt written, untested vs. server; delivery receipts and acks |
| `send.go` (1:1 text only) | `cm_client_send_text` | written, untested vs. server |
| `send.go`, `retry.go`, `group.go`, `receipt.go` | `messaging.h`, `send.c`, `retry.c`, `groups.c` | 1:1, group and broadcast send, builders (reply/reaction/edit/revoke), retry receipts both directions, group API; unit-tested only through the scripted-server client test |
| `download.go`, `upload.go`, `mediaconn.go`, `mediaretry.go` | `media.h`, `http.h` | key schedule, streaming decrypt, upload, retry; loopback-tested |
| `appstate/`, `appstate.go` | `appstate.h` | snapshot/patch decode+apply with MAC checks, patch send, recovery, key share; LTHash/index unit-tested |
| `user.go`, `presence.go`, `privacysettings.go`, `notification.go`, `call.go` | `user.h` | is-on-whatsapp, user info, picture, status, blocklist, privacy, presence/chatstate, notifications, call events |
| `store.LIDs`, `migrateSessionStore` | `lid.c`, `store.h` | PN↔LID map (learned from message attrs, usync, group participants), persisted; sessions/identities migrate to the LID address; DMs use the LID once known; unit-tested |
| `pair-code.go` | `paircode.c`, `cm_client_pair_phone` | written (PBKDF2/AES-CTR code wrap, key bundle, adv secret); untested vs. phone |
| `history_sync.go` | `history.c` | notification -> download/inline -> inflate -> decode; applies push names and PN/LID maps, emits `CM_EXT_HISTORY_SYNC`; written, untested vs. server |
| `tctoken.go` | `tctoken.c` | privacy tokens stored, attached to 1:1 sends, issued after send; written, untested |
| `msgsecret.go` | `msgsecret.h` | derive/encrypt/decrypt for poll votes, event responses, enc reactions/comments; caller supplies the message secret |
| `user.go` business | `cm_client_get_business_profile` | written, untested |
| `qrchan` | `client.c` | QR codes emitted one at a time (60 s, then 20 s), `CM_EVT_QR_TIMEOUT` when exhausted |
| newsletters (w:mex GraphQL query ids), reporting token (field whitelist), `cstoken` | - | not ported: need values captured from a live client |

## Dependencies

- OpenSSL 3.3.x, linked statically, **not vendored**: pass `OPENSSL_DIR=` (a
  build/install tree with `include/` and `libssl.a`/`libcrypto.a`).
- zlib.
- Vendored in `third_party/`: libsignal-protocol-c (GPLv3), protobuf-c runtime
  (BSD), wslay 1.1.1 (MIT) with a hand-written `config.h`.

## Licensing

cmeow's own code keeps whatsmeow's MPL-2.0. Because it links
libsignal-protocol-c (GPLv3), the combined library, and apps linking it,
must be distributed under GPLv3-compatible open-source terms. This was
accepted for this project.

## Build and test

    make OPENSSL_DIR=/path/to/openssl    # build/libcmeow.a
    make test OPENSSL_DIR=...            # self-contained tests, plain C, no other toolchain
    make test SAN="-fsanitize=address,undefined -g -O1" ...   # optional, gcc >= 4.8 / clang only

BlackBerry 10 (bbndk, gcc 4.6): set the cross compiler and archiver from the NDK environment, and the
link libraries for QNX, e.g. `make CC=qcc AR=ntoarmv7-ar CFLAGS="-Vgcc_ntoarmv7le -O2"
SYSLIBS="-lz -lsocket" OPENSSL_DIR=...` (adjust the names to your NDK; `make` itself only needs
`CC`, `AR`, `CFLAGS`). The tests link the whole library plus `SYSLIBS`; `libcmeow.a` itself has no
extra requirements besides your static OpenSSL and zlib.

Tests: `test_binary` (codec), `test_crypto` (primitives vs. RFC vectors, frame
parser at many chunk sizes, Noise), `test_handshake` (mock server, every cert
rejection path), `test_conn` (forked mock server over a socketpair: websocket
upgrade, Noise handshake, encrypted echo of small and 300 KB messages, close,
bad certificate root, non-websocket peer, silent peer).

Also `test_client` (login flow against a scripted server; Signal session
round trip and persistence through the store glue).

**Not verified:** a live connection to WhatsApp, XEdDSA verification of the
real certificate chain (the egress proxy here cannot reach WhatsApp), pairing
(QR and phone code), and every send/receive/group/media/app-state/history path
against a real server. The tests above use scripted peers, loopback servers and
unit-level checks only. `account` stores the self-signed device identity
(without account signature key), which is all whatsmeow ever sends.

## Non-C items (development time only)

- `make protos` uses protoc / protoc-gen-c (C++) at development time only; the
  generated C is committed, so building cmeow needs neither.

## Compiler compatibility

Written for gcc 4.6 (BlackBerry 10 NDK): strict `-std=c99 -Wall -Wextra
-Wpedantic -Wshadow -Wconversion -Wdeclaration-after-statement` is clean on
gcc 13, and no C11 features or post-4.6 builtins are used. **gcc 4.6 itself was
not available here, so this is an audit, not a build.** The generated protobuf
code uses anonymous unions for oneofs (a GNU extension that gcc 4.6 accepts),
so `src/proto` and vendored code are built without `-pedantic`.
`net.c` uses POSIX sockets (`getaddrinfo`, `poll`), which QNX provides.

## Deviations from the Go behaviour

- Strings containing NUL bytes are rejected on decode; C strings cannot hold them.
- Decoder nesting (256) and zlib output (128 MiB) are capped; Go has no limits.
- Inputs that panic the Go code return errors instead.
- The encoder returns `CM_ERR_TOO_LARGE` for lists that do not fit a 16-bit size
  instead of truncating.
- `Node.Content`/attribute values are the tagged union `cm_value`. Attribute
  order is insertion order.
- Concurrency: goroutines are replaced by one poll-driven loop
  (`cm_conn_pump`); callers drive it.

## Layout

    include/         public headers (include them as "client.h", "messaging.h", ...)
    src/             library sources (client.c, message.c, prekeys.c, store.c, ...) (tokens_gen.c generated by tools/gen_tokens.c)
    src/proto/       generated protobuf-c code
    third_party/     libsignal-protocol-c, protobuf-c, wslay
    tests/           test suite
    tools/           token table generator (C; reads whatsmeow's token.go as data, output committed)

## Known limitations

- Never run against a live WhatsApp server; protocol details were ported from the Go source.
- Media/HTTP transfers and blocking helpers pump the socket inline, so keepalives can lapse on very long transfers.
- No newsletters, reporting tokens or FB/Messenger transports (they need data that has to be captured from a live client).
- gcc 4.6 compatibility was audited by hand only (built here with a newer gcc under strict C99 flags).
