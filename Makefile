# cmeow - C99 port of whatsmeow
#
# Targets:
#   make                build/libcmeow.a (cmeow + vendored libsignal-protocol-c,
#                       protobuf-c runtime and the generated whatsmeow protobufs)
#   make test           build and run the self-contained tests (SAN=... adds sanitizers on gcc >= 4.8)
#   make protos         regenerate src/proto/ (needs protoc + protoc-gen-c, dev only)
#   make tokens         regenerate src/tokens_gen.c from a whatsmeow checkout
#   make clean
#
# OpenSSL (3.3.x, static) is NOT vendored: point OPENSSL_DIR at a build/install
# tree containing include/ and libcrypto.a/libssl.a (a source tree that has been
# built in place works too).

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2

OPENSSL_DIR  ?= third_party/openssl
OPENSSL_INC  := -I$(OPENSSL_DIR)/include
OPENSSL_LIBS := $(firstword $(wildcard $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/lib/libssl.a)) \
                $(firstword $(wildcard $(OPENSSL_DIR)/libcrypto.a $(OPENSSL_DIR)/lib/libcrypto.a))
# Extra libraries for linking the tests. Override for your target, e.g. BlackBerry 10 (QNX) needs
# the socket library and has no separate libpthread/libdl:  SYSLIBS="-lz -lsocket"
SYSLIBS      ?= -lz -ldl -lpthread

# Our own code: strict.
CSTD    := -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
INCLUDE := -Iinclude -Ithird_party/libsignal -Ithird_party/protobuf-c -isystem src/proto -Ithird_party/wslay $(OPENSSL_INC)

# Vendored / generated code: C99, warnings left to upstream.
VENDOR_FLAGS := -std=c99 -w
VENDOR_INC   := -DHAVE_CONFIG_H -Ithird_party/wslay -Iinclude -Ithird_party/protobuf-c -Ithird_party/libsignal -isystem src/proto $(OPENSSL_INC)

CM_SRC := $(sort $(wildcard src/*.c))

LS_DIR := third_party/libsignal
LS_SRC := $(addprefix $(LS_DIR)/,vpool.c signal_protocol.c curve.c hkdf.c ratchet.c protocol.c \
          session_state.c session_record.c session_pre_key.c session_builder.c session_cipher.c \
          key_helper.c sender_key.c sender_key_state.c sender_key_record.c group_session_builder.c \
          group_cipher.c fingerprint.c device_consistency.c \
          FingerprintProtocol.pb-c.c LocalStorageProtocol.pb-c.c WhisperTextProtocol.pb-c.c \
          curve25519/curve25519-donna.c) \
          $(addprefix $(LS_DIR)/curve25519/ed25519/,fe_0.c fe_1.c fe_add.c fe_cmov.c fe_copy.c \
          fe_frombytes.c fe_invert.c fe_isnegative.c fe_isnonzero.c fe_mul.c fe_neg.c fe_pow22523.c \
          fe_sq.c fe_sq2.c fe_sub.c fe_tobytes.c ge_add.c ge_double_scalarmult.c ge_frombytes.c \
          ge_madd.c ge_msub.c ge_p1p1_to_p2.c ge_p1p1_to_p3.c ge_p2_0.c ge_p2_dbl.c ge_p3_0.c \
          ge_p3_dbl.c ge_p3_to_cached.c ge_p3_to_p2.c ge_p3_tobytes.c ge_precomp_0.c \
          ge_scalarmult_base.c ge_sub.c ge_tobytes.c open.c sc_muladd.c sc_reduce.c sign.c \
          nacl_sha512/blocks.c nacl_sha512/hash.c tests/internal_fast_tests.c) \
          $(addprefix $(LS_DIR)/curve25519/ed25519/additions/,compare.c curve_sigs.c elligator.c \
          fe_isequal.c fe_isreduced.c fe_mont_rhs.c fe_montx_to_edy.c fe_sqrt.c ge_isneutral.c \
          ge_montx_to_p3.c ge_neg.c ge_p3_to_montx.c ge_scalarmult.c ge_scalarmult_cofactor.c \
          keygen.c open_modified.c sc_clamp.c sc_cmov.c sc_neg.c sign_modified.c utility.c \
          xeddsa.c zeroize.c generalized/ge_p3_add.c generalized/gen_eddsa.c \
          generalized/gen_labelset.c generalized/gen_veddsa.c generalized/gen_x.c \
          generalized/point_isreduced.c generalized/sc_isreduced.c)
LS_INC := -I$(LS_DIR)/curve25519/ed25519/nacl_includes -I$(LS_DIR)/curve25519/ed25519/additions \
          -I$(LS_DIR)/curve25519/ed25519/additions/generalized -I$(LS_DIR)/curve25519/ed25519 \
          -I$(LS_DIR)/curve25519/ed25519/tests -I$(LS_DIR)/curve25519

WS_DIR := third_party/wslay
WS_SRC := $(addprefix $(WS_DIR)/,wslay_event.c wslay_frame.c wslay_net.c wslay_queue.c)

PBC_SRC   := third_party/protobuf-c/protobuf-c/protobuf-c.c
PROTO_SRC := $(sort $(wildcard src/proto/*/*.pb-c.c))

CM_OBJ    := $(CM_SRC:%.c=build/%.o)
VENDOR_OBJ:= $(LS_SRC:%.c=build/%.o) $(PBC_SRC:%.c=build/%.o) $(WS_SRC:%.c=build/%.o) $(PROTO_SRC:%.c=build/%.o)

# Sanitizers are optional (gcc 4.6 has none). Host build example:
#   make test SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
SAN ?=

all: build/libcmeow.a

build/src/%.o: src/%.c $(wildcard include/*.h)
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(CFLAGS) $(INCLUDE) -c $< -o $@

# the vendored libsignal needs its own include dirs; the generated protos and
# protobuf-c are C99 but use anonymous unions for oneofs (a GNU extension in
# gcc 4.6, standard C11), so they are compiled without -pedantic.
build/third_party/%.o: third_party/%.c
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_FLAGS) $(CFLAGS) $(VENDOR_INC) $(LS_INC) -c $< -o $@

build/src/proto/%.o: src/proto/%.c
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_FLAGS) -Os $(VENDOR_INC) -c $< -o $@

build/libcmeow.a: $(CM_OBJ) $(VENDOR_OBJ)
	$(AR) rcs $@ $^

# ---- tests (compile the library sources directly) ----
TEST_SRC := $(CM_SRC)

# Our code is rebuilt with $(SAN) if given; the vendored objects are linked as-is.
# every tests/test_*.c is a test program; a bare name on the command line works too
TEST_NAMES := $(basename $(notdir $(wildcard tests/test_*.c)))
TEST_BINS  := $(addprefix build/,$(TEST_NAMES))

build/test_%: tests/test_%.c $(wildcard tests/*.inc) $(TEST_SRC) $(VENDOR_OBJ)
	@mkdir -p build
	$(CC) $(CSTD) $(SAN) $(INCLUDE) -Itests -Isrc $< $(TEST_SRC) $(VENDOR_OBJ) -o $@ $(OPENSSL_LIBS) $(SYSLIBS)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "== $$t"; ./$$t || exit 1; done

# Dev-time only: needs protoc and protoc-gen-c (C++). The output is committed.
# usage: make protos WHATSMEOW=/path/to/whatsmeow
protos:
	rm -rf src/proto && mkdir -p src/proto
	cd $(WHATSMEOW)/proto && for f in */*.proto; do protoc -I. --c_out=$(CURDIR)/src/proto $$f || exit 1; done

build/gen_tokens: tools/gen_tokens.c
	@mkdir -p build
	$(CC) $(CSTD) $(CFLAGS) $< -o $@

tokens: build/gen_tokens
	build/gen_tokens $(WHATSMEOW)/binary/token/token.go src/tokens_gen.c

clean:
	rm -rf build

.PHONY: all test protos tokens clean
