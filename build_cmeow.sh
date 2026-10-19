#!/bin/bash
# Builds and installs cmeow for BlackBerry 10 with the bbndk toolchain (armv7 device + x86 simulator),
# next to the OpenSSL/zlib/curl libraries built by the matching scripts:
#   $BASE_DIR/openssl/$ARCH, $BASE_DIR/zlib/$ARCH  ->  $BASE_DIR/cmeow/$ARCH/{include,lib}
# The bbndk environment (qcc, ntoarm-ar, ...) must be on PATH. The Makefile itself is
# platform-neutral; other platforms just call make with their own CC/AR/OPENSSL_DIR/ZLIB_DIR.
set -e

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="${BASE_DIR:-/root/bb10/libraries}"

for ARCH in armv7 x86; do
    if [ "$ARCH" = "armv7" ]; then
        CC="qcc -Vgcc_ntoarmv7le"
        AR="ntoarm-ar"
        RANLIB="ntoarm-ranlib"
    else
        CC="qcc -Vgcc_ntox86"
        AR="ntox86-ar"
        RANLIB="ntox86-ranlib"
    fi

    PREFIX="$BASE_DIR/cmeow/$ARCH"
    mkdir -p "$PREFIX"

    make -C "$SRC_DIR" \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-O2" \
        OPENSSL_DIR="$BASE_DIR/openssl/$ARCH" \
        ZLIB_DIR="$BASE_DIR/zlib/$ARCH" \
        BUILD="$SRC_DIR/build/$ARCH" \
        PREFIX="$PREFIX" \
        clean install
done
