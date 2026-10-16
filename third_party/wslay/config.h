/* hand-written replacement for wslay's autoconf config.h (POSIX target) */
#ifndef WSLAY_CONFIG_H
#define WSLAY_CONFIG_H
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define WORDS_BIGENDIAN 1
#endif
#endif
