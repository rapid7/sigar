/*
 * Public domain
 * machine/endian.h compatibility shim
 */

#ifndef LIBCRYPTOCOMPAT_BYTE_ORDER_H_
#define LIBCRYPTOCOMPAT_BYTE_ORDER_H_

#if defined(_WIN32)

#define LITTLE_ENDIAN  1234
#define BIG_ENDIAN 4321
#define PDP_ENDIAN	3412

/*
 * Use GCC and Visual Studio compiler defines to determine endian.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif

#elif defined(__linux__)
#include <endian.h>

#elif defined(__sun) || defined(_AIX) || defined(__hpux)
#include <sys/types.h>
#include <arpa/nameser_compat.h>

#elif defined(__sgi)
#include <standards.h>
#include <sys/endian.h>

#else
#include_next <machine/endian.h>

#endif

#ifndef bswap_16
#define bswap_16(x) ((x) >> 8) | ((x) << 8)
#endif

#ifndef bswap_32
#define bswap_32(x) \
	(((x) >> 24) & 0xff) | \
	(((x) << 8) & 0xff0000) | \
	(((x) >> 8) & 0xff00) | \
	(((x)<<24) & 0xff000000)
#endif

#if !defined(le32toh)
#if BYTE_ORDER == LITTLE_ENDIAN
#define be16toh(x) bswap_16 (x)
#define le16toh(x) (x)
#define be32toh(x) bswap_32 (x)
#define le32toh(x) (x)
#else
#define be16toh(x) (x)
#define le16toh(x) bswap_16 (x)
#define be32toh(x) (x)
#define le32toh(x) bswap_32 (x)
#endif
#endif

#endif
