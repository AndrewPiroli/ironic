/*
 * Ironic - C IPC interface - Endianness handling
 *
 * Copyright (C) 2026 Techflash
 *
 * Based on code from libppcemu:
 * Copyright (C) 2026 Techflash
 *
 * Based on code from EverythingNet:
 * Copyright (C) 2025 Techflah
 */

#include <stdio.h>
#include <stdint.h>

#ifndef _CRONIC_ENDIAN_H
#define _CRONIC_ENDIAN_H

#if defined(__has_builtin)
#  if __has_builtin(__builtin_bswap16)
#    define NO_CUSTOM_SWAP16
#  endif
#  if __has_builtin(__builtin_bswap32)
#    define NO_CUSTOM_SWAP32
#  endif
#  if __has_builtin(__builtin_bswap64)
#    define NO_CUSTOM_SWAP64
#  endif
#endif

#ifdef NO_CUSTOM_SWAP16
#  define __cronic_swap16 __builtin_bswap16
#  undef NO_CUSTOM_SWAP16
#else
static inline uint16_t __cronic_swap16(uint16_t in) {
	return (uint16_t)((in << 8) | (in >> 8));
}
#endif

#ifdef NO_CUSTOM_SWAP32
#  define __cronic_swap32 __builtin_bswap32
#  undef NO_CUSTOM_SWAP32
#else
static inline uint32_t __cronic_swap32(uint32_t in) {
	return (uint32_t)(
		(__cronic_swap16((uint16_t)in) << 16) |
		(__cronic_swap16((uint16_t)(in >> 16)))
	);
}
#endif

#ifdef NO_CUSTOM_SWAP64
#  define __cronic_swap64 __builtin_bswap64
#  undef NO_CUSTOM_SWAP64
#else
static inline uint64_t __cronic_swap32(uint64_t in) {
	return (uint64_t)(
		(__cronic_swap32((uint32_t)in) << 32) |
		(__cronic_swap32((uint32_t)(in >> 32)))
	);
}
#endif

/* In order of accuracy:
 * - We have __BYTE_ORDER__ and __ORDER_LITTLER_ENDIAN__, and they are equal?
 * - __LITTLE_ENDIAN__ or __LITTLE_ENDIAN are defined?
 *
 * And the reverse of the above for BE:
 * - We have __BYTE_ORDER__ and __ORDER_BIG_ENDIAN__, and they are equal?
 * - __BIG_ENDIAN__ or __BIG_ENDIAN are defined?
 */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#  if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    define CRONIC_CPU_IS_LE 1
#  elif defined(__ORDER_BIG_ENDIAN__)
#    if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define CRONIC_CPU_IS_BE 1
#    endif
#  endif
#elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN)
#  define CRONIC_CPU_IS_BE 1
#elif defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN)
#  define CRONIC_CPU_IS_LE 1
#else
#  error "Unable to determine endianness for this platform, or endianness is neither big nor little"
#endif

#if defined(CRONIC_CPU_IS_BE)
/* to/from host endianness */
#  define cronic_cpu_to_le64(x)  __cronic_swap64(x)
#  define cronic_cpu_to_le32(x)  __cronic_swap32(x)
#  define cronic_cpu_to_le16(x)  __cronic_swap16(x)
#  define cronic_cpu_to_be64(x)  x
#  define cronic_cpu_to_be32(x)  x
#  define cronic_cpu_to_be16(x)  x
#  define cronic_le64_to_cpu(x)  __cronic_swap64(x)
#  define cronic_le32_to_cpu(x)  __cronic_swap32(x)
#  define cronic_le16_to_cpu(x)  __cronic_swap16(x)
#  define cronic_be64_to_cpu(x)  x
#  define cronic_be32_to_cpu(x)  x
#  define cronic_be16_to_cpu(x)  x

/* to/from specific endianness */
#  define cronic_be64_to_le64(x) __cronic_swap64(x)
#  define cronic_be32_to_le32(x) __cronic_swap32(x)
#  define cronic_be16_to_le16(x) __cronic_swap16(x)
#  define cronic_le64_to_be64(x) __cronic_swap64(x)
#  define cronic_le32_to_be32(x) __cronic_swap32(x)
#  define cronic_le16_to_be16(x) __cronic_swap16(x)
#elif defined(CRONIC_CPU_IS_LE)
/* to/from host endianness */
#  define cronic_cpu_to_le64(x)  x
#  define cronic_cpu_to_le32(x)  x
#  define cronic_cpu_to_le16(x)  x
#  define cronic_cpu_to_be64(x)  __cronic_swap64(x)
#  define cronic_cpu_to_be32(x)  __cronic_swap32(x)
#  define cronic_cpu_to_be16(x)  __cronic_swap16(x)
#  define cronic_le64_to_cpu(x)  x
#  define cronic_le32_to_cpu(x)  x
#  define cronic_le16_to_cpu(x)  x
#  define cronic_be64_to_cpu(x)  __cronic_swap64(x)
#  define cronic_be32_to_cpu(x)  __cronic_swap32(x)
#  define cronic_be16_to_cpu(x)  __cronic_swap16(x)

/* to/from specific endianness */
#  define cronic_be64_to_le64(x) __cronic_swap64(x)
#  define cronic_be32_to_le32(x) __cronic_swap32(x)
#  define cronic_be16_to_le16(x) __cronic_swap16(x)
#  define cronic_le64_to_be64(x) __cronic_swap64(x)
#  define cronic_le32_to_be32(x) __cronic_swap32(x)
#  define cronic_le16_to_be16(x) __cronic_swap16(x)
#else
#  error "Unexpected endianness"
#endif

#endif /* _CRONIC_ENDIAN_H */
