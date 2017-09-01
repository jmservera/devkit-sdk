#ifndef __DICE_CRYPTO_SHA256_H__
#define __DICE_CRYPTO_SHA256_H__

#include <stdint.h>

typedef int asb;

typedef uint8_t  sha2_uint8_t;  // Exactly 1 byte
typedef uint32_t sha2_word32;   // Exactly 4 bytes
typedef uint64_t sha2_word64;   // Exactly 8 bytes

#define SHA256_BLOCK_LENGTH         64
#define SHA256_DIGEST_LENGTH        32

typedef uint64_t hashMagic_t;

#if HOST_IS_LITTLE_ENDIAN
#define HASH_MAGIC_VALUE    (0x4078746368736168LL)
#else
#define HASH_MAGIC_VALUE    (0x6861736863747840LL)
#endif

typedef struct _DICE_SHA256_CONTEXT {
    uint32_t    state[8];
    hashMagic_t magic;
    uint64_t    bitcount;
    uint8_t     buffer[SHA256_BLOCK_LENGTH];
} DICE_SHA256_CONTEXT;

#endif

