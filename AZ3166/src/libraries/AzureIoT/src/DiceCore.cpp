/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/

#include "DiceCore.h"
#include "DiceSha256.h"
#include <stdio.h>
//#include "stm32f4xx_hal.h"
//#include "stm32f4xx_nucleo.h"

// Protected data
extern DICE_UDS             DiceUDS;                        // NV
extern DICE_CMPND_ID        DiceCDI;                        // V
extern DICE_SHA256_CONTEXT  DiceHashCtx;                    // V
extern uint8_t              vDigest[DICE_DIGEST_LENGTH];    // V
extern uint8_t              rDigest[DICE_DIGEST_LENGTH];    // V
extern void* __start_riot_core;
extern void* __stop_riot_core;

// Non-protected data
extern DICE_DATA            DiceData;

// Prototypes
static uint32_t _DiceMeasure(uint8_t *data, size_t dataSize, uint8_t *digest, size_t digestSize);
static uint32_t _DiceDeriveCDI(uint8_t *digest, size_t digestLen);

static void _DiceSha256Init(void);
static void _DiceSha256Transform(const sha2_word32 *);
static void _DiceSha256Update(const sha2_uint8_t *data, size_t len);
static void _DiceSha256Final(sha2_uint8_t *digest);
static void _DiceSha256Block(const uint8_t *buf, size_t bufSize, uint8_t *digest);
static void _DiceSha256Block2(const uint8_t *buf1, size_t bufSize1, const uint8_t *buf2, size_t bufSize2, uint8_t *digest);

static void _BZERO(void *p, uint32_t l);
static void _MEMCPY(void *d, const void *s, uint32_t l);

// Functions

void
DiceCore(
    void
)
{
    // Disable FW PreArm in protected code
	//__HAL_FIREWALL_PREARM_DISABLE();
	
    // Compute digest of RIoT Core
    if (_DiceMeasure(DiceData.riotCore, DiceData.riotSize, rDigest, DICE_DIGEST_LENGTH)) {
        // Enter remediation
        goto Remediate;
    }
    (void)printf("#DEBUG: func: %s, file: %s, line: %d, rDigest[0]=%x.\r\n", __FUNCTION__, __FILE__, __LINE__, rDigest[0]);
		
    // Derive CDI based on measurement of RIoT Core and UDS.
   if (_DiceDeriveCDI(rDigest, DICE_DIGEST_LENGTH)) {
       // Enter remediation
       goto Remediate;
   }

    // Clean up potentially sensative data
    _BZERO(vDigest, DICE_DIGEST_LENGTH);
    _BZERO(rDigest, DICE_DIGEST_LENGTH);
    _BZERO(&DiceHashCtx, sizeof(DiceHashCtx));

    // The CDI is ready and UDS digest is cleaned up.
    // Enable shared access to volatile data.
    //__HAL_FIREWALL_VOLATILEDATA_SHARED_ENABLE();

    // Set FPA bit for proper FW closure when exiting protected code
    //__HAL_FIREWALL_PREARM_ENABLE();

    // We're done.
    return;

Remediate:
    // Set FPA bit for proper FW closure when exiting protected code
    //__HAL_FIREWALL_PREARM_ENABLE();

    // Access to volatile data outside protected code is our indication
    // of success.  We will enter remediation upon return from DiceCore.
    return;
}

static uint32_t
_DiceMeasure(
    uint8_t    *data,
    size_t      dataSize,
    uint8_t    *digest,
    size_t      digestSize
)
{
    // Validate parameters
    if ((!data) || (dataSize < (2 * sizeof(uint32_t))) ||
        (!digest) || (digestSize != DICE_DIGEST_LENGTH)) {
        // Remediation
        return 1;
    }

    // Measure data area
    _DiceSha256Block(data, dataSize, digest);

    // Success
    return 0;
}

static uint32_t
_DiceDeriveCDI(
    uint8_t    *digest,
    size_t      digestSize
)
{
    // Validate parameter
    if (!(digest) || (digestSize != DICE_DIGEST_LENGTH)) {
        // Remediate
        goto Error;
    }

    // Don't use the UDS directly.
    _DiceSha256Block(DiceUDS.bytes, DICE_UDS_LENGTH, vDigest);

    // Derive CDI value based on UDS and RIoT Core measurement
    _DiceSha256Block2(vDigest, DICE_DIGEST_LENGTH,
                      rDigest, DICE_DIGEST_LENGTH,
                      DiceCDI.bytes);

    (void)printf("DiceCDI bytes: ");
    for (int i = 0; i < 32; i++){
        (void)printf("%x ", DiceCDI.bytes[i]);
    }
    (void)printf("\r\n");
    // Success
    return 0;

Error:
    // Failure
    return 1;
}


//
// DICE SHA256
//

#define HOST_IS_LITTLE_ENDIAN   1
#define ALIGNED_ACCESS_REQUIRED 1

#if !defined(BYTE_ORDER) || ((BYTE_ORDER != LITTLE_ENDIAN) && (BYTE_ORDER != BIG_ENDIAN))
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321
#if HOST_IS_LITTLE_ENDIAN
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif

#define SHA256_SHORT_BLOCK_LENGTH   (SHA256_BLOCK_LENGTH - 8)

#if BYTE_ORDER == LITTLE_ENDIAN
#if !defined(ALIGNED_ACCESS_REQUIRED)
#define REVERSE32(w,x)  { \
    sha2_word32 tmp = (w); \
    tmp = (tmp >> 16) | (tmp << 16); \
    (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}
#else
#define REVERSE32(w,x) { \
    sha2_uint8_t *b = (sha2_uint8_t*) &w; \
    sha2_word32 tmp = 0; \
    tmp = ((sha2_word32)*b++); \
    tmp = (tmp << 8) | ((sha2_word32)*b++); \
    tmp = (tmp << 8) | ((sha2_word32)*b++); \
    tmp = (tmp << 8) | ((sha2_word32)*b++); \
    (x) = tmp; \
}
#endif

#define REVERSE64(w,x)  { \
    sha2_word64 tmp = (w); \
    tmp = (tmp >> 32) | (tmp << 32); \
    tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | \
          ((tmp & 0x00ff00ff00ff00ffULL) << 8); \
    (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
          ((tmp & 0x0000ffff0000ffffULL) << 16); \
}
#endif

#define ADDINC128(w,n)  { \
    (w)[0] += (sha2_word64)(n); \
    if ((w)[0] < (n)) { \
        (w)[1]++; \
    } \
}

#define R(b,x)      ((x) >> (b))
#define S32(b,x)    (((x) >> (b)) | ((x) << (32 - (b))))
#define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0_256(x)   (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x)   (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x)   (S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))
#define sigma1_256(x)   (S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

static const sha2_word32 dK256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static const sha2_word32 _DiceSha256InitialHashValue[8] = {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

static void _BZERO(void *p, uint32_t l)
{
    int i;
    for (i = 0; i < (l); i++) {
        ((uint8_t*)p)[i] = 0;
    }
}

static void _MEMCPY(void *d, const void *s, uint32_t l)
{
    int i;
    for (i = 0; i < (l); i++) {
        ((uint8_t*)d)[i] = ((uint8_t*)s)[i];
    }
}

static void _DiceSha256Init(void)
{
    DiceHashCtx.magic = HASH_MAGIC_VALUE;
    _MEMCPY(DiceHashCtx.state, _DiceSha256InitialHashValue, SHA256_DIGEST_LENGTH);
    _BZERO(DiceHashCtx.buffer, SHA256_BLOCK_LENGTH);
    DiceHashCtx.bitcount = 0;
}

static void _DiceSha256Transform(const sha2_word32 *data)
{
    sha2_word32 a, b, c, d, e, f, g, h, s0, s1;
    sha2_word32 T1, T2, *W256;
    int j;

    W256 = (sha2_word32 *)DiceHashCtx.buffer;
	
    a = DiceHashCtx.state[0];
    b = DiceHashCtx.state[1];
    c = DiceHashCtx.state[2];
    d = DiceHashCtx.state[3];
    e = DiceHashCtx.state[4];
    f = DiceHashCtx.state[5];
    g = DiceHashCtx.state[6];
    h = DiceHashCtx.state[7];
	
    j = 0;

    do {
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Copy data while converting to host uint8_t order */
        REVERSE32(*data++, W256[j]);
        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + dK256[j] + W256[j];
#else /* BYTE_ORDER == LITTLE_ENDIAN */
        /* Apply the SHA-256 compression function to update a..h with copy */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + dK256[j] + (W256[j] = *data++);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W256[(j + 1) & 0x0f];
        s0 = sigma0_256(s0);
        s1 = W256[(j + 14) & 0x0f];
        s1 = sigma1_256(s1);

  			/* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + dK256[j] +
            (W256[j & 0x0f] += s1 + W256[(j + 9) & 0x0f] + s0);
			
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;

    } while (j < 64);

    /* Compute the current intermediate hash value */
    DiceHashCtx.state[0] += a;
    DiceHashCtx.state[1] += b;
    DiceHashCtx.state[2] += c;
    DiceHashCtx.state[3] += d;
    DiceHashCtx.state[4] += e;
    DiceHashCtx.state[5] += f;
    DiceHashCtx.state[6] += g;
    DiceHashCtx.state[7] += h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

static void _DiceSha256Update(const sha2_uint8_t *data, size_t len)
{
    unsigned int    freespace, usedspace;

    if (len == 0) {
        /* Calling with no data is valid - we do nothing */
        return;
    }

    usedspace = (DiceHashCtx.bitcount >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA256_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            _MEMCPY(&DiceHashCtx.buffer[usedspace], data, freespace);
            DiceHashCtx.bitcount += freespace << 3;
            len -= freespace;
            data += freespace;
            _DiceSha256Transform((sha2_word32 *)DiceHashCtx.buffer);
        }
        else {
            /* The buffer is not yet full */
            _MEMCPY(&DiceHashCtx.buffer[usedspace], data, len);
            DiceHashCtx.bitcount += len << 3;
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA256_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        _DiceSha256Transform((sha2_word32 *)data);
        DiceHashCtx.bitcount += SHA256_BLOCK_LENGTH << 3;
        len -= SHA256_BLOCK_LENGTH;
        data += SHA256_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        _MEMCPY(DiceHashCtx.buffer, data, len);
        DiceHashCtx.bitcount += len << 3;
    }
    /* Clean up: */
    usedspace = freespace = 0;
}

static void _DiceSha256Final(sha2_uint8_t *digest)
{
    sha2_word32 *d = (sha2_word32 *)digest;
    unsigned int    usedspace;

    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != (sha2_uint8_t *)0) {
        usedspace = (DiceHashCtx.bitcount >> 3) % SHA256_BLOCK_LENGTH;
#if BYTE_ORDER == LITTLE_ENDIAN
        /* Convert FROM host uint8_t order */
        REVERSE64(DiceHashCtx.bitcount, DiceHashCtx.bitcount);
#endif
        if (usedspace > 0) {
            /* Begin padding with a 1 bit: */
            DiceHashCtx.buffer[usedspace++] = 0x80;

            if (usedspace <= SHA256_SHORT_BLOCK_LENGTH) {
                /* Set-up for the last transform: */
                _BZERO(&DiceHashCtx.buffer[usedspace], SHA256_SHORT_BLOCK_LENGTH - usedspace);
            }
            else {
                if (usedspace < SHA256_BLOCK_LENGTH) {
                    _BZERO(&DiceHashCtx.buffer[usedspace], SHA256_BLOCK_LENGTH - usedspace);
                }
                /* Do second-to-last transform: */
                _DiceSha256Transform((sha2_word32 *)DiceHashCtx.buffer);

                /* And set-up for the last transform: */
                _BZERO(DiceHashCtx.buffer, SHA256_SHORT_BLOCK_LENGTH);
            }
        }
        else {
            /* Set-up for the last transform: */
            _BZERO(DiceHashCtx.buffer, SHA256_SHORT_BLOCK_LENGTH);

            /* Begin padding with a 1 bit: */
            *DiceHashCtx.buffer = 0x80;
        }
        /* Set the bit count: */
        *(sha2_word64 *)&DiceHashCtx.buffer[SHA256_SHORT_BLOCK_LENGTH] = DiceHashCtx.bitcount;

        /* Final transform: */
        _DiceSha256Transform((sha2_word32 *)DiceHashCtx.buffer);

#if BYTE_ORDER == LITTLE_ENDIAN
        {
            /* Convert TO host uint8_t order */
            int j;
            for (j = 0; j < 8; j++) {
                REVERSE32(DiceHashCtx.state[j], DiceHashCtx.state[j]);
                *d++ = DiceHashCtx.state[j];
            }
        }
#else
        _MEMCPY(d, DiceHashCtx.state, SHA256_DIGEST_LENGTH);
#endif
    }

    /* Clean up state data: */
    _BZERO(&DiceHashCtx, sizeof(DICE_SHA256_CONTEXT));
    usedspace = 0;
}

static void _DiceSha256Block(const uint8_t *buf, size_t bufSize, uint8_t *digest)
{
    _DiceSha256Init();
    _DiceSha256Update(buf, bufSize);
    _DiceSha256Final(digest);
}

static void _DiceSha256Block2(const uint8_t *buf1, size_t bufSize1,
                              const uint8_t *buf2, size_t bufSize2,
                              uint8_t *digest)
{
    _DiceSha256Init();
    _DiceSha256Update(buf1, bufSize1);
    _DiceSha256Update(buf2, bufSize2);
    _DiceSha256Final(digest);
}


