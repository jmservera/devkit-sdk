/*(Copyright)

Microsoft Copyright 2015, 2016
Confidential Information

*/
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define DER_MAX_PEM     0x400
#define DER_MAX_TBS     0x300
#define DER_MAX_NESTED  0x10

//
// Context structure for the DER-encoder. This structure contains a fixed-
// length array for nested SEQUENCES (which imposes a nesting limit).
// The buffer use for encoded data is caller-allocted.
//
typedef struct
{
    uint8_t     *Buffer;        // Encoded data
    uint32_t     Length;        // Size, in bytes, of Buffer
    uint32_t     Position;      // Current buffer position

    // SETS, SEQUENCES, etc. can be nested. This array contains the start of
    // the payload for collection types and is set by  DERStartSequenceOrSet().
    // Collections are "popped" using DEREndSequenceOrSet().
    int CollectionStart[DER_MAX_NESTED];
    int CollectionPos;
} DERBuilderContext;

// We only have a small subset of potential PEM encodings
enum CertType {
    CERT_TYPE = 0,
    PUBLICKEY_TYPE,
    ECC_PRIVATEKEY_TYPE,
    CERT_REQ_TYPE,
    LAST_CERT_TYPE
};

typedef struct
{
    uint16_t     hLen;
    uint16_t     fLen;
    const char  *header;
    const char  *footer;
} PEMHeadersFooters;

void
__attribute__((section(".riot_core")))
DERInitContext(
    DERBuilderContext   *Context,
    uint8_t             *Buffer,
    uint32_t             Length
);

int
__attribute__((section(".riot_core")))
DERGetEncodedLength(
    DERBuilderContext   *Context
);


int
__attribute__((section(".riot_core")))
DERAddOID(
    DERBuilderContext   *Context,
    int                 *Values
);

int
__attribute__((section(".riot_core")))
DERAddUTF8String(
    DERBuilderContext   *Context,
    const char          *Str
);

int
__attribute__((section(".riot_core")))
DERAddPrintableString(
    DERBuilderContext   *Context,
    const char          *Str
);


int
__attribute__((section(".riot_core")))
DERAddUTCTime(
    DERBuilderContext   *Context,
    const char          *Str
);

int
__attribute__((section(".riot_core")))
DERAddIntegerFromArray(
    DERBuilderContext   *Context,
    uint8_t             *Val,
    uint32_t            NumBytes
);

int
__attribute__((section(".riot_core")))
DERAddInteger(
    DERBuilderContext   *Context,
    int                 Val
);

int
__attribute__((section(".riot_core")))
DERAddShortExplicitInteger(
    DERBuilderContext   *Context,
    int                  Val
);

int
__attribute__((section(".riot_core")))
DERAddBoolean(
    DERBuilderContext   *Context,
    bool                 Val
);


int
__attribute__((section(".riot_core")))
DERAddBitString(
    DERBuilderContext   *Context,
    uint8_t             *BitString,
    uint32_t             BitStringNumBytes
);

int
__attribute__((section(".riot_core")))
DERAddOctetString(
    DERBuilderContext   *Context,
    uint8_t             *OctetString,
    uint32_t             OctetStringLen
);

int
__attribute__((section(".riot_core")))
DERStartSequenceOrSet(
    DERBuilderContext   *Context,
    bool                 Sequence
);

int
__attribute__((section(".riot_core")))
DERStartExplicit(
    DERBuilderContext   *Context,
    uint32_t             Num
);

int
__attribute__((section(".riot_core")))
DERStartEnvelopingOctetString(
    DERBuilderContext   *Context
);

int
__attribute__((section(".riot_core")))
DERStartEnvelopingBitString(
    DERBuilderContext   *Context
);

int
__attribute__((section(".riot_core")))
DERPopNesting(
    DERBuilderContext   *Context
);

int
__attribute__((section(".riot_core")))
DERGetNestingDepth(
    DERBuilderContext   *Context
);

int
__attribute__((section(".riot_core")))
DERTbsToCert(
    DERBuilderContext   *Context
);

int
__attribute__((section(".riot_core")))
DERtoPEM(
    DERBuilderContext   *Context,
    uint32_t            Type,
    char                *PEM,
    uint32_t            *Length
);

#ifdef __cplusplus
}
#endif
