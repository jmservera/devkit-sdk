
/*(Copyright)

Microsoft Copyright 2015, 2016
Confidential Information

*/
#ifndef _RIOT_CORE_H
#define _RIOT_CORE_H

#include <stdint.h>
#include "Riot.h"
#include "RiotDerEnc.h"
#include "RiotX509Bldr.h"

#define RIoTCore __attribute__((section(".riot_core")))

static bool __attribute__((section(".riot_core"))) RiotCore_Remediate(RIOT_STATUS status);
void __attribute__((section(".riot_core"))) RiotStart(const uint8_t  *CDI, const uint16_t  CDILen);

#define Riot_Remediate(SM, ERR)     \
    if (SM##_Remediate(ERR)) {      \
        return;                     \
    }
#endif
