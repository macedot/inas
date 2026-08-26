/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimum accepted dialect and preferred dialect. The C server copies
 * these into smb2_server.allowed_dialects so negotiate and tests share
 * one list.
 */
#define INAS_SMB_DIALECT_MIN 0x0302u
#define INAS_SMB_DIALECT_PREF 0x0311u

static inline int inas_smb_dialect_allowed(uint16_t dialect)
{
        return dialect == INAS_SMB_DIALECT_MIN || dialect == INAS_SMB_DIALECT_PREF;
}

#ifdef __cplusplus
}
#endif
