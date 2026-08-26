/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INAS_AUTH_WINDOW_SEC 60
#define INAS_AUTH_MAX_FAIL 10
#define INAS_AUTH_LOCK_SEC 300
#define INAS_AUTH_PEERS 64

typedef struct inas_auth_slot {
        uint32_t ip;
        unsigned fails;
        time_t window_start;
        time_t locked_until;
        time_t last_used;
} inas_auth_slot;

int inas_auth_is_locked(const inas_auth_slot *slot, time_t now);

/* Record a failure. Returns 1 if the peer is locked after this failure. */
int inas_auth_on_failure(inas_auth_slot *slot, time_t now);

void inas_auth_on_success(inas_auth_slot *slot);

inas_auth_slot *inas_auth_lookup(inas_auth_slot *table, int n, uint32_t ip, time_t now);

#ifdef __cplusplus
}
#endif
