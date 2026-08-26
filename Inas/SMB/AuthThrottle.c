/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#include "AuthThrottle.h"

#include <string.h>

int inas_auth_is_locked(const inas_auth_slot *slot, time_t now)
{
        if (!slot || slot->ip == 0) {
                return 0;
        }
        return slot->locked_until > now;
}

int inas_auth_on_failure(inas_auth_slot *slot, time_t now)
{
        if (!slot) {
                return 0;
        }
        if (slot->locked_until > now) {
                slot->last_used = now;
                return 1;
        }
        if (slot->window_start == 0 || now - slot->window_start >= INAS_AUTH_WINDOW_SEC) {
                slot->window_start = now;
                slot->fails = 0;
        }
        slot->fails++;
        slot->last_used = now;
        if (slot->fails > INAS_AUTH_MAX_FAIL) {
                slot->locked_until = now + INAS_AUTH_LOCK_SEC;
                return 1;
        }
        return 0;
}

void inas_auth_on_success(inas_auth_slot *slot)
{
        if (!slot) {
                return;
        }
        slot->fails = 0;
        slot->window_start = 0;
        slot->locked_until = 0;
}

inas_auth_slot *inas_auth_lookup(inas_auth_slot *table, int n, uint32_t ip, time_t now)
{
        inas_auth_slot *empty = NULL;
        inas_auth_slot *oldest = NULL;
        int i;

        if (!table || n <= 0 || ip == 0) {
                return NULL;
        }
        for (i = 0; i < n; i++) {
                if (table[i].ip == ip) {
                        table[i].last_used = now;
                        return &table[i];
                }
                if (table[i].ip == 0) {
                        if (!empty) {
                                empty = &table[i];
                        }
                } else if (!oldest || table[i].last_used < oldest->last_used) {
                        oldest = &table[i];
                }
        }
        if (!empty) {
                empty = oldest;
        }
        if (!empty) {
                return NULL;
        }
        memset(empty, 0, sizeof(*empty));
        empty->ip = ip;
        empty->last_used = now;
        return empty;
}
