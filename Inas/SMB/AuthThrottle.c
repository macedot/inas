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

int inas_auth_global_locked(const inas_auth_global *g, time_t now)
{
        if (!g) {
                return 0;
        }
        return g->backoff_until > now;
}

void inas_auth_global_record_failure(inas_auth_global *g, time_t now)
{
        unsigned backoff;
        unsigned shift;

        if (!g) {
                return;
        }
        if (g->backoff_until > now) {
                return;
        }
        if (g->window_start == 0 || now - g->window_start >= INAS_AUTH_GLOBAL_WINDOW_SEC) {
                g->window_start = now;
                g->fails = 0;
        }
        g->fails++;
        if (g->fails <= INAS_AUTH_GLOBAL_LIMIT) {
                return;
        }
        g->streak++;
        shift = g->streak - 1;
        if (shift >= 31u ||
            (INAS_AUTH_GLOBAL_BACKOFF_SEC << shift) > INAS_AUTH_GLOBAL_BACKOFF_CAP) {
                backoff = INAS_AUTH_GLOBAL_BACKOFF_CAP;
        } else {
                backoff = INAS_AUTH_GLOBAL_BACKOFF_SEC << shift;
        }
        g->backoff_until = now + (time_t)backoff;
        g->fails = 0;
        g->window_start = 0;
}

void inas_auth_global_record_success(inas_auth_global *g)
{
        if (!g) {
                return;
        }
        g->fails = 0;
        g->window_start = 0;
        g->backoff_until = 0;
        g->streak = 0;
}
