/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INAS_MAX_SHARES 9

typedef struct inas_smb_share {
        const char *name;
        const char *root_path;
} inas_smb_share;

typedef struct inas_smb_config {
        const char *username;
        const char *password;
        const char *hostname;
        const char *bind_ip;
        uint16_t port;
        const uint16_t *try_ports;
        int try_port_count;
        int share_count;
        const inas_smb_share *shares;
} inas_smb_config;

/* Bind and serve on a background thread. Returns 0 or -errno. */
int inas_smb_start(const inas_smb_config *config);

void inas_smb_stop(void);

int inas_smb_is_running(void);

int inas_smb_bound_port(void);

int inas_smb_client_count(void);

uint64_t inas_smb_bytes_transferred(void);

int inas_smb_auth_stats(int *peer_count, int *locked_count);

int inas_smb_auth_global_locked(void);

#ifdef __cplusplus
}
#endif
