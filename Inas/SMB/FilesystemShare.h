/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct inas_smb_config {
        const char *root_path;
        const char *share_name;
        const char *username;
        const char *password;
        const char *hostname;
        uint16_t port;
} inas_smb_config;

/* Bind and serve on a background thread. Returns 0 or -errno. */
int inas_smb_start(const inas_smb_config *config);

void inas_smb_stop(void);

int inas_smb_is_running(void);

int inas_smb_bound_port(void);

int inas_smb_client_count(void);

uint64_t inas_smb_bytes_transferred(void);

#ifdef __cplusplus
}
#endif
