/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal IPC$ srvsvc: DCE/RPC bind_ack + NetrShareEnum levels 0/1. */
int inas_srvsvc_process(const uint8_t *req, size_t req_len, const char *const *names,
                        int name_count, uint8_t **out, size_t *out_len);

size_t inas_srvsvc_build_bind(uint8_t *buf, size_t cap, uint32_t call_id);
size_t inas_srvsvc_build_enum(uint8_t *buf, size_t cap, uint32_t call_id, uint32_t level);
int inas_srvsvc_enum_has_share(const uint8_t *rep, size_t len, const char *name);

#ifdef __cplusplus
}
#endif
