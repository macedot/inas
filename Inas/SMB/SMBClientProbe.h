/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if DEBUG

/* Connect with the given dialect (0 = ANY3). Returns 0 on success. */
int inas_smb_client_connect(const char *host, uint16_t port, const char *user, const char *password,
                            const char *share, uint16_t dialect, uint16_t *negotiated, char *err,
                            int errlen);

/* Create/write/read/list/rename/unlink plus a `..` traversal check. */
int inas_smb_client_roundtrip(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, char *err, int errlen);

/* Open + close `cycles` directory iterations over one connection to detect
 * server-side fd leaks. Returns 0 if every iteration succeeded. */
int inas_smb_client_dir_cycle(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, int cycles, char *err,
                              int errlen);

/* Open the same file `count` times without closing in between; returns the
 * number of successful opens (bounded by the server handle table). */
int inas_smb_client_open_many(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, int count, char *err,
                              int errlen);

/* Write `ok_len` bytes (must succeed), then a single raw WRITE of `big_len`
 * bytes (must be rejected). Returns 0 if both expectations hold. */
int inas_smb_client_write_bounds(const char *host, uint16_t port, const char *user,
                                 const char *password, const char *share, uint32_t ok_len,
                                 uint32_t big_len, char *err, int errlen);

/* After a sealed session, send a plaintext CREATE. Returns 0 if the server
 * drops the connection or rejects the PDU. */
int inas_smb_client_plaintext_after_session(const char *host, uint16_t port, const char *user,
                                            const char *password, const char *share, char *err,
                                            int errlen);

#endif /* DEBUG */

#ifdef __cplusplus
}
#endif
