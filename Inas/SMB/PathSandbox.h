/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve an SMB path (backslash or slash separated) under `root`.
 * Rejects absolute paths, `..` components, and escapes outside root.
 * Writes a NUL-terminated POSIX path into `out`.
 * Returns 0 on success, -1 on rejection.
 */
int inas_path_resolve(const char *root, const char *smb_name, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif
