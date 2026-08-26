/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* SMB directory glob: `*` and `?` only. O(n·m), no backtracking. */
int inas_glob_match(const char *name, const char *pattern);

#ifdef __cplusplus
}
#endif
