/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy absolute-path resolver, retained only for unit tests of the
 * component validation rules (PathSandboxTests / PathSandbox.swift).
 * The server uses inas_path_resolve_at() exclusively.
 */
int inas_path_resolve(const char *root, const char *smb_name, char *out, size_t out_len);

typedef struct inas_path {
        int dirfd;
        char name[256];
} inas_path;

/* Walk `smb_name` from `rootfd` with openat(O_NOFOLLOW|O_DIRECTORY).
 * On success `out->dirfd` is a directory fd the caller owns (inas_path_release).
 * `out->name` is the final component, or empty if the path is the directory itself.
 */
int inas_path_resolve_at(int rootfd, const char *smb_name, inas_path *out);

void inas_path_release(inas_path *p);

#ifdef __cplusplus
}
#endif
