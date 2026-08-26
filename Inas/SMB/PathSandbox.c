/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#include "PathSandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef NAME_MAX
#define NAME_MAX 255
#endif

static int is_safe_component(const char *comp, size_t len)
{
        if (len == 0) {
                return 0;
        }
        if (len == 1 && comp[0] == '.') {
                return 1;
        }
        if (len == 2 && comp[0] == '.' && comp[1] == '.') {
                return 0;
        }
        if (len > NAME_MAX) {
                return 0;
        }
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)comp[i];
                if (c < 0x20 || c == 0x7F || c == '/' || c == '\\') {
                        return 0;
                }
        }
        return 1;
}

static int realpath_prefix_ok(const char *root_real, const char *candidate)
{
        size_t root_len = strlen(root_real);
        size_t cand_len = strlen(candidate);
        if (cand_len < root_len) {
                return 0;
        }
        if (strncmp(candidate, root_real, root_len) != 0) {
                return 0;
        }
        if (cand_len == root_len) {
                return 1;
        }
        return candidate[root_len] == '/';
}

void inas_path_release(inas_path *p)
{
        if (!p) {
                return;
        }
        if (p->dirfd >= 0) {
                close(p->dirfd);
        }
        p->dirfd = -1;
        p->name[0] = '\0';
}

int inas_path_resolve_at(int rootfd, const char *smb_name, inas_path *out)
{
        int dirfd;
        const char *name;
        const char *p;

        if (!out || rootfd < 0) {
                return -1;
        }
        memset(out, 0, sizeof(*out));
        out->dirfd = -1;

        dirfd = dup(rootfd);
        if (dirfd < 0) {
                return -1;
        }

        name = smb_name ? smb_name : "";
        while (*name == '\\' || *name == '/') {
                name++;
        }
        if (name[0] == '\0' || strcmp(name, ".") == 0) {
                out->dirfd = dirfd;
                out->name[0] = '\0';
                return 0;
        }

        p = name;
        while (*p) {
                const char *start = p;
                while (*p && *p != '\\' && *p != '/') {
                        p++;
                }
                size_t seglen = (size_t)(p - start);
                int last;
                while (*p == '\\' || *p == '/') {
                        p++;
                }
                last = (*p == '\0');
                if (seglen == 0) {
                        continue;
                }
                if (!is_safe_component(start, seglen)) {
                        close(dirfd);
                        return -1;
                }
                if (seglen == 1 && start[0] == '.') {
                        continue;
                }
                if (last) {
                        if (seglen >= sizeof(out->name)) {
                                close(dirfd);
                                return -1;
                        }
                        memcpy(out->name, start, seglen);
                        out->name[seglen] = '\0';
                        out->dirfd = dirfd;
                        return 0;
                }
                char component[NAME_MAX + 1];
                memcpy(component, start, seglen);
                component[seglen] = '\0';
                int next =
                    openat(dirfd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                close(dirfd);
                if (next < 0) {
                        return -1;
                }
                dirfd = next;
        }

        out->dirfd = dirfd;
        out->name[0] = '\0';
        return 0;
}

int inas_path_resolve(const char *root, const char *smb_name, char *out, size_t out_len)
{
        char root_real[PATH_MAX];
        char built[PATH_MAX];
        char parent_real[PATH_MAX];
        char tmp[PATH_MAX];
        const char *name;
        size_t built_len;

        if (!root || !out || out_len < 2) {
                return -1;
        }

        if (!realpath(root, root_real)) {
                return -1;
        }

        name = smb_name ? smb_name : "";
        while (*name == '\\' || *name == '/') {
                name++;
        }

        if (name[0] == '\0' || strcmp(name, ".") == 0) {
                if (strlen(root_real) + 1 > out_len) {
                        return -1;
                }
                memcpy(out, root_real, strlen(root_real) + 1);
                return 0;
        }

        if (snprintf(built, sizeof(built), "%s", root_real) >= (int)sizeof(built)) {
                return -1;
        }
        built_len = strlen(built);

        const char *p = name;
        while (*p) {
                const char *start = p;
                while (*p && *p != '\\' && *p != '/') {
                        p++;
                }
                size_t seglen = (size_t)(p - start);
                if (seglen == 0) {
                        if (*p) {
                                p++;
                        }
                        continue;
                }
                if (!is_safe_component(start, seglen)) {
                        return -1;
                }
                if (seglen == 1 && start[0] == '.') {
                        if (*p) {
                                p++;
                        }
                        continue;
                }
                if (built_len + 1 + seglen + 1 > sizeof(built)) {
                        return -1;
                }
                built[built_len++] = '/';
                memcpy(built + built_len, start, seglen);
                built_len += seglen;
                built[built_len] = '\0';
                if (*p) {
                        p++;
                }
        }

        if (!realpath_prefix_ok(root_real, built)) {
                return -1;
        }

        if (realpath(built, tmp)) {
                if (!realpath_prefix_ok(root_real, tmp)) {
                        return -1;
                }
                if (strlen(tmp) + 1 > out_len) {
                        return -1;
                }
                memcpy(out, tmp, strlen(tmp) + 1);
                return 0;
        }

        char *slash = strrchr(built, '/');
        if (!slash || slash == built) {
                return -1;
        }
        *slash = '\0';
        if (!realpath(built, parent_real)) {
                return -1;
        }
        if (!realpath_prefix_ok(root_real, parent_real)) {
                return -1;
        }
        if (snprintf(tmp, sizeof(tmp), "%s/%s", parent_real, slash + 1) >= (int)sizeof(tmp)) {
                return -1;
        }
        if (!realpath_prefix_ok(root_real, tmp)) {
                return -1;
        }
        if (strlen(tmp) + 1 > out_len) {
                return -1;
        }
        memcpy(out, tmp, strlen(tmp) + 1);
        return 0;
}
