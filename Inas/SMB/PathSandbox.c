#include "PathSandbox.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
is_safe_component(const char *comp, size_t len)
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
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)comp[i];
                if (c == '\0' || c == '/') {
                        return 0;
                }
        }
        return 1;
}

static int
realpath_prefix_ok(const char *root_real, const char *candidate)
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

int
inas_path_resolve(const char *root, const char *smb_name, char *out, size_t out_len)
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

        /* Existing path: canonicalize and re-check. */
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

        /* New path: parent must exist inside the root. */
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
