/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#include "GlobMatch.h"

#include <string.h>

int inas_glob_match(const char *name, const char *pattern)
{
        const char *n;
        const char *p;
        const char *star = NULL;
        const char *nstar = NULL;

        if (!name) {
                name = "";
        }
        if (!pattern || pattern[0] == '\0' || strcmp(pattern, "*") == 0 ||
            strcmp(pattern, "*.*") == 0) {
                return 1;
        }

        n = name;
        p = pattern;
        while (*n) {
                if (*p == '*') {
                        star = p++;
                        nstar = n;
                        if (*p == '\0') {
                                return 1;
                        }
                        continue;
                }
                if (*p == '?' || *p == *n) {
                        p++;
                        n++;
                        continue;
                }
                if (star) {
                        p = star + 1;
                        n = ++nstar;
                        continue;
                }
                return 0;
        }
        while (*p == '*') {
                p++;
        }
        return *n == '\0' && *p == '\0';
}
