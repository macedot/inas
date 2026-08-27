/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#include "Srvsvc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DCERPC_REQUEST 0
#define DCERPC_RESPONSE 2
#define DCERPC_FAULT 3
#define DCERPC_BIND 11
#define DCERPC_BIND_ACK 12
#define DCERPC_ALTER 14
#define DCERPC_ALTER_ACK 15

#define SRVSVC_NETRSHAREENUM 0x0f
#define SRVSVC_NETRSHAREGETINFO 0x10

#define ERROR_INVALID_LEVEL 124
#define NERR_NET_NAME_NOT_FOUND 2100

#define STYPE_DISKTREE 0
#define STYPE_IPC 3
#define STYPE_SPECIAL 0x80000000u

#define NDR32_UUID                                                                                 \
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,  \
            0x60

struct wbuf {
        uint8_t *p;
        size_t len;
        size_t cap;
};

static int w_ensure(struct wbuf *w, size_t add)
{
        size_t ncap;
        void *np;

        if (w->len + add <= w->cap) {
                return 0;
        }
        ncap = w->cap ? w->cap : 256;
        while (ncap < w->len + add) {
                ncap *= 2;
        }
        np = realloc(w->p, ncap);
        if (!np) {
                return -1;
        }
        w->p = np;
        w->cap = ncap;
        return 0;
}

static int w_u8(struct wbuf *w, uint8_t v)
{
        if (w_ensure(w, 1) != 0) {
                return -1;
        }
        w->p[w->len++] = v;
        return 0;
}

static int w_u16(struct wbuf *w, uint16_t v)
{
        if (w_ensure(w, 2) != 0) {
                return -1;
        }
        w->p[w->len++] = (uint8_t)v;
        w->p[w->len++] = (uint8_t)(v >> 8);
        return 0;
}

static int w_u32(struct wbuf *w, uint32_t v)
{
        if (w_ensure(w, 4) != 0) {
                return -1;
        }
        w->p[w->len++] = (uint8_t)v;
        w->p[w->len++] = (uint8_t)(v >> 8);
        w->p[w->len++] = (uint8_t)(v >> 16);
        w->p[w->len++] = (uint8_t)(v >> 24);
        return 0;
}

static int w_bytes(struct wbuf *w, const uint8_t *b, size_t n)
{
        if (w_ensure(w, n) != 0) {
                return -1;
        }
        memcpy(w->p + w->len, b, n);
        w->len += n;
        return 0;
}

static int w_pad4(struct wbuf *w)
{
        while (w->len & 3) {
                if (w_u8(w, 0) != 0) {
                        return -1;
                }
        }
        return 0;
}

static int w_unistr(struct wbuf *w, const char *s)
{
        size_t n = strlen(s) + 1;
        size_t i;

        if (w_u32(w, (uint32_t)n) != 0 || w_u32(w, 0) != 0 || w_u32(w, (uint32_t)n) != 0) {
                return -1;
        }
        for (i = 0; i < n; i++) {
                if (w_u16(w, (uint8_t)s[i]) != 0) {
                        return -1;
                }
        }
        return w_pad4(w);
}

static uint16_t rd_u16(const uint8_t *p)
{
        return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_u32(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
               ((uint32_t)p[3] << 24);
}

static int ascii_eq_ci(const char *a, const char *b)
{
        if (!a || !b) {
                return 0;
        }
        while (*a && *b) {
                unsigned char ca = (unsigned char)*a++;
                unsigned char cb = (unsigned char)*b++;
                if (ca >= 'A' && ca <= 'Z') {
                        ca = (unsigned char)(ca - 'A' + 'a');
                }
                if (cb >= 'A' && cb <= 'Z') {
                        cb = (unsigned char)(cb - 'A' + 'a');
                }
                if (ca != cb) {
                        return 0;
                }
        }
        return *a == 0 && *b == 0;
}

static uint32_t share_stype(const char *name)
{
        if (ascii_eq_ci(name, "IPC$")) {
                return STYPE_IPC | STYPE_SPECIAL;
        }
        return STYPE_DISKTREE;
}

static const char *share_remark(const char *name)
{
        if (ascii_eq_ci(name, "IPC$")) {
                return "Remote IPC";
        }
        return "iNAS";
}

static int w_hdr(struct wbuf *w, uint8_t ptype, uint32_t call_id)
{
        /* frag_length and alloc_hint patched later */
        static const uint8_t drep[4] = {0x10, 0x00, 0x00, 0x00};

        if (w_u8(w, 5) != 0 || w_u8(w, 0) != 0 || w_u8(w, ptype) != 0 || w_u8(w, 0x03) != 0) {
                return -1;
        }
        if (w_bytes(w, drep, 4) != 0 || w_u16(w, 0) != 0 || w_u16(w, 0) != 0 ||
            w_u32(w, call_id) != 0) {
                return -1;
        }
        return 0;
}

static void patch_frag(struct wbuf *w)
{
        if (w->len >= 10) {
                w->p[8] = (uint8_t)w->len;
                w->p[9] = (uint8_t)(w->len >> 8);
        }
}

static void patch_alloc_hint(struct wbuf *w)
{
        uint32_t hint;

        if (w->len < 24) {
                return;
        }
        hint = (uint32_t)(w->len - 24);
        w->p[16] = (uint8_t)hint;
        w->p[17] = (uint8_t)(hint >> 8);
        w->p[18] = (uint8_t)(hint >> 16);
        w->p[19] = (uint8_t)(hint >> 24);
}

static int encode_bind_ack(struct wbuf *w, const uint8_t *req, size_t req_len)
{
        uint32_t call_id;
        uint16_t max_xmit = 4280;
        uint16_t max_recv = 4280;
        uint32_t assoc = 1;
        uint8_t nctx = 1;
        size_t off;
        uint8_t i;
        static const uint8_t ndr32[] = {NDR32_UUID};
        static const char secaddr[] = "\\PIPE\\srvsvc";

        if (req_len < 28) {
                return -1;
        }
        call_id = rd_u32(req + 12);
        max_xmit = rd_u16(req + 16);
        max_recv = rd_u16(req + 18);
        nctx = req[24];
        if (nctx == 0) {
                nctx = 1;
        }
        if (w_hdr(w, req[2] == DCERPC_ALTER ? DCERPC_ALTER_ACK : DCERPC_BIND_ACK, call_id) != 0) {
                return -1;
        }
        if (w_u16(w, max_xmit) != 0 || w_u16(w, max_recv) != 0 || w_u32(w, assoc) != 0) {
                return -1;
        }
        if (w_u16(w, (uint16_t)sizeof(secaddr)) != 0 ||
            w_bytes(w, (const uint8_t *)secaddr, sizeof(secaddr)) != 0 || w_pad4(w) != 0) {
                return -1;
        }
        if (w_u8(w, nctx) != 0 || w_u8(w, 0) != 0 || w_u8(w, 0) != 0 || w_u8(w, 0) != 0) {
                return -1;
        }
        off = 28;
        for (i = 0; i < nctx; i++) {
                uint8_t nts;
                uint8_t t;
                int accept = 0;

                if (off + 24 > req_len) {
                        break;
                }
                nts = req[off + 2];
                for (t = 0; t < nts; t++) {
                        size_t ts = off + 24 + (size_t)t * 20;
                        if (ts + 16 <= req_len && memcmp(req + ts, ndr32, 16) == 0) {
                                accept = 1;
                                break;
                        }
                }
                if (w_u16(w, accept ? 0 : 2) != 0 || w_u16(w, 0) != 0) {
                        return -1;
                }
                if (accept) {
                        static const uint8_t syn[] = {NDR32_UUID, 0x02, 0x00, 0x00, 0x00};
                        if (w_bytes(w, syn, sizeof(syn)) != 0) {
                                return -1;
                        }
                } else {
                        uint8_t z[20];
                        memset(z, 0, sizeof(z));
                        if (w_bytes(w, z, sizeof(z)) != 0) {
                                return -1;
                        }
                }
                off += 24 + (size_t)nts * 20;
        }
        patch_frag(w);
        return 0;
}

static int encode_fault(struct wbuf *w, uint32_t call_id, uint16_t ctx, uint32_t status)
{
        if (w_hdr(w, DCERPC_FAULT, call_id) != 0) {
                return -1;
        }
        if (w_u32(w, 0) != 0 || w_u16(w, ctx) != 0 || w_u8(w, 0) != 0 || w_u8(w, 0) != 0 ||
            w_u32(w, status) != 0) {
                return -1;
        }
        patch_frag(w);
        patch_alloc_hint(w);
        return 0;
}

static int encode_info_ptrs(struct wbuf *w, uint32_t level, const char *name, uint32_t *ref)
{
        if (w_u32(w, *ref) != 0) {
                return -1;
        }
        *ref += 4;
        if (level >= 1) {
                if (w_u32(w, share_stype(name)) != 0) {
                        return -1;
                }
                if (w_u32(w, *ref) != 0) {
                        return -1;
                }
                *ref += 4;
        }
        if (level >= 2) {
                if (w_u32(w, 0) != 0 || w_u32(w, 0xffffffffu) != 0 || w_u32(w, 0) != 0) {
                        return -1;
                }
                if (w_u32(w, *ref) != 0) {
                        return -1;
                }
                *ref += 4;
                if (w_u32(w, 0) != 0) { /* passwd NULL */
                        return -1;
                }
        }
        return 0;
}

static const char *share_disk_path(const char *name, char *buf, size_t cap)
{
        if (ascii_eq_ci(name, "IPC$")) {
                return "";
        }
        /* Finder/Windows GetInfo treats an empty shi2_path as "deleted". */
        if (buf && cap) {
                snprintf(buf, cap, "C:\\inas\\%s", name ? name : "inas");
                return buf;
        }
        return "C:\\inas";
}

static int encode_info_strings(struct wbuf *w, uint32_t level, const char *name)
{
        char path[80];

        if (w_unistr(w, name ? name : "") != 0) {
                return -1;
        }
        if (level >= 1 && w_unistr(w, share_remark(name)) != 0) {
                return -1;
        }
        if (level >= 2 && w_unistr(w, share_disk_path(name, path, sizeof(path))) != 0) {
                return -1;
        }
        return 0;
}

static int rpc_begin_resp(struct wbuf *w, uint32_t call_id, uint16_t ctx)
{
        if (w_hdr(w, DCERPC_RESPONSE, call_id) != 0) {
                return -1;
        }
        if (w_u32(w, 0) != 0 || w_u16(w, ctx) != 0 || w_u8(w, 0) != 0 || w_u8(w, 0) != 0) {
                return -1;
        }
        return 0;
}

static int encode_enum(struct wbuf *w, uint32_t call_id, uint16_t ctx, uint32_t level,
                       const char *const *names, int n)
{
        int i;
        uint32_t ref = 0x00020000;
        uint32_t status = 0;
        int supported = (level == 0 || level == 1 || level == 2);

        if (n < 0) {
                n = 0;
        }
        if (!supported) {
                status = ERROR_INVALID_LEVEL;
                n = 0;
        }
        if (rpc_begin_resp(w, call_id, ctx) != 0) {
                return -1;
        }
        /* SHARE_ENUM_STRUCT: Level + encapsulated union (discriminant + unique ptr). */
        if (w_u32(w, level) != 0 || w_u32(w, level) != 0) {
                return -1;
        }
        if (status != 0) {
                if (w_u32(w, 0) != 0 || w_u32(w, 0) != 0 || w_u32(w, 0) != 0 ||
                    w_u32(w, status) != 0) {
                        return -1;
                }
                patch_frag(w);
                patch_alloc_hint(w);
                return 0;
        }
        if (w_u32(w, ref) != 0) {
                return -1;
        }
        ref += 4;
        /* container: EntriesRead + unique ptr to array, then deferred array/strings */
        if (w_u32(w, (uint32_t)n) != 0 || w_u32(w, n ? ref : 0) != 0) {
                return -1;
        }
        if (n) {
                ref += 4;
                if (w_u32(w, (uint32_t)n) != 0) {
                        return -1;
                }
                for (i = 0; i < n; i++) {
                        if (encode_info_ptrs(w, level, names[i], &ref) != 0) {
                                return -1;
                        }
                }
                for (i = 0; i < n; i++) {
                        if (encode_info_strings(w, level, names[i]) != 0) {
                                return -1;
                        }
                }
        }
        /* TotalEntries (ref DWORD), ResumeHandle (unique NULL), NET_API_STATUS */
        if (w_u32(w, (uint32_t)n) != 0 || w_u32(w, 0) != 0 || w_u32(w, 0) != 0) {
                return -1;
        }
        patch_frag(w);
        patch_alloc_hint(w);
        return 0;
}

static int encode_getinfo(struct wbuf *w, uint32_t call_id, uint16_t ctx, uint32_t level,
                          const char *name)
{
        uint32_t ref = 0x00020000;
        uint32_t status = 0;
        int supported = (level == 0 || level == 1 || level == 2);

        if (!name || !name[0]) {
                status = NERR_NET_NAME_NOT_FOUND;
        } else if (!supported) {
                status = ERROR_INVALID_LEVEL;
        }
        if (rpc_begin_resp(w, call_id, ctx) != 0) {
                return -1;
        }
        /* LPSHARE_INFO: union discriminant + unique ptr to SHARE_INFO_X */
        if (w_u32(w, level) != 0) {
                return -1;
        }
        if (status != 0) {
                if (w_u32(w, 0) != 0 || w_u32(w, status) != 0) {
                        return -1;
                }
                patch_frag(w);
                patch_alloc_hint(w);
                return 0;
        }
        if (w_u32(w, ref) != 0) {
                return -1;
        }
        ref += 4;
        if (encode_info_ptrs(w, level, name, &ref) != 0 ||
            encode_info_strings(w, level, name) != 0 || w_u32(w, 0) != 0) {
                return -1;
        }
        patch_frag(w);
        patch_alloc_hint(w);
        return 0;
}

static uint32_t skip_unistr(const uint8_t *p, size_t len, size_t *off)
{
        uint32_t actual;
        size_t o = *off;

        if (o + 4 > len) {
                return 0;
        }
        if (rd_u32(p + o) == 0) {
                *off = o + 4;
                return 0;
        }
        o += 4;
        if (o + 12 > len) {
                return 0;
        }
        actual = rd_u32(p + o + 8);
        o += 12 + (size_t)actual * 2;
        while (o & 3) {
                o++;
        }
        *off = o;
        return actual;
}

static int skip_unistr_body(const uint8_t *p, size_t len, size_t *off)
{
        uint32_t actual;
        size_t o = *off;

        if (o + 12 > len) {
                return -1;
        }
        actual = rd_u32(p + o + 8);
        o += 12 + (size_t)actual * 2;
        if (o > len) {
                return -1;
        }
        while (o & 3) {
                o++;
        }
        *off = o;
        return 0;
}

static int read_unistr_body(const uint8_t *p, size_t len, size_t *off, char *out, size_t cap)
{
        uint32_t actual;
        uint32_t i;
        size_t o = *off;

        if (o + 12 > len) {
                return -1;
        }
        actual = rd_u32(p + o + 8);
        o += 12;
        if (o + (size_t)actual * 2 > len) {
                return -1;
        }
        if (out && cap) {
                size_t n = actual ? actual - 1 : 0;
                if (n >= cap) {
                        n = cap - 1;
                }
                for (i = 0; i < n; i++) {
                        out[i] = (char)p[o + (size_t)i * 2];
                }
                out[n] = 0;
        }
        o += (size_t)actual * 2;
        while (o & 3) {
                o++;
        }
        *off = o;
        return 0;
}

static uint32_t parse_enum_level(const uint8_t *stub, size_t stub_len)
{
        size_t off = 0;

        skip_unistr(stub, stub_len, &off);
        if (off + 4 > stub_len) {
                return 1;
        }
        return rd_u32(stub + off);
}

static int parse_getinfo_name(const uint8_t *stub, size_t stub_len, uint32_t *level, char *name,
                              size_t cap)
{
        size_t off = 0;
        uint32_t first;

        skip_unistr(stub, stub_len, &off);
        if (off + 4 > stub_len) {
                return -1;
        }
        first = rd_u32(stub + off);
        /* Unique pointer vs inline WSTR (max_count is a small integer). */
        if (first == 0) {
                off += 4;
                if (name && cap) {
                        name[0] = 0;
                }
        } else if (first > 4096) {
                off += 4;
                if (read_unistr_body(stub, stub_len, &off, name, cap) != 0) {
                        return -1;
                }
        } else if (read_unistr_body(stub, stub_len, &off, name, cap) != 0) {
                return -1;
        }
        if (off + 4 > stub_len) {
                return -1;
        }
        *level = rd_u32(stub + off);
        return 0;
}

static const char *find_share(const char *const *names, int n, const char *want)
{
        int i;

        for (i = 0; i < n; i++) {
                if (ascii_eq_ci(names[i], want)) {
                        return names[i];
                }
        }
        return NULL;
}

int inas_srvsvc_process(const uint8_t *req, size_t req_len, const char *const *names,
                        int name_count, uint8_t **out, size_t *out_len)
{
        struct wbuf w;
        uint8_t ptype;
        uint32_t call_id;
        int rc;

        if (!req || req_len < 16 || !out || !out_len) {
                return -1;
        }
        memset(&w, 0, sizeof(w));
        ptype = req[2];
        call_id = rd_u32(req + 12);
        if (ptype == DCERPC_BIND || ptype == DCERPC_ALTER) {
                rc = encode_bind_ack(&w, req, req_len);
        } else if (ptype == DCERPC_REQUEST) {
                uint16_t ctx = 0;
                uint16_t opnum = 0;

                if (req_len >= 24) {
                        ctx = rd_u16(req + 20);
                        opnum = rd_u16(req + 22);
                }
                if (opnum == SRVSVC_NETRSHAREENUM) {
                        uint32_t level = 1;
                        if (req_len > 24) {
                                level = parse_enum_level(req + 24, req_len - 24);
                        }
                        rc = encode_enum(&w, call_id, ctx, level, names, name_count);
                } else if (opnum == SRVSVC_NETRSHAREGETINFO) {
                        uint32_t level = 1;
                        char net[64];

                        net[0] = 0;
                        if (req_len > 24) {
                                parse_getinfo_name(req + 24, req_len - 24, &level, net,
                                                   sizeof(net));
                        }
                        rc = encode_getinfo(&w, call_id, ctx, level,
                                            find_share(names, name_count, net));
                } else {
                        rc = encode_fault(&w, call_id, ctx, 0x1c010002); /* nca_s_op_rng_error */
                }
        } else {
                rc = encode_fault(&w, call_id, 0, 0x1c01000b); /* nca_s_proto_error */
        }
        if (rc != 0) {
                free(w.p);
                return -1;
        }
        *out = w.p;
        *out_len = w.len;
        return 0;
}

size_t inas_srvsvc_build_bind(uint8_t *buf, size_t cap, uint32_t call_id)
{
        static const uint8_t pkt[] = {
            0x05, 0x00, 0x0b, 0x03, 0x10,       0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0xb8,       0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00,       0x00, 0x01, 0x00, 0xc8, 0x4f, 0x32, 0x4b,
            0x70, 0x16, 0xd3, 0x01, 0x12,       0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
            0x03, 0x00, 0x00, 0x00, NDR32_UUID, 0x02, 0x00, 0x00, 0x00};
        uint8_t tmp[sizeof(pkt)];

        if (!buf || cap < sizeof(pkt)) {
                return 0;
        }
        memcpy(tmp, pkt, sizeof(pkt));
        tmp[12] = (uint8_t)call_id;
        tmp[13] = (uint8_t)(call_id >> 8);
        tmp[14] = (uint8_t)(call_id >> 16);
        tmp[15] = (uint8_t)(call_id >> 24);
        memcpy(buf, tmp, sizeof(pkt));
        return sizeof(pkt);
}

size_t inas_srvsvc_build_enum(uint8_t *buf, size_t cap, uint32_t call_id, uint32_t level)
{
        struct wbuf w;

        memset(&w, 0, sizeof(w));
        if (w_hdr(&w, DCERPC_REQUEST, call_id) != 0) {
                free(w.p);
                return 0;
        }
        if (w_u32(&w, 0) != 0 || w_u16(&w, 0) != 0 || w_u16(&w, SRVSVC_NETRSHAREENUM) != 0) {
                free(w.p);
                return 0;
        }
        /* NULL ServerName, then SHARE_ENUM_STRUCT (level + union disc + null container). */
        if (w_u32(&w, 0) != 0 || w_u32(&w, level) != 0 || w_u32(&w, level) != 0 ||
            w_u32(&w, 0) != 0 || w_u32(&w, 0xffffffffu) != 0 || w_u32(&w, 0) != 0) {
                free(w.p);
                return 0;
        }
        patch_frag(&w);
        patch_alloc_hint(&w);
        if (!buf || cap < w.len) {
                size_t n = w.len;
                free(w.p);
                return buf ? 0 : n;
        }
        memcpy(buf, w.p, w.len);
        free(w.p);
        return w.len;
}

int inas_srvsvc_enum_has_share(const uint8_t *rep, size_t len, const char *name)
{
        size_t off;
        uint32_t level;
        uint32_t disc;
        uint32_t ctr;
        uint32_t entries;
        uint32_t arr;
        uint32_t maxc;
        uint32_t i;
        uint32_t stride;
        const uint8_t *elems;
        int found = 0;

        if (!rep || !name || len < 40 || rep[2] != DCERPC_RESPONSE) {
                return 0;
        }
        off = 24;
        if (off + 16 > len) {
                return 0;
        }
        level = rd_u32(rep + off);
        off += 4;
        disc = rd_u32(rep + off);
        off += 4;
        if (disc != level || (level != 0 && level != 1 && level != 2)) {
                return 0;
        }
        ctr = rd_u32(rep + off);
        off += 4;
        if (ctr == 0 || off + 8 > len) {
                return 0;
        }
        entries = rd_u32(rep + off);
        off += 4;
        arr = rd_u32(rep + off);
        off += 4;
        if (entries == 0 || arr == 0 || off + 4 > len) {
                return 0;
        }
        maxc = rd_u32(rep + off);
        off += 4;
        if (maxc < entries) {
                return 0;
        }
        stride = level == 0 ? 4u : (level == 1 ? 12u : 32u);
        if (off + (size_t)entries * stride > len) {
                return 0;
        }
        elems = rep + off;
        off += (size_t)entries * stride;
        for (i = 0; i < entries; i++) {
                const uint8_t *e = elems + (size_t)i * stride;
                char net[64];

                if (rd_u32(e) == 0 || read_unistr_body(rep, len, &off, net, sizeof(net)) != 0) {
                        return 0;
                }
                if (ascii_eq_ci(net, name)) {
                        found = 1;
                }
                if (level >= 1) {
                        if (rd_u32(e + 8) != 0 && skip_unistr_body(rep, len, &off) != 0) {
                                return 0;
                        }
                }
                if (level >= 2) {
                        if (rd_u32(e + 24) != 0 && skip_unistr_body(rep, len, &off) != 0) {
                                return 0;
                        }
                        if (rd_u32(e + 28) != 0 && skip_unistr_body(rep, len, &off) != 0) {
                                return 0;
                        }
                }
        }
        if (off + 12 > len) {
                return 0;
        }
        if (rd_u32(rep + off) != entries) {
                return 0;
        }
        if (rd_u32(rep + off + 8) != 0) {
                return 0;
        }
        return found;
}
