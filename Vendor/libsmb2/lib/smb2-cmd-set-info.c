/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <errno.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

/*
 * FILE_RENAME_INFORMATION and FILE_LINK_INFORMATION share the same wire
 * format: ReplaceIfExists, Reserved, RootDirectory, FileNameLength, FileName.
 */
static int
smb2_encode_new_name(struct smb2_context *smb2, struct smb2_pdu *pdu,
                     struct smb2_iovec *iov, uint8_t replace_if_exist,
                     const uint8_t *file_name)
{
        int i, len;
        uint8_t *buf;
        struct smb2_utf16 *name;

        name = smb2_utf8_to_utf16((char *)file_name);
        if (name == NULL) {
                smb2_set_error(smb2, "Could not convert name into UTF-16");
                return -1;
        }
        /* Convert '/' to '\' in-place before copying into the iovec */
        for (i = 0; i < name->len; i++) {
                if (name->val[i] == 0x002f) {
                        name->val[i] = 0x005c;
                }
        }

        len = 28 + name->len * 2;
        smb2_set_uint32(iov, 4, len); /* buffer length */

        buf = calloc(len, sizeof(uint8_t));
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate set info data buffer");
                free(name);
                return -1;
        }
        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);
        if (iov == NULL) {
                smb2_set_error(smb2, "Failed to add iovector for set-info new-name data");
                free(name);
                return -1;
        }

        smb2_set_uint8(iov, 0, replace_if_exist);
        smb2_set_uint64(iov, 8, 0u);
        smb2_set_uint32(iov, 16, name->len * 2);
        memcpy(iov->buf + 20, name->val, name->len * 2);
        free(name);

        return 0;
}

static int
smb2_encode_set_info_request(struct smb2_context *smb2,
                             struct smb2_pdu *pdu,
                             struct smb2_set_info_request *req)
{
        int len;
        uint8_t *buf;
        struct smb2_iovec *iov;
        struct smb2_file_end_of_file_info *eofi;
        struct smb2_file_disposition_info *fdi;
        struct smb2_file_rename_info *rni;
        struct smb2_file_link_info *lni;
        struct smb2_security_descriptor *sd;

        len = SMB2_SET_INFO_REQUEST_SIZE & 0xfffffffe;
        buf = calloc(len, sizeof(uint8_t));
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate set info buffer");
                return -1;
        }

        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);
        if (iov == NULL) {
                smb2_set_error(smb2, "Failed to add iovector for set-info request header");
                return -1;
        }

        smb2_set_uint16(iov, 0, SMB2_SET_INFO_REQUEST_SIZE);
        smb2_set_uint8(iov, 2, req->info_type);
        smb2_set_uint8(iov, 3, req->file_info_class);
        smb2_set_uint16(iov,8, SMB2_HEADER_SIZE + 32); /* buffer offset */
        smb2_set_uint32(iov,12, req->additional_information);
        memcpy(iov->buf + 16, req->file_id, SMB2_FD_SIZE);

        if (smb2->passthrough) {
                if (req->buffer_length) {
                        buf = malloc(PAD_TO_32BIT(req->buffer_length));
                        if (buf == NULL) {
                                smb2_set_error(smb2, "Failed to allocate set "
                                                        "info data buffer");
                                return -1;
                        }
                        memcpy(buf, req->input_data, req->buffer_length);
                        iov = smb2_add_iovector(smb2, &pdu->out, buf, req->buffer_length, free);
                        if (iov == NULL) {
                                smb2_set_error(smb2, "Failed to add iovector for set-info passthrough buffer");
                                return -1;
                        }
                }
                smb2_set_uint32(iov, 4, req->buffer_length);
                smb2_set_uint16(iov, 8, req->buffer_offset);
                return 0;
        }

        switch (req->info_type) {
        case SMB2_0_INFO_FILE:
                switch (req->file_info_class) {
                case SMB2_FILE_BASIC_INFORMATION:
                        len = 40;
                        smb2_set_uint32(iov, 4, len); /* buffer length */

                        buf = calloc(len, sizeof(uint8_t));
                        if (buf == NULL) {
                                smb2_set_error(smb2, "Failed to allocate set "
                                               "info data buffer");
                                return -1;
                        }
                        iov = smb2_add_iovector(smb2, &pdu->out, buf, len,
                                                free);
                        if (iov == NULL) {
                                smb2_set_error(smb2, "Failed to add iovector for set-info basic data");
                                return -1;
                        }
                        smb2_encode_file_basic_info(smb2, req->input_data, iov);
                        break;
                case SMB2_FILE_END_OF_FILE_INFORMATION:
                        len = 8;
                        smb2_set_uint32(iov, 4, len); /* buffer length */

                        buf = calloc(len, sizeof(uint8_t));
                        if (buf == NULL) {
                                smb2_set_error(smb2, "Failed to allocate set "
                                               "info data buffer");
                                return -1;
                        }
                        iov = smb2_add_iovector(smb2, &pdu->out, buf, len,
                                                free);
                        if (iov == NULL) {
                                smb2_set_error(smb2, "Failed to add iovector for set-info EOF data");
                                return -1;
                        }

                        eofi = req->input_data;
                        smb2_set_uint64(iov, 0, eofi->end_of_file);
                        break;
                case SMB2_FILE_RENAME_INFORMATION:
                        rni = req->input_data;
                        if (smb2_encode_new_name(smb2, pdu, iov,
                                                 rni->replace_if_exist,
                                                 rni->file_name) < 0) {
                                return -1;
                        }
                        break;
                case SMB2_FILE_LINK_INFORMATION:
                        lni = req->input_data;
                        if (smb2_encode_new_name(smb2, pdu, iov,
                                                 lni->replace_if_exist,
                                                 lni->file_name) < 0) {
                                return -1;
                        }
                        break;
                case SMB2_FILE_DISPOSITION_INFORMATION:
                        len = 1;
                        smb2_set_uint32(iov, 4, len); /* buffer length */

                        buf = calloc(len, sizeof(uint8_t));
                        if (buf == NULL) {
                                smb2_set_error(smb2, "Failed to allocate set "
                                               "info data buffer");
                                return -1;
                        }
                        iov = smb2_add_iovector(smb2, &pdu->out, buf, len,
                                                free);
                        if (iov == NULL) {
                                smb2_set_error(smb2, "Failed to add iovector for set-info disposition data");
                                return -1;
                        }

                        fdi = req->input_data;
                        smb2_set_uint8(iov, 0, fdi->delete_pending);
                        break;
                default:
                        smb2_set_error(smb2, "Can not enccode info_type/"
                                       "info_class %d/%d yet",
                                       req->info_type,
                                       req->file_info_class);
                        return -1;
                }
                break;

        case SMB2_0_INFO_SECURITY:
                sd = req->input_data;

                len = smb2_security_descriptor_size(sd);
                smb2_set_uint32(iov, 4, len); /* buffer length */

                buf = calloc(len, sizeof(uint8_t));
                if (buf == NULL) {
                        smb2_set_error(smb2, "Failed to allocate set "
                                       "info data buffer");
                        return -1;
                }
                iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);
                if (iov == NULL) {
                        smb2_set_error(smb2, "Failed to add iovector for set-info security data");
                        return -1;
                }

                if (smb2_encode_security_descriptor(smb2, sd, iov)) {
                        return -1;
                }
                break;

        default:
                smb2_set_error(smb2, "Can not encode file info_type %d yet",
                               req->info_type);
                return -1;
        }

        return 0;
}

struct smb2_pdu *
smb2_cmd_set_info_async(struct smb2_context *smb2,
                        struct smb2_set_info_request *req,
                        smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_SET_INFO, cb, cb_data);
        if (pdu == NULL) {
                return NULL;
        }

        if (smb2_encode_set_info_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        if (smb2_pad_to_64bit(smb2, &pdu->out) != 0) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        return pdu;
}

static int
smb2_encode_set_info_reply(struct smb2_context *smb2,
                             struct smb2_pdu *pdu,
                             struct smb2_set_info_request *req)
{
        int len;
        uint8_t *buf;
        struct smb2_iovec *iov;

        len = SMB2_SET_INFO_REPLY_SIZE & 0xfffffffe;
        buf = calloc(len, sizeof(uint8_t));
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate set info buffer");
                return -1;
        }

        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);
        if (iov == NULL) {
                smb2_set_error(smb2, "Failed to add iovector for set-info reply header");
                return -1;
        }
        smb2_set_uint16(iov, 0, SMB2_SET_INFO_REPLY_SIZE);
        return 0;
}

struct smb2_pdu *
smb2_cmd_set_info_reply_async(struct smb2_context *smb2,
                        struct smb2_set_info_request *req,
                        smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_SET_INFO, cb, cb_data);
        if (pdu == NULL) {
                return NULL;
        }

        if (smb2_encode_set_info_reply(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        if (smb2_pad_to_64bit(smb2, &pdu->out) != 0) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        return pdu;
}

int
smb2_process_set_info_fixed(struct smb2_context *smb2,
                            struct smb2_pdu *pdu)
{
        return 0;
}

int
smb2_process_set_info_request_fixed(struct smb2_context *smb2,
                            struct smb2_pdu *pdu)
{
        struct smb2_set_info_request *req;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];
        uint16_t struct_size;

        smb2_get_uint16(iov, 0, &struct_size);
        if (struct_size != SMB2_SET_INFO_REQUEST_SIZE ||
            (struct_size & 0xfffe) != iov->len) {
                smb2_set_error(smb2, "Unexpected size of set "
                               "info request. Expected %d, got %d",
                               SMB2_SET_INFO_REQUEST_SIZE,
                               (int)iov->len);
                return -1;
        }

        req = malloc(sizeof(*req));
        if (req == NULL) {
                smb2_set_error(smb2, "Failed to allocate set-info request");
                return -1;
        }
        pdu->payload = req;

        smb2_get_uint8(iov, 2, &req->info_type);
        smb2_get_uint8(iov, 3, &req->file_info_class);
        smb2_get_uint32(iov, 4, &req->buffer_length);
        smb2_get_uint16(iov, 8, &req->buffer_offset);
        smb2_get_uint32(iov, 12, &req->additional_information);
        memcpy(req->file_id, iov->buf + 16, SMB2_FD_SIZE);

        return req->buffer_length;
}

int
smb2_process_set_info_request_variable(struct smb2_context *smb2,
                            struct smb2_pdu *pdu)
{
        struct smb2_set_info_request *req = (struct smb2_set_info_request*)pdu->payload;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];

        if (req->buffer_length == 0) {
                req->input_data = NULL;
                return 0;
        }
        /* The variable tail holds exactly buffer_length bytes (the read loop
         * grows it after the 32-byte fixed header), so a client that puts
         * extra padding between the header and the buffer would already be
         * misaligned here; all known clients (Windows, smbfs, libsmb2) place
         * the buffer at offset SMB2_HEADER_SIZE + 32. */
        if ((uint32_t)iov->len < req->buffer_length) {
                smb2_set_error(smb2, "set-info buffer %u longer than PDU data %zu",
                               req->buffer_length, iov->len);
                return -1;
        }

        switch (req->info_type) {
        case SMB2_0_INFO_FILE:
                switch (req->file_info_class) {
                case SMB2_FILE_DISPOSITION_INFORMATION:
                /* Raw little-endian buffers: the server handlers either read
                 * a single byte or a uint64, or ignore the payload. */
                case SMB2_FILE_END_OF_FILE_INFORMATION:
                case SMB2_FILE_ALLOCATION_INFORMATION:
                case SMB2_FILE_POSITION_INFORMATION:
                case SMB2_FILE_MODE_INFORMATION:
                case SMB2_FILE_BASIC_INFORMATION:
                        req->input_data = iov->buf;
                        return 0;
                case SMB2_FILE_RENAME_INFORMATION:
                case SMB2_FILE_LINK_INFORMATION: {
                        /* MS-FSCC 2.4.34/2.4.22: 1-byte ReplaceIfExists,
                         * 3 reserved, 8-byte RootDirectory, 4-byte
                         * FileNameLength, then a UTF-16LE name (name at
                         * offset 16). libsmb2's own client encoder uses a
                         * 20-byte header (root at 8, length at 16, name at
                         * 20); accept both — the standard layout always has
                         * a non-zero length at 12, the libsmb2 layout has 0
                         * there. The server handler expects a struct with a
                         * NUL-terminated UTF-8 name pointer. */
                        struct smb2_iovec v = { iov->buf, iov->len, NULL };
                        struct smb2_file_rename_info *ri;
                        const char *utf8_name;
                        uint8_t replace;
                        uint32_t len_std;
                        uint32_t len_alt;
                        uint32_t name_len;
                        size_t name_off;
                        size_t slen;
                        void *ptr;

                        if (iov->len < 20) {
                                smb2_set_error(smb2, "rename/link buffer too short");
                                return -1;
                        }
                        smb2_get_uint8(&v, 0, &replace);
                        smb2_get_uint32(&v, 12, &len_std);
                        smb2_get_uint32(&v, 16, &len_alt);
                        if (len_std > 0 && (uint64_t)len_std <= (uint64_t)(iov->len - 16) &&
                            !(len_std & 1)) {
                                name_len = len_std;
                                name_off = 16;
                        } else if (len_alt > 0 &&
                                   (uint64_t)len_alt <= (uint64_t)(iov->len - 20) &&
                                   !(len_alt & 1)) {
                                name_len = len_alt;
                                name_off = 20;
                        } else {
                                smb2_set_error(smb2, "bad rename/link name length");
                                return -1;
                        }
                        utf8_name = smb2_utf16_to_utf8((uint16_t *)(void *)(iov->buf + name_off),
                                                       name_len / 2);
                        if (utf8_name == NULL) {
                                smb2_set_error(smb2, "can not decode rename/link name");
                                return -1;
                        }
                        slen = strlen(utf8_name) + 1;
                        ptr = smb2_alloc_init(smb2, sizeof(*ri) + slen);
                        if (ptr == NULL) {
                                free((void *)utf8_name);
                                return -1;
                        }
                        ri = ptr;
                        ri->replace_if_exist = replace;
                        ri->file_name = (const uint8_t *)((uint8_t *)ptr + sizeof(*ri));
                        memcpy((void *)ri->file_name, utf8_name, slen);
                        free((void *)utf8_name);
                        req->input_data = ri;
                        return 0;
                }
                default:
                        smb2_set_error(smb2, "can not interpret set-info file class %d yet",
                                       req->file_info_class);
                        return -1;
                }
        default:
                smb2_set_error(smb2, "can not interpret set-info type %d yet",
                               req->info_type);
                return -1;
        }
}

