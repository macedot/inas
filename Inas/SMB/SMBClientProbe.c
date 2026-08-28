/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

/* Test-only SMB client helpers used by InasTests to drive the loopback
 * server. Compiled in Debug builds only (the test action); release archives
 * of the app carry no SMB client code. */

#include "SMBClientProbe.h"
#include "FilesystemShare.h"
#include "Srvsvc.h"

#include <sys/types.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if DEBUG

static void set_err(char *err, int errlen, struct smb2_context *smb2, const char *fallback)
{
        const char *msg = smb2 ? smb2_get_error(smb2) : NULL;
        if (!err || errlen <= 0) {
                return;
        }
        if (msg && msg[0] && fallback && fallback[0]) {
                snprintf(err, (size_t)errlen, "%s: %s", fallback, msg);
        } else if (msg && msg[0]) {
                snprintf(err, (size_t)errlen, "%s", msg);
        } else if (fallback) {
                snprintf(err, (size_t)errlen, "%s", fallback);
        } else {
                err[0] = '\0';
        }
}

static struct smb2_context *open_share(const char *host, uint16_t port, const char *user,
                                       const char *password, const char *share, uint16_t dialect,
                                       char *err, int errlen)
{
        struct smb2_context *smb2;
        char server[128];

        if (!host || !user || !password || !share) {
                set_err(err, errlen, NULL, "invalid arguments");
                return NULL;
        }
        smb2 = smb2_init_context();
        if (!smb2) {
                set_err(err, errlen, NULL, "smb2_init_context failed");
                return NULL;
        }
        if (port == 0 || port == 445) {
                snprintf(server, sizeof(server), "%s", host);
        } else {
                snprintf(server, sizeof(server), "%s:%u", host, port);
        }
        if (dialect == 0) {
                smb2_set_version(smb2, SMB2_VERSION_ANY3);
        } else {
                smb2_set_version(smb2, (enum smb2_negotiate_version)dialect);
        }
        smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP);
        smb2_set_user(smb2, user);
        smb2_set_password(smb2, password);
        /* Advertise encryption; the server requires SMB 3 seal. */
        smb2_set_sign(smb2, 1);
        smb2_set_security_mode(smb2,
                               SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED);
        smb2_set_timeout(smb2, 8);
        if (smb2_connect_share(smb2, server, share, user) != 0) {
                set_err(err, errlen, smb2, "connect failed");
                smb2_destroy_context(smb2);
                return NULL;
        }
        return smb2;
}

struct raw_status {
        volatile int done;
        int status;
};

static void raw_cb(struct smb2_context *smb2, int status, void *command_data, void *cb_data)
{
        struct raw_status *rs = cb_data;

        (void)smb2;
        (void)command_data;
        rs->status = status;
        rs->done = 1;
}

static int wait_for_cb(struct smb2_context *smb2, struct raw_status *rs)
{
        while (!rs->done) {
                struct pollfd pfd;

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = (short)smb2_which_events(smb2);
                pfd.revents = 0;
                if (poll(&pfd, 1, 5000) < 1) {
                        return -1;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        return -1;
                }
        }
        return 0;
}

int inas_smb_client_connect(const char *host, uint16_t port, const char *user, const char *password,
                            const char *share, uint16_t dialect, uint16_t *negotiated, char *err,
                            int errlen)
{
        struct smb2_context *smb2 =
            open_share(host, port, user, password, share, dialect, err, errlen);
        if (!smb2) {
                return -1;
        }
        if (negotiated) {
                *negotiated = smb2_get_dialect(smb2);
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return 0;
}

int inas_smb_client_roundtrip(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, char *err, int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        const char payload[] = "hello-inas";
        char buf[64];
        int n;
        int saw = 0;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }

        if (smb2_open(smb2, "../outside.txt", O_RDWR | O_CREAT) != NULL) {
                set_err(err, errlen, NULL, "path escape succeeded");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }

        if (smb2_mkdir(smb2, "probe-dir") != 0) {
                set_err(err, errlen, smb2, "mkdir failed");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }
        fh = smb2_open(smb2, "probe-dir/hello.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create failed");
                smb2_rmdir(smb2, "probe-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }
        if (smb2_pwrite(smb2, fh, (const uint8_t *)payload, (uint32_t)strlen(payload), 0) < 0) {
                set_err(err, errlen, smb2, "write failed");
                smb2_close(smb2, fh);
                smb2_unlink(smb2, "probe-dir/hello.txt");
                smb2_rmdir(smb2, "probe-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }
        smb2_close(smb2, fh);

        fh = smb2_open(smb2, "probe-dir/hello.txt", O_RDONLY);
        if (!fh) {
                set_err(err, errlen, smb2, "reopen failed");
                smb2_unlink(smb2, "probe-dir/hello.txt");
                smb2_rmdir(smb2, "probe-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }
        memset(buf, 0, sizeof(buf));
        n = smb2_pread(smb2, fh, (uint8_t *)buf, sizeof(buf) - 1, 0);
        smb2_close(smb2, fh);
        if (n != (int)strlen(payload) || memcmp(buf, payload, (size_t)n) != 0) {
                set_err(err, errlen, smb2, "read mismatch");
                smb2_unlink(smb2, "probe-dir/hello.txt");
                smb2_rmdir(smb2, "probe-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }

        saw = 1;

        if (smb2_unlink(smb2, "probe-dir/hello.txt") != 0) {
                set_err(err, errlen, smb2, "unlink failed");
                smb2_rmdir(smb2, "probe-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }
        if (smb2_rmdir(smb2, "probe-dir") != 0) {
                set_err(err, errlen, smb2, "rmdir failed");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }

        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        if (err && errlen > 0) {
                err[0] = '\0';
        }
        return 0;
}

int inas_smb_client_dir_cycle(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, int cycles, char *err,
                              int errlen)
{
        struct smb2_context *smb2;
        struct smb2dir *dir;
        int i;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        if (smb2_mkdir(smb2, "cycle-dir") != 0) {
                set_err(err, errlen, smb2, "mkdir cycle-dir failed");
                goto out;
        }
        for (i = 0; i < cycles; i++) {
                dir = smb2_opendir(smb2, "cycle-dir");
                if (!dir) {
                        set_err(err, errlen, smb2, "opendir failed during cycles");
                        goto out;
                }
                smb2_closedir(smb2, dir);
        }
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return rc;
}

int inas_smb_client_open_many(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, int count, char *err,
                              int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh **fhs;
        int n = 0;
        int i;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        fhs = calloc((size_t)count, sizeof(*fhs));
        if (!fhs) {
                set_err(err, errlen, NULL, "oom");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return -1;
        }
        for (n = 0; n < count; n++) {
                fhs[n] = smb2_open(smb2, "many.txt", O_RDWR | O_CREAT);
                if (!fhs[n]) {
                        break;
                }
        }
        for (i = 0; i < n; i++) {
                smb2_close(smb2, fhs[i]);
        }
        free(fhs);
        set_err(err, errlen, NULL, NULL);
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return n;
}

int inas_smb_client_write_bounds(const char *host, uint16_t port, const char *user,
                                 const char *password, const char *share, uint32_t ok_len,
                                 uint32_t big_len, char *err, int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        struct smb2_write_request req;
        struct smb2_pdu *pdu;
        struct raw_status rs;
        uint8_t *buf;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        fh = smb2_open(smb2, "bounds.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "open for write bounds failed");
                goto out;
        }
        buf = malloc(big_len);
        if (!buf) {
                set_err(err, errlen, NULL, "oom");
                smb2_close(smb2, fh);
                goto out;
        }
        memset(buf, 'x', big_len);

        /* In-bounds write; the sync client may chunk to the negotiated max. */
        if (smb2_pwrite(smb2, fh, buf, ok_len, 0) != (int)ok_len) {
                set_err(err, errlen, smb2, "in-bounds write failed");
                free(buf);
                smb2_close(smb2, fh);
                goto out;
        }

        /* A single oversized raw WRITE must be rejected by the server. */
        memset(&req, 0, sizeof(req));
        req.length = big_len;
        req.offset = 0;
        req.buf = buf;
        memcpy(req.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        memset(&rs, 0, sizeof(rs));
        pdu = smb2_cmd_write_async(smb2, &req, 0, raw_cb, &rs);
        if (!pdu) {
                set_err(err, errlen, smb2, "raw write encode failed");
                free(buf);
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_queue_pdu(smb2, pdu);
        if (wait_for_cb(smb2, &rs) != 0) {
                set_err(err, errlen, NULL, "raw write timed out");
                free(buf);
                smb2_close(smb2, fh);
                goto out;
        }
        free(buf);
        smb2_close(smb2, fh);
        if (rs.status == 0) {
                set_err(err, errlen, NULL, "oversized write was accepted");
                goto out;
        }
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return rc;
}

int inas_smb_client_plaintext_after_session(const char *host, uint16_t port, const char *user,
                                            const char *password, const char *share, char *err,
                                            int errlen)
{
        struct smb2_context *smb2;
        struct smb2_create_request req;
        struct smb2_pdu *pdu;
        struct raw_status rs;
        struct pollfd pfd;
        int i;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        /* Drop sealing so the next PDU goes out as a bare SMB2 header. */
        smb2_set_seal(smb2, 0);
        smb2_set_sign(smb2, 0);

        memset(&req, 0, sizeof(req));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_READ_ATTRIBUTES;
        req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        req.create_disposition = SMB2_FILE_OPEN;
        req.name = "hello.txt";

        memset(&rs, 0, sizeof(rs));
        pdu = smb2_cmd_create_async(smb2, &req, raw_cb, &rs);
        if (!pdu) {
                set_err(err, errlen, smb2, "plaintext create encode failed");
                smb2_destroy_context(smb2);
                return -1;
        }
        smb2_queue_pdu(smb2, pdu);

        pfd.fd = smb2_get_fd(smb2);
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, 2000) < 1 || smb2_service(smb2, POLLOUT) < 0) {
                /* Write failed because the server already dropped us. */
                set_err(err, errlen, NULL, NULL);
                smb2_destroy_context(smb2);
                return 0;
        }

        /* Do not parse inbound PDUs: sealing is off on this context, so a
         * transform reply would crash the decoder. The reject we want is
         * the server hanging up. */
        for (i = 0; i < 20; i++) {
                char peek;
                ssize_t n;

                pfd.fd = smb2_get_fd(smb2);
                if (pfd.fd < 0) {
                        set_err(err, errlen, NULL, NULL);
                        smb2_destroy_context(smb2);
                        return 0;
                }
                pfd.events = POLLIN | POLLHUP | POLLERR;
                pfd.revents = 0;
                if (poll(&pfd, 1, 100) < 1) {
                        continue;
                }
                if (pfd.revents & (POLLHUP | POLLERR)) {
                        set_err(err, errlen, NULL, NULL);
                        smb2_destroy_context(smb2);
                        return 0;
                }
                n = recv(pfd.fd, &peek, 1, MSG_PEEK);
                if (n <= 0) {
                        set_err(err, errlen, NULL, NULL);
                        smb2_destroy_context(smb2);
                        return 0;
                }
                set_err(err, errlen, NULL,
                        "server replied to plaintext CREATE instead of dropping");
                smb2_destroy_context(smb2);
                return -1;
        }

        set_err(err, errlen, NULL, "server kept the connection after plaintext CREATE");
        smb2_destroy_context(smb2);
        return -1;
}

static int run_until_status(struct smb2_context *smb2, struct smb2_pdu *pdu, struct raw_status *rs,
                            const char *what, char *err, int errlen)
{
        if (!pdu) {
                set_err(err, errlen, smb2, what);
                return -1;
        }
        memset(rs, 0, sizeof(*rs));
        smb2_queue_pdu(smb2, pdu);
        if (wait_for_cb(smb2, rs) != 0) {
                snprintf(err, (size_t)errlen, "%s timed out", what);
                return -1;
        }
        if (rs->status == (int)SMB2_STATUS_NOT_IMPLEMENTED) {
                snprintf(err, (size_t)errlen, "%s: STATUS_NOT_IMPLEMENTED", what);
                return -1;
        }
        return 0;
}

int inas_smb_client_linux_post_login(const char *host, uint16_t port, const char *user,
                                     const char *password, const char *share, char *err, int errlen)
{
        struct smb2_context *smb2;
        struct smb2_query_info_request qi;
        struct smb2_ioctl_request io;
        struct smb2_change_notify_request cn;
        struct smb2fh *fh;
        struct raw_status rs;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }

        memset(&qi, 0, sizeof(qi));
        qi.info_type = SMB2_0_INFO_FILESYSTEM;
        qi.file_info_class = SMB2_FILE_FS_SECTOR_SIZE_INFORMATION;
        qi.output_buffer_length = 4096;
        memcpy(qi.file_id, compound_file_id, SMB2_FD_SIZE);
        if (run_until_status(smb2, smb2_cmd_query_info_async(smb2, &qi, raw_cb, &rs), &rs,
                             "FileFsSectorSizeInformation", err, errlen) != 0) {
                goto out;
        }

        qi.file_info_class = SMB2_FILE_FS_FULL_SIZE_INFORMATION;
        if (run_until_status(smb2, smb2_cmd_query_info_async(smb2, &qi, raw_cb, &rs), &rs,
                             "FileFsFullSizeInformation", err, errlen) != 0) {
                goto out;
        }

        memset(&io, 0, sizeof(io));
        io.ctl_code = SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO;
        memcpy(io.file_id, compound_file_id, SMB2_FD_SIZE);
        io.flags = SMB2_0_IOCTL_IS_FSCTL;
        if (run_until_status(smb2, smb2_cmd_ioctl_async(smb2, &io, raw_cb, &rs), &rs,
                             "QUERY_NETWORK_INTERFACE_INFO", err, errlen) != 0) {
                goto out;
        }

        fh = smb2_open(smb2, "", O_RDONLY);
        if (!fh) {
                fh = smb2_open(smb2, ".", O_RDONLY);
        }
        if (!fh) {
                set_err(err, errlen, smb2, "open share root failed");
                goto out;
        }

        memset(&qi, 0, sizeof(qi));
        qi.info_type = SMB2_0_INFO_FILE;
        qi.file_info_class = SMB2_FILE_STREAM_INFORMATION;
        qi.output_buffer_length = 4096;
        memcpy(qi.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        if (run_until_status(smb2, smb2_cmd_query_info_async(smb2, &qi, raw_cb, &rs), &rs,
                             "FileStreamInformation", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }

        memset(&cn, 0, sizeof(cn));
        cn.output_buffer_length = 4096;
        memcpy(cn.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        cn.completion_filter = SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME |
                               SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME;
        {
                struct smb2_pdu *pdu = smb2_cmd_change_notify_async(smb2, &cn, raw_cb, &rs);
                struct smb2fh *touch;

                if (!pdu) {
                        set_err(err, errlen, smb2, "CHANGE_NOTIFY alloc failed");
                        smb2_close(smb2, fh);
                        goto out;
                }
                memset(&rs, 0, sizeof(rs));
                smb2_queue_pdu(smb2, pdu);
                /* Notify is held until a name change; create a file so this
                 * probe does not sit on the 5s poll timeout. */
                touch = smb2_open(smb2, "cn-touch.txt", O_RDWR | O_CREAT);
                if (touch) {
                        smb2_close(smb2, touch);
                }
                if (wait_for_cb(smb2, &rs) != 0) {
                        snprintf(err, (size_t)errlen, "CHANGE_NOTIFY timed out");
                        smb2_close(smb2, fh);
                        goto out;
                }
                if (rs.status == (int)SMB2_STATUS_NOT_IMPLEMENTED) {
                        snprintf(err, (size_t)errlen, "CHANGE_NOTIFY: STATUS_NOT_IMPLEMENTED");
                        smb2_close(smb2, fh);
                        goto out;
                }
        }
        smb2_close(smb2, fh);
        smb2_unlink(smb2, "cn-touch.txt");

        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return rc;
}

struct ioctl_status {
        volatile int done;
        int status;
        uint8_t *out;
        size_t out_len;
};

static void ioctl_cb(struct smb2_context *smb2, int status, void *command_data, void *cb_data)
{
        struct ioctl_status *is = cb_data;
        struct smb2_ioctl_reply *rep = command_data;

        (void)smb2;
        if (status == 0 && rep && rep->output && rep->output_count) {
                is->out = malloc(rep->output_count);
                if (is->out) {
                        memcpy(is->out, rep->output, rep->output_count);
                        is->out_len = rep->output_count;
                }
        }
        is->status = status;
        is->done = 1;
}

static int wait_ioctl(struct smb2_context *smb2, struct smb2_pdu *pdu, struct ioctl_status *is,
                      const char *what, char *err, int errlen)
{
        if (!pdu) {
                set_err(err, errlen, smb2, what);
                return -1;
        }
        smb2_queue_pdu(smb2, pdu);
        while (!is->done) {
                struct pollfd pfd;

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = (short)smb2_which_events(smb2);
                pfd.revents = 0;
                if (poll(&pfd, 1, 5000) < 1) {
                        snprintf(err, (size_t)errlen, "%s timed out", what);
                        return -1;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        set_err(err, errlen, smb2, what);
                        return -1;
                }
        }
        if (is->status != 0) {
                set_err(err, errlen, smb2, what);
                return -1;
        }
        return 0;
}

static int stub_enum_ok(const char *share, uint32_t level, char *err, int errlen)
{
        uint8_t enumreq[256];
        uint8_t *out = NULL;
        size_t out_len = 0;
        size_t elen;
        const char *names[1];

        names[0] = share;
        elen = inas_srvsvc_build_enum(enumreq, sizeof(enumreq), 2, level);
        if (!elen) {
                set_err(err, errlen, NULL, "build enum failed");
                return -1;
        }
        if (inas_srvsvc_process(enumreq, elen, names, 1, &out, &out_len) != 0 ||
            !inas_srvsvc_enum_has_share(out, out_len, names[0])) {
                set_err(err, errlen, NULL, "srvsvc NetrShareEnum NDR missed share");
                free(out);
                return -1;
        }
        free(out);
        return 0;
}

int inas_smb_client_share_enum(const char *host, uint16_t port, const char *user,
                               const char *password, const char *expect_share, char *err,
                               int errlen)
{
        struct smb2_context *smb2 = NULL;
        struct smb2fh *fh;
        struct smb2_ioctl_request io;
        struct smb2_pdu *pdu;
        struct ioctl_status is;
        uint8_t bind[128];
        uint8_t enumreq[256];
        uint8_t *out = NULL;
        size_t out_len = 0;
        size_t blen;
        size_t elen;
        const char *names[1];
        const char *share = expect_share ? expect_share : "inas";
        int rc = -1;

        names[0] = share;
        blen = inas_srvsvc_build_bind(bind, sizeof(bind), 1);
        if (!blen) {
                set_err(err, errlen, NULL, "build bind failed");
                return -1;
        }
        if (inas_srvsvc_process(bind, blen, names, 1, &out, &out_len) != 0 || !out ||
            out[2] != 12) {
                set_err(err, errlen, NULL, "srvsvc bind_ack failed");
                free(out);
                return -1;
        }
        free(out);
        if (stub_enum_ok(share, 0, err, errlen) != 0 || stub_enum_ok(share, 1, err, errlen) != 0 ||
            stub_enum_ok(share, 2, err, errlen) != 0) {
                return -1;
        }

        smb2 = open_share(host, port, user, password, "IPC$", 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        fh = smb2_open(smb2, "srvsvc", O_RDWR);
        if (!fh) {
                set_err(err, errlen, smb2, "CREATE srvsvc failed");
                goto out;
        }

        memset(&io, 0, sizeof(io));
        io.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
        memcpy(io.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        io.flags = SMB2_0_IOCTL_IS_FSCTL;
        io.input = bind;
        io.input_count = (uint32_t)blen;
        memset(&is, 0, sizeof(is));
        pdu = smb2_cmd_ioctl_async(smb2, &io, ioctl_cb, &is);
        if (wait_ioctl(smb2, pdu, &is, "srvsvc bind", err, errlen) != 0) {
                free(is.out);
                smb2_close(smb2, fh);
                goto out;
        }
        free(is.out);

        elen = inas_srvsvc_build_enum(enumreq, sizeof(enumreq), 2, 1);
        io.input = enumreq;
        io.input_count = (uint32_t)elen;
        memset(&is, 0, sizeof(is));
        pdu = smb2_cmd_ioctl_async(smb2, &io, ioctl_cb, &is);
        if (wait_ioctl(smb2, pdu, &is, "NetrShareEnum", err, errlen) != 0) {
                free(is.out);
                smb2_close(smb2, fh);
                goto out;
        }
        if (!inas_srvsvc_enum_has_share(is.out, is.out_len, share)) {
                set_err(err, errlen, NULL, "NetrShareEnum reply missing share or bad NDR");
                free(is.out);
                smb2_close(smb2, fh);
                goto out;
        }
        free(is.out);
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        smb2 = NULL;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        {
                struct smb2dir *dir = smb2_opendir(smb2, "");
                if (!dir) {
                        set_err(err, errlen, smb2, "opendir share root failed");
                        goto out;
                }
                smb2_closedir(smb2, dir);
                dir = smb2_opendir(smb2, share);
                if (!dir) {
                        set_err(err, errlen, smb2, "opendir share-name alias failed");
                        goto out;
                }
                smb2_closedir(smb2, dir);
        }
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (smb2) {
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

struct qdir_wire {
        volatile int done;
        int status;
        uint8_t *buf;
        uint32_t len;
};

static void qdir_wire_cb(struct smb2_context *smb2, int status, void *command_data, void *cb_data)
{
        struct qdir_wire *w = cb_data;
        struct smb2_query_directory_reply *rep = command_data;

        (void)smb2;
        w->status = status;
        if (status == 0 && rep && rep->output_buffer && rep->output_buffer_length) {
                w->len = rep->output_buffer_length;
                w->buf = malloc(w->len);
                if (w->buf) {
                        memcpy(w->buf, rep->output_buffer, w->len);
                }
        }
        w->done = 1;
}

static uint32_t rd_le32(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
               ((uint32_t)p[3] << 24);
}

/* macOS smbfs walks directory records and returns EBADRPC ("RPC struct is
 * bad") if NextEntryOffset is not 8-aligned or if leftover bytes remain
 * after an unpadded last entry. `hdr` is the fixed part of the record;
 * FileNameLength sits at offset 60 in every class checked here. */
static int apple_parse_dir_records(const uint8_t *buf, uint32_t len, uint32_t hdr, char *err,
                                   int errlen)
{
        uint32_t off = 0;
        unsigned n = 0;

        if (len == 0) {
                snprintf(err, (size_t)errlen, "empty QUERY_DIRECTORY payload");
                return -1;
        }
        while (off < len) {
                uint32_t next;
                uint32_t namelen;
                uint32_t used;

                if (len - off < hdr) {
                        snprintf(err, (size_t)errlen,
                                 "short directory entry at %u remain %u (Apple EBADRPC)", off,
                                 len - off);
                        return -1;
                }
                next = rd_le32(buf + off);
                namelen = rd_le32(buf + off + 60);
                if (next != 0 && (next & 7u) != 0) {
                        snprintf(err, (size_t)errlen, "NextEntryOffset %u is not 8-byte aligned",
                                 next);
                        return -1;
                }
                if (namelen & 1u) {
                        snprintf(err, (size_t)errlen, "odd FileNameLength %u", namelen);
                        return -1;
                }
                if (namelen > len - off - hdr) {
                        snprintf(err, (size_t)errlen, "FileNameLength %u overflows buffer",
                                 namelen);
                        return -1;
                }
                used = hdr + namelen;
                if (next == 0) {
                        if (off + used != len) {
                                snprintf(err, (size_t)errlen,
                                         "last entry leftover %u bytes (Apple EBADRPC)",
                                         len - (off + used));
                                return -1;
                        }
                        n++;
                        break;
                }
                if (next < used) {
                        snprintf(err, (size_t)errlen, "NextEntryOffset %u < entry %u", next, used);
                        return -1;
                }
                if (next > len - off) {
                        snprintf(err, (size_t)errlen, "NextEntryOffset %u past buffer", next);
                        return -1;
                }
                off += next;
                n++;
        }
        if (n == 0) {
                snprintf(err, (size_t)errlen, "no directory entries");
                return -1;
        }
        return 0;
}

static int apple_parse_id_both(const uint8_t *buf, uint32_t len, char *err, int errlen)
{
        return apple_parse_dir_records(buf, len, SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE, err,
                                       errlen);
}

int inas_smb_client_query_dir_wire(const char *host, uint16_t port, const char *user,
                                   const char *password, const char *share, char *err, int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        struct smb2_query_directory_request req;
        struct qdir_wire w;
        struct smb2_pdu *pdu;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        fh = smb2_open(smb2, "", O_RDONLY);
        if (!fh) {
                fh = smb2_open(smb2, ".", O_RDONLY);
        }
        if (!fh) {
                set_err(err, errlen, smb2, "open share root failed");
                goto out;
        }

        memset(&req, 0, sizeof(req));
        req.file_information_class = SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION;
        req.flags = SMB2_RESTART_SCANS;
        memcpy(req.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        req.name = "*";
        req.output_buffer_length = 0x10000;

        memset(&w, 0, sizeof(w));
        pdu = smb2_cmd_query_directory_async(smb2, &req, qdir_wire_cb, &w);
        if (!pdu) {
                set_err(err, errlen, smb2, "QUERY_DIRECTORY alloc failed");
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_queue_pdu(smb2, pdu);
        if (wait_for_cb(smb2, (struct raw_status *)&w) != 0) {
                snprintf(err, (size_t)errlen, "QUERY_DIRECTORY timed out");
                free(w.buf);
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);
        if (w.status != 0) {
                snprintf(err, (size_t)errlen, "QUERY_DIRECTORY status 0x%x", (unsigned)w.status);
                free(w.buf);
                goto out;
        }
        if (!w.buf) {
                snprintf(err, (size_t)errlen, "QUERY_DIRECTORY missing output buffer");
                goto out;
        }
        rc = apple_parse_id_both(w.buf, w.len, err, errlen);
        free(w.buf);
        if (rc == 0) {
                set_err(err, errlen, NULL, NULL);
        }
out:
        if (smb2) {
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

/* macOS Finder deletes and renames via SET_INFO (FileDispositionInformation
 * / FileRenameInformation) on an open handle, not via a delete-on-close
 * CREATE. Both must succeed and take effect on close. */
int inas_smb_client_setinfo_delete_rename(const char *host, uint16_t port, const char *user,
                                          const char *password, const char *share, char *err,
                                          int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        struct smb2_set_info_request sr;
        struct smb2_file_disposition_info fdi;
        struct smb2_file_rename_info rni;
        struct raw_status rs;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }

        fh = smb2_open(smb2, "si-del.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create si-del.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);

        fh = smb2_open(smb2, "si-del.txt", O_RDWR);
        if (!fh) {
                set_err(err, errlen, smb2, "reopen si-del.txt failed");
                goto out;
        }
        memset(&sr, 0, sizeof(sr));
        sr.info_type = SMB2_0_INFO_FILE;
        sr.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        fdi.delete_pending = 1;
        sr.input_data = &fdi;
        if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                             "FileDispositionInformation", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }
        if (rs.status != 0) {
                snprintf(err, (size_t)errlen, "FileDispositionInformation status 0x%x",
                         (unsigned)rs.status);
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-del.txt", O_RDONLY);
        if (fh) {
                smb2_close(smb2, fh);
                set_err(err, errlen, NULL, "delete_pending close did not unlink si-del.txt");
                goto out;
        }

        fh = smb2_open(smb2, "si-rn-a.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create si-rn-a.txt failed");
                goto out;
        }
        memset(&sr, 0, sizeof(sr));
        sr.info_type = SMB2_0_INFO_FILE;
        sr.file_info_class = SMB2_FILE_RENAME_INFORMATION;
        memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        rni.replace_if_exist = 0;
        rni.file_name = (const uint8_t *)"si-rn-b.txt";
        sr.input_data = &rni;
        if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                             "FileRenameInformation", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }
        if (rs.status != 0) {
                snprintf(err, (size_t)errlen, "FileRenameInformation status 0x%x",
                         (unsigned)rs.status);
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-rn-a.txt", O_RDONLY);
        if (fh) {
                smb2_close(smb2, fh);
                set_err(err, errlen, NULL, "old name si-rn-a.txt still resolves after rename");
                goto out;
        }
        fh = smb2_open(smb2, "si-rn-b.txt", O_RDONLY);
        if (!fh) {
                set_err(err, errlen, smb2, "rename target si-rn-b.txt missing");
                goto out;
        }
        smb2_close(smb2, fh);

        /* Finder move-into-folder is the same SET_INFO rename with a
         * directory-qualified target name. */
        if (smb2_mkdir(smb2, "si-dir") != 0) {
                set_err(err, errlen, smb2, "mkdir si-dir failed");
                goto out;
        }
        fh = smb2_open(smb2, "si-rn-b.txt", O_RDWR);
        if (!fh) {
                set_err(err, errlen, smb2, "reopen si-rn-b.txt for move failed");
                goto out;
        }
        memset(&sr, 0, sizeof(sr));
        sr.info_type = SMB2_0_INFO_FILE;
        sr.file_info_class = SMB2_FILE_RENAME_INFORMATION;
        memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        rni.replace_if_exist = 0;
        rni.file_name = (const uint8_t *)"si-dir/si-rn-b.txt";
        sr.input_data = &rni;
        if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                             "FileRenameInformation move", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-dir/si-rn-b.txt", O_RDONLY);
        if (!fh) {
                set_err(err, errlen, smb2, "moved file si-dir/si-rn-b.txt missing");
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-rn-b.txt", O_RDONLY);
        if (fh) {
                smb2_close(smb2, fh);
                set_err(err, errlen, NULL, "old root name si-rn-b.txt still present after move");
                goto out;
        }

        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (smb2) {
                smb2_unlink(smb2, "si-del.txt");
                smb2_unlink(smb2, "si-rn-a.txt");
                smb2_unlink(smb2, "si-rn-b.txt");
                smb2_unlink(smb2, "si-dir/si-rn-b.txt");
                smb2_rmdir(smb2, "si-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

/* Linux file managers (gvfs, kio_smb) stat the directory and every entry
 * when a folder is opened. smb2_stat() compounds CREATE + QUERY_INFO
 * (FileAllInformation) + CLOSE, exercising the related-fid fixup. */
int inas_smb_client_stat_entry(const char *host, uint16_t port, const char *user,
                               const char *password, const char *share, char *err, int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        struct smb2_stat_64 st;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        if (smb2_mkdir(smb2, "stat-dir") != 0) {
                set_err(err, errlen, smb2, "mkdir stat-dir failed");
                goto out;
        }
        fh = smb2_open(smb2, "stat-dir/file.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create stat-dir/file.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);

        memset(&st, 0, sizeof(st));
        if (smb2_stat(smb2, "stat-dir", &st) != 0) {
                set_err(err, errlen, smb2, "stat subdir failed");
                goto out;
        }
        if (st.smb2_type != SMB2_TYPE_DIRECTORY) {
                set_err(err, errlen, NULL, "stat subdir reports non-directory type");
                goto out;
        }
        memset(&st, 0, sizeof(st));
        if (smb2_stat(smb2, "stat-dir/file.txt", &st) != 0) {
                set_err(err, errlen, smb2, "stat file in subdir failed");
                goto out;
        }
        if (st.smb2_type != SMB2_TYPE_FILE) {
                set_err(err, errlen, NULL, "stat file in subdir reports non-file type");
                goto out;
        }

        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (smb2) {
                smb2_unlink(smb2, "stat-dir/file.txt");
                smb2_rmdir(smb2, "stat-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

/* cifs.ko lists directories with FileFullDirectoryInformation /
 * FileIdFullDirectoryInformation, not the FileIdBoth class macOS uses.
 * Run both against a subdirectory handle and validate the wire layout. */
int inas_smb_client_query_dir_classes(const char *host, uint16_t port, const char *user,
                                      const char *password, const char *share, char *err,
                                      int errlen)
{
        static const struct {
                uint8_t cls;
                uint32_t hdr;
                const char *label;
        } classes[] = {
            {SMB2_FILE_FULL_DIRECTORY_INFORMATION, 68, "FileFullDirectoryInformation"},
            {SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION, SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE,
             "FileIdFullDirectoryInformation"},
        };
        struct smb2_context *smb2 = NULL;
        struct smb2fh *fh = NULL;
        int rc = -1;
        size_t i;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        if (smb2_mkdir(smb2, "qdir-dir") != 0) {
                set_err(err, errlen, smb2, "mkdir qdir-dir failed");
                goto out;
        }
        fh = smb2_open(smb2, "qdir-dir/entry.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create qdir-dir/entry.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);
        fh = NULL;

        for (i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
                struct smb2_query_directory_request req;
                struct qdir_wire w;
                struct smb2_pdu *pdu;

                fh = smb2_open(smb2, "qdir-dir", O_RDONLY);
                if (!fh) {
                        set_err(err, errlen, smb2, "open qdir-dir failed");
                        goto out;
                }
                memset(&req, 0, sizeof(req));
                req.file_information_class = classes[i].cls;
                req.flags = SMB2_RESTART_SCANS;
                memcpy(req.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
                req.name = "*";
                req.output_buffer_length = 0x10000;

                memset(&w, 0, sizeof(w));
                pdu = smb2_cmd_query_directory_async(smb2, &req, qdir_wire_cb, &w);
                if (!pdu) {
                        set_err(err, errlen, smb2, classes[i].label);
                        goto out;
                }
                smb2_queue_pdu(smb2, pdu);
                if (wait_for_cb(smb2, (struct raw_status *)&w) != 0) {
                        snprintf(err, (size_t)errlen, "%s timed out", classes[i].label);
                        free(w.buf);
                        goto out;
                }
                smb2_close(smb2, fh);
                fh = NULL;
                if (w.status != 0) {
                        snprintf(err, (size_t)errlen, "%s status 0x%x", classes[i].label,
                                 (unsigned)w.status);
                        free(w.buf);
                        goto out;
                }
                if (!w.buf) {
                        snprintf(err, (size_t)errlen, "%s missing output buffer", classes[i].label);
                        goto out;
                }
                if (apple_parse_dir_records(w.buf, w.len, classes[i].hdr, err, errlen) != 0) {
                        free(w.buf);
                        goto out;
                }
                free(w.buf);
        }

        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (fh) {
                smb2_close(smb2, fh);
        }
        if (smb2) {
                smb2_unlink(smb2, "qdir-dir/entry.txt");
                smb2_rmdir(smb2, "qdir-dir");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

static int wait_for_cb_timeout(struct smb2_context *smb2, struct raw_status *rs, int timeout_ms)
{
        int left = timeout_ms;

        while (!rs->done && left > 0) {
                struct pollfd pfd;
                int slice = left > 100 ? 100 : left;
                int pr;

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = (short)smb2_which_events(smb2);
                pfd.revents = 0;
                pr = poll(&pfd, 1, slice);
                if (pr < 0) {
                        return -1;
                }
                left -= slice;
                if (pr == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        return -1;
                }
        }
        return rs->done ? 0 : -1;
}

/* Finder delete/rename edges: name gone after SET_INFO (before CLOSE),
 * non-empty directory disposition, rename collision. */
int inas_smb_client_setinfo_delete_edges(const char *host, uint16_t port, const char *user,
                                         const char *password, const char *share, char *err,
                                         int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        struct smb2fh *fh2;
        struct smb2_set_info_request sr;
        struct smb2_file_disposition_info fdi;
        struct smb2_file_rename_info rni;
        struct raw_status rs;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }

        fh = smb2_open(smb2, "si-gone.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create si-gone.txt failed");
                goto out;
        }
        memset(&sr, 0, sizeof(sr));
        sr.info_type = SMB2_0_INFO_FILE;
        sr.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        fdi.delete_pending = 1;
        sr.input_data = &fdi;
        if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                             "FileDispositionInformation gone", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }
        if (rs.status != 0) {
                snprintf(err, (size_t)errlen, "disposition si-gone.txt status 0x%x",
                         (unsigned)rs.status);
                smb2_close(smb2, fh);
                goto out;
        }
        fh2 = smb2_open(smb2, "si-gone.txt", O_RDONLY);
        if (fh2) {
                smb2_close(smb2, fh2);
                smb2_close(smb2, fh);
                set_err(err, errlen, NULL, "si-gone.txt still resolvable after SET_INFO");
                goto out;
        }
        smb2_close(smb2, fh);

        if (smb2_mkdir(smb2, "si-ned") != 0) {
                set_err(err, errlen, smb2, "mkdir si-ned failed");
                goto out;
        }
        fh = smb2_open(smb2, "si-ned/child.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create si-ned/child.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-ned", O_RDONLY);
        if (!fh) {
                set_err(err, errlen, smb2, "open si-ned failed");
                goto out;
        }
        memset(&sr, 0, sizeof(sr));
        sr.info_type = SMB2_0_INFO_FILE;
        sr.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        fdi.delete_pending = 1;
        sr.input_data = &fdi;
        if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                             "FileDispositionInformation ned", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);
        if (rs.status != (int)SMB2_STATUS_DIRECTORY_NOT_EMPTY) {
                snprintf(err, (size_t)errlen, "non-empty dir disposition status 0x%x",
                         (unsigned)rs.status);
                goto out;
        }

        fh = smb2_open(smb2, "si-col-a.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create si-col-a.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-col-b.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create si-col-b.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "si-col-a.txt", O_RDWR);
        if (!fh) {
                set_err(err, errlen, smb2, "reopen si-col-a.txt failed");
                goto out;
        }
        memset(&sr, 0, sizeof(sr));
        sr.info_type = SMB2_0_INFO_FILE;
        sr.file_info_class = SMB2_FILE_RENAME_INFORMATION;
        memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        rni.replace_if_exist = 0;
        rni.file_name = (const uint8_t *)"si-col-b.txt";
        sr.input_data = &rni;
        if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                             "FileRenameInformation collision", err, errlen) != 0) {
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);
        if (rs.status != (int)SMB2_STATUS_OBJECT_NAME_COLLISION) {
                snprintf(err, (size_t)errlen, "rename collision status 0x%x", (unsigned)rs.status);
                goto out;
        }

        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (smb2) {
                smb2_unlink(smb2, "si-gone.txt");
                smb2_unlink(smb2, "si-ned/child.txt");
                smb2_rmdir(smb2, "si-ned");
                smb2_unlink(smb2, "si-col-a.txt");
                smb2_unlink(smb2, "si-col-b.txt");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

/* CHANGE_NOTIFY must stay pending across a WRITE and complete with
 * NOTIFY_ENUM_DIR when a name is created. */
int inas_smb_client_change_notify_mutate(const char *host, uint16_t port, const char *user,
                                         const char *password, const char *share, char *err,
                                         int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *root = NULL;
        struct smb2fh *fh;
        struct smb2_change_notify_request cn;
        struct smb2_pdu *pdu;
        struct raw_status rs;
        char buf[4] = {'x', 'x', 'x', 'x'};
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }

        fh = smb2_open(smb2, "cn-exist.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create cn-exist.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);

        root = smb2_open(smb2, "", O_RDONLY);
        if (!root) {
                root = smb2_open(smb2, ".", O_RDONLY);
        }
        if (!root) {
                set_err(err, errlen, smb2, "open share root failed");
                goto out;
        }

        memset(&cn, 0, sizeof(cn));
        cn.output_buffer_length = 4096;
        memcpy(cn.file_id, smb2_get_file_id(root), SMB2_FD_SIZE);
        cn.completion_filter = SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME |
                               SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME;
        pdu = smb2_cmd_change_notify_async(smb2, &cn, raw_cb, &rs);
        if (!pdu) {
                set_err(err, errlen, smb2, "CHANGE_NOTIFY alloc failed");
                goto out;
        }
        memset(&rs, 0, sizeof(rs));
        smb2_queue_pdu(smb2, pdu);

        fh = smb2_open(smb2, "cn-exist.txt", O_RDWR);
        if (!fh) {
                set_err(err, errlen, smb2, "reopen cn-exist.txt failed");
                goto out;
        }
        if (smb2_write(smb2, fh, (uint8_t *)buf, sizeof(buf)) < 0) {
                set_err(err, errlen, smb2, "write cn-exist.txt failed");
                smb2_close(smb2, fh);
                goto out;
        }
        smb2_close(smb2, fh);

        if (wait_for_cb_timeout(smb2, &rs, 400) == 0) {
                snprintf(err, (size_t)errlen, "CHANGE_NOTIFY completed on WRITE status 0x%x",
                         (unsigned)rs.status);
                goto out;
        }

        fh = smb2_open(smb2, "cn-new.txt", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create cn-new.txt failed");
                goto out;
        }
        smb2_close(smb2, fh);

        if (wait_for_cb(smb2, &rs) != 0) {
                snprintf(err, (size_t)errlen, "CHANGE_NOTIFY timed out after create");
                goto out;
        }
        if (rs.status != (int)SMB2_STATUS_NOTIFY_ENUM_DIR) {
                snprintf(err, (size_t)errlen, "CHANGE_NOTIFY after create status 0x%x",
                         (unsigned)rs.status);
                goto out;
        }

        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (root) {
                smb2_close(smb2, root);
        }
        if (smb2) {
                smb2_unlink(smb2, "cn-exist.txt");
                smb2_unlink(smb2, "cn-new.txt");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

int inas_smb_client_count_survives_failed_login(const char *host, uint16_t port, const char *user,
                                                const char *password, const char *share, char *err,
                                                int errlen)
{
        struct smb2_context *live;
        uint16_t negotiated = 0;
        char failerr[128];
        int i;
        int n;
        int rc = -1;

        live = open_share(host, port, user, password, share, 0, err, errlen);
        if (!live) {
                return -1;
        }
        for (i = 0; i < 50 && inas_smb_client_count() < 1; i++) {
                usleep(20000);
        }
        if (inas_smb_client_count() < 1) {
                set_err(err, errlen, NULL, "live session never counted");
                goto out;
        }
        if (inas_smb_client_connect(host, port, user, "wrong-password", share, 0, &negotiated,
                                    failerr, (int)sizeof(failerr)) == 0) {
                set_err(err, errlen, NULL, "wrong password succeeded");
                goto out;
        }
        for (i = 0; i < 25; i++) {
                usleep(20000);
        }
        n = inas_smb_client_count();
        if (n != 1) {
                snprintf(err, (size_t)errlen, "count after failed login is %d, want 1", n);
                goto out;
        }
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        smb2_disconnect_share(live);
        smb2_destroy_context(live);
        return rc;
}

struct conc_copy {
        const char *host;
        uint16_t port;
        const char *user;
        const char *password;
        const char *share;
        volatile int writing;
        volatile int write_rc;
        char werr[256];
};

static void *conc_copy_thread(void *arg)
{
        struct conc_copy *a = arg;
        struct smb2_context *smb2;
        struct smb2fh *fh;
        uint8_t *buf;
        int i;

        a->write_rc = -1;
        smb2 = open_share(a->host, a->port, a->user, a->password, a->share, 0, a->werr,
                          (int)sizeof(a->werr));
        if (!smb2) {
                a->writing = 0;
                return NULL;
        }
        fh = smb2_open(smb2, "conc-copy.bin", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(a->werr, (int)sizeof(a->werr), smb2, "create conc-copy.bin failed");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                a->writing = 0;
                return NULL;
        }
        buf = malloc(512 * 1024);
        if (!buf) {
                smb2_close(smb2, fh);
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                a->writing = 0;
                return NULL;
        }
        memset(buf, 0xab, 512 * 1024);
        a->writing = 1;
        for (i = 0; i < 16; i++) {
                if (smb2_pwrite(smb2, fh, buf, 512 * 1024, (uint64_t)i * 512 * 1024) < 0) {
                        set_err(a->werr, (int)sizeof(a->werr), smb2, "pwrite conc-copy.bin failed");
                        a->writing = 0;
                        free(buf);
                        smb2_close(smb2, fh);
                        smb2_unlink(smb2, "conc-copy.bin");
                        smb2_disconnect_share(smb2);
                        smb2_destroy_context(smb2);
                        return NULL;
                }
        }
        a->write_rc = 0;
        a->writing = 0;
        free(buf);
        smb2_close(smb2, fh);
        smb2_unlink(smb2, "conc-copy.bin");
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return NULL;
}

int inas_smb_client_concurrent_copy_and_enum(const char *host, uint16_t port, const char *user,
                                             const char *password, const char *share, char *err,
                                             int errlen)
{
        struct conc_copy a;
        pthread_t th;
        char e2[256];
        int i;
        int enum_ok = 0;
        int qdir_ok = 0;
        int saw_busy = 0;
        int rc = -1;

        memset(&a, 0, sizeof(a));
        a.host = host;
        a.port = port;
        a.user = user;
        a.password = password;
        a.share = share;
        if (pthread_create(&th, NULL, conc_copy_thread, &a) != 0) {
                set_err(err, errlen, NULL, "pthread_create failed");
                return -1;
        }
        for (i = 0; i < 100 && !a.writing && a.write_rc != 0; i++) {
                usleep(20000);
        }
        if (a.writing) {
                saw_busy = 1;
        }
        for (i = 0; i < 40; i++) {
                if (inas_smb_client_share_enum(host, port, user, password, share, e2,
                                               (int)sizeof(e2)) == 0) {
                        enum_ok = 1;
                }
                if (inas_smb_client_query_dir_wire(host, port, user, password, share, e2,
                                                   (int)sizeof(e2)) == 0) {
                        qdir_ok = 1;
                }
                if (a.writing) {
                        saw_busy = 1;
                }
                if (enum_ok && qdir_ok && (saw_busy || a.write_rc == 0)) {
                        break;
                }
                usleep(50000);
        }
        pthread_join(th, NULL);
        if (a.write_rc != 0) {
                snprintf(err, (size_t)errlen, "copy thread failed: %s", a.werr);
                goto out;
        }
        if (!enum_ok) {
                snprintf(err, (size_t)errlen, "share enum failed during copy: %s", e2);
                goto out;
        }
        if (!qdir_ok) {
                snprintf(err, (size_t)errlen, "QUERY_DIRECTORY failed during copy: %s", e2);
                goto out;
        }
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        return rc;
}

int inas_smb_client_transfer_verify(const char *host, uint16_t port, const char *user,
                                    const char *password, const char *share, char *err, int errlen)
{
        struct smb2_context *smb2;
        struct smb2fh *fh;
        uint8_t *wbuf = NULL;
        uint8_t *rbuf = NULL;
        const uint32_t chunk = 512 * 1024;
        const int chunks = 4;
        int i;
        int rc = -1;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        wbuf = malloc(chunk);
        rbuf = malloc(chunk);
        if (!wbuf || !rbuf) {
                set_err(err, errlen, NULL, "malloc failed");
                goto out;
        }
        fh = smb2_open(smb2, "xfer-verify.bin", O_RDWR | O_CREAT);
        if (!fh) {
                set_err(err, errlen, smb2, "create xfer-verify.bin failed");
                goto out;
        }
        for (i = 0; i < chunks; i++) {
                memset(wbuf, 0xa0 + i, chunk);
                if (smb2_pwrite(smb2, fh, wbuf, chunk, (uint64_t)i * chunk) != (int)chunk) {
                        set_err(err, errlen, smb2, "pwrite xfer-verify.bin failed");
                        smb2_close(smb2, fh);
                        goto out;
                }
        }
        smb2_close(smb2, fh);
        fh = smb2_open(smb2, "xfer-verify.bin", O_RDONLY);
        if (!fh) {
                set_err(err, errlen, smb2, "reopen xfer-verify.bin failed");
                goto out;
        }
        for (i = 0; i < chunks; i++) {
                memset(wbuf, 0xa0 + i, chunk);
                memset(rbuf, 0, chunk);
                if (smb2_pread(smb2, fh, rbuf, chunk, (uint64_t)i * chunk) != (int)chunk ||
                    memcmp(wbuf, rbuf, chunk) != 0) {
                        set_err(err, errlen, smb2, "pread mismatch on xfer-verify.bin");
                        smb2_close(smb2, fh);
                        goto out;
                }
        }
        smb2_close(smb2, fh);
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        if (smb2) {
                smb2_unlink(smb2, "xfer-verify.bin");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        free(wbuf);
        free(rbuf);
        return rc;
}

struct par_ctl {
        const char *host;
        uint16_t port;
        const char *user;
        const char *password;
        const char *share;
        volatile int stop;
        volatile int creates;
        volatile int deletes;
        volatile int lists;
        volatile int failed;
        char err[256];
};

static void *par_create_thread(void *arg)
{
        struct par_ctl *c = arg;
        struct smb2_context *smb2 = open_share(c->host, c->port, c->user, c->password, c->share, 0,
                                               c->err, (int)sizeof(c->err));
        int n = 0;

        if (!smb2) {
                c->failed = 1;
                return NULL;
        }
        while (!c->stop) {
                char name[64];
                struct smb2fh *fh;

                snprintf(name, sizeof(name), "par/c-%d.txt", n++);
                fh = smb2_open(smb2, name, O_RDWR | O_CREAT);
                if (!fh) {
                        snprintf(c->err, sizeof(c->err), "create %s failed", name);
                        c->failed = 1;
                        break;
                }
                smb2_close(smb2, fh);
                c->creates++;
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return NULL;
}

static void *par_delete_thread(void *arg)
{
        struct par_ctl *c = arg;
        struct smb2_context *smb2 = open_share(c->host, c->port, c->user, c->password, c->share, 0,
                                               c->err, (int)sizeof(c->err));
        int n = 0;

        if (!smb2) {
                c->failed = 1;
                return NULL;
        }
        while (!c->stop) {
                char name[64];
                struct smb2fh *fh;
                struct smb2_set_info_request sr;
                struct smb2_file_disposition_info fdi;
                struct raw_status rs;

                snprintf(name, sizeof(name), "par/d-%d.txt", n++);
                fh = smb2_open(smb2, name, O_RDWR | O_CREAT);
                if (!fh) {
                        snprintf(c->err, sizeof(c->err), "create-for-delete %s failed", name);
                        c->failed = 1;
                        break;
                }
                memset(&sr, 0, sizeof(sr));
                sr.info_type = SMB2_0_INFO_FILE;
                sr.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
                memcpy(sr.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
                fdi.delete_pending = 1;
                sr.input_data = &fdi;
                if (run_until_status(smb2, smb2_cmd_set_info_async(smb2, &sr, raw_cb, &rs), &rs,
                                     "par delete", c->err, (int)sizeof(c->err)) != 0 ||
                    rs.status != 0) {
                        smb2_close(smb2, fh);
                        c->failed = 1;
                        break;
                }
                smb2_close(smb2, fh);
                c->deletes++;
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return NULL;
}

static void *par_list_thread(void *arg)
{
        struct par_ctl *c = arg;
        struct smb2_context *smb2 = open_share(c->host, c->port, c->user, c->password, c->share, 0,
                                               c->err, (int)sizeof(c->err));

        if (!smb2) {
                c->failed = 1;
                return NULL;
        }
        while (!c->stop) {
                struct smb2dir *dir = smb2_opendir(smb2, "par");
                if (!dir) {
                        snprintf(c->err, sizeof(c->err), "opendir par failed: %s",
                                 smb2_get_error(smb2));
                        c->failed = 1;
                        break;
                }
                while (smb2_readdir(smb2, dir)) {
                }
                smb2_closedir(smb2, dir);
                c->lists++;
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return NULL;
}

int inas_smb_client_parallel_create_delete_list(const char *host, uint16_t port, const char *user,
                                                const char *password, const char *share, char *err,
                                                int errlen)
{
        struct par_ctl c;
        pthread_t tc, td, tl;
        struct smb2_context *smb2;
        int rc = -1;

        memset(&c, 0, sizeof(c));
        c.host = host;
        c.port = port;
        c.user = user;
        c.password = password;
        c.share = share;

        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (!smb2) {
                return -1;
        }
        if (smb2_mkdir(smb2, "par") != 0 &&
            smb2_get_nterror(smb2) != SMB2_STATUS_OBJECT_NAME_COLLISION) {
                /* mkdir may fail if it exists; try going on. */
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);

        if (pthread_create(&tc, NULL, par_create_thread, &c) != 0 ||
            pthread_create(&td, NULL, par_delete_thread, &c) != 0 ||
            pthread_create(&tl, NULL, par_list_thread, &c) != 0) {
                c.stop = 1;
                set_err(err, errlen, NULL, "pthread_create failed");
                return -1;
        }
        usleep(2000000);
        c.stop = 1;
        pthread_join(tc, NULL);
        pthread_join(td, NULL);
        pthread_join(tl, NULL);

        if (c.failed) {
                snprintf(err, (size_t)errlen, "parallel op failed: %s", c.err);
                goto out;
        }
        if (c.creates < 1 || c.deletes < 1 || c.lists < 1) {
                snprintf(err, (size_t)errlen, "parallel too few ops creates=%d deletes=%d lists=%d",
                         c.creates, c.deletes, c.lists);
                goto out;
        }
        set_err(err, errlen, NULL, NULL);
        rc = 0;
out:
        smb2 = open_share(host, port, user, password, share, 0, err, errlen);
        if (smb2) {
                struct smb2dir *dir = smb2_opendir(smb2, "par");
                if (dir) {
                        struct smb2dirent *de;
                        while ((de = smb2_readdir(smb2, dir)) != NULL) {
                                char path[128];
                                if (de->name[0] == '.') {
                                        continue;
                                }
                                snprintf(path, sizeof(path), "par/%s", de->name);
                                smb2_unlink(smb2, path);
                        }
                        smb2_closedir(smb2, dir);
                }
                smb2_rmdir(smb2, "par");
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
        return rc;
}

#endif /* DEBUG */
