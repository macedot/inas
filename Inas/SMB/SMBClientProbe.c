/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

/* Test-only SMB client helpers used by InasTests to drive the loopback
 * server. Compiled in Debug builds only (the test action); release archives
 * of the app carry no SMB client code. */

#include "SMBClientProbe.h"

#include <sys/types.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#if DEBUG

static void set_err(char *err, int errlen, struct smb2_context *smb2, const char *fallback)
{
        const char *msg = smb2 ? smb2_get_error(smb2) : NULL;
        if (!err || errlen <= 0) {
                return;
        }
        if (msg && msg[0]) {
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

#endif /* DEBUG */
