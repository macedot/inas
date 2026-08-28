/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if DEBUG

/* Connect with the given dialect (0 = ANY3). Returns 0 on success. */
int inas_smb_client_connect(const char *host, uint16_t port, const char *user, const char *password,
                            const char *share, uint16_t dialect, uint16_t *negotiated, char *err,
                            int errlen);

/* Create/write/read/list/rename/unlink plus a `..` traversal check. */
int inas_smb_client_roundtrip(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, char *err, int errlen);

/* Open + close `cycles` directory iterations over one connection to detect
 * server-side fd leaks. Returns 0 if every iteration succeeded. */
int inas_smb_client_dir_cycle(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, int cycles, char *err,
                              int errlen);

/* Open the same file `count` times without closing in between; returns the
 * number of successful opens (bounded by the server handle table). */
int inas_smb_client_open_many(const char *host, uint16_t port, const char *user,
                              const char *password, const char *share, int count, char *err,
                              int errlen);

/* Write `ok_len` bytes (must succeed), then a single raw WRITE of `big_len`
 * bytes (must be rejected). Returns 0 if both expectations hold. */
int inas_smb_client_write_bounds(const char *host, uint16_t port, const char *user,
                                 const char *password, const char *share, uint32_t ok_len,
                                 uint32_t big_len, char *err, int errlen);

/* After a sealed session, send a plaintext CREATE. Returns 0 if the server
 * drops the connection or rejects the PDU. */
int inas_smb_client_plaintext_after_session(const char *host, uint16_t port, const char *user,
                                            const char *password, const char *share, char *err,
                                            int errlen);

/* Linux post-login commands: QFS sector/full size, stream info, network
 * interface ioctl, and change-notify. Fails if any return
 * STATUS_NOT_IMPLEMENTED. */
int inas_smb_client_linux_post_login(const char *host, uint16_t port, const char *user,
                                     const char *password, const char *share, char *err,
                                     int errlen);

/* IPC$ + srvsvc NetrShareEnum (Linux smbclient -L / gvfs browse). */
int inas_smb_client_share_enum(const char *host, uint16_t port, const char *user,
                               const char *password, const char *expect_share, char *err,
                               int errlen);

/* QUERY_DIRECTORY FileIdBothDirectoryInformation and check the on-wire
 * layout the way macOS smbfs does (8-byte NextEntryOffset, no leftover
 * bytes after the last unpadded entry). */
int inas_smb_client_query_dir_wire(const char *host, uint16_t port, const char *user,
                                   const char *password, const char *share, char *err, int errlen);

/* macOS-style SET_INFO workflows: FileDispositionInformation delete on an
 * open handle plus FileRenameInformation. Returns 0 if the delete unlinked
 * and the rename moved the file. */
int inas_smb_client_setinfo_delete_rename(const char *host, uint16_t port, const char *user,
                                          const char *password, const char *share, char *err,
                                          int errlen);

/* Linux file-manager flow: smb2_stat() a subdirectory and a file inside it
 * (compound CREATE + QUERY_INFO FileAllInformation + CLOSE). */
int inas_smb_client_stat_entry(const char *host, uint16_t port, const char *user,
                               const char *password, const char *share, char *err, int errlen);

/* cifs.ko listing classes: QUERY_DIRECTORY FileFull / FileIdFull on a
 * subdirectory handle, wire-validated. */
int inas_smb_client_query_dir_classes(const char *host, uint16_t port, const char *user,
                                      const char *password, const char *share, char *err,
                                      int errlen);

/* SET_INFO edges Finder hits: name gone after disposition (before CLOSE),
 * non-empty directory → DIRECTORY_NOT_EMPTY, rename collision. */
int inas_smb_client_setinfo_delete_edges(const char *host, uint16_t port, const char *user,
                                         const char *password, const char *share, char *err,
                                         int errlen);

/* CHANGE_NOTIFY stays pending across WRITE and completes with
 * NOTIFY_ENUM_DIR when a name is created. */
int inas_smb_client_change_notify_mutate(const char *host, uint16_t port, const char *user,
                                         const char *password, const char *share, char *err,
                                         int errlen);

/* Live session must stay counted when another TCP dies before login. */
int inas_smb_client_count_survives_failed_login(const char *host, uint16_t port, const char *user,
                                                const char *password, const char *share, char *err,
                                                int errlen);

/* WRITE on one connection while share-enum + QUERY_DIRECTORY run on others. */
int inas_smb_client_concurrent_copy_and_enum(const char *host, uint16_t port, const char *user,
                                             const char *password, const char *share, char *err,
                                             int errlen);

/* Write 4×512KiB, read back, memcmp. Catches a stalled WRITE pipeline. */
int inas_smb_client_transfer_verify(const char *host, uint16_t port, const char *user,
                                    const char *password, const char *share, char *err, int errlen);

/* Three connections: CREATE, SET_INFO-delete, QUERY_DIRECTORY on one folder. */
int inas_smb_client_parallel_create_delete_list(const char *host, uint16_t port, const char *user,
                                                const char *password, const char *share, char *err,
                                                int errlen);

/* CREATE + 1MB WRITE + FLUSH + CLOSE must finish quickly (no fsync stall). */
int inas_smb_client_flush_is_fast(const char *host, uint16_t port, const char *user,
                                  const char *password, const char *share, char *err, int errlen);

/* Two live sessions: count==2, drop one => 1, drop the other => 0. */
int inas_smb_client_two_sessions_count(const char *host, uint16_t port, const char *user,
                                       const char *password, const char *share, char *err,
                                       int errlen);

/* SET_INFO FileBasicInformation last_write_time must round-trip on QUERY_INFO. */
int inas_smb_client_setinfo_times(const char *host, uint16_t port, const char *user,
                                  const char *password, const char *share, char *err, int errlen);

/* Named streams ("file:stream") must round-trip and die with the base file. */
int inas_smb_client_stream_roundtrip(const char *host, uint16_t port, const char *user,
                                     const char *password, const char *share, char *err,
                                     int errlen);

#endif /* DEBUG */

#ifdef __cplusplus
}
#endif
