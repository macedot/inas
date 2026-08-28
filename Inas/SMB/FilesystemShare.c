/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#define __STDC_WANT_LIB_EXT1__ 1

/*
 * Path operations use dirfd + leaf + *at/O_NOFOLLOW (inas_path_resolve_at).
 * Never open, stat, rename, or unlink a user-supplied path by absolute
 * string — that reintroduces the TOCTOU this sandbox closed.
 */

#include "FilesystemShare.h"
#include "PathSandbox.h"
#include "GlobMatch.h"
#include "AuthThrottle.h"
#include "DialectPolicy.h"
#include "Srvsvc.h"

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/smb2-errors.h>
#include "libsmb2-private.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#ifdef __APPLE__
#include <os/log.h>
#endif

#define INAS_MAX_HANDLES 256
#define INAS_SHARE_DEFAULT "inas"
#define INAS_TREE_IPC 0xFFFE
#define PAD_TO_64BIT(len) (((len) + 0x07u) & 0xfffffff8u)
#define INAS_IO_TARGETS 16
#define INAS_IO_MAX_INFLIGHT 8
#define INAS_MAX_SESSIONS 16

#ifdef __APPLE__
#include <dispatch/dispatch.h>
#endif

struct inas_io_target {
        struct smb2_context *smb2;
        int dead;
        int refs;
        int in_use;
};

struct inas_io_completion {
        struct inas_io_target *target;
        struct inas_io_completion *next;
        uint64_t message_id;
        int is_read;
        int fd;          /* dup'd file descriptor, owned by the op */
        uint64_t offset; /* file offset for the I/O */
        int status;      /* >=0 bytes transferred, <0 -errno */
        uint8_t *buf;    /* read: worker-allocated data; write: copied data */
        uint32_t length; /* requested transfer size */
};

struct inas_share {
        char name[64];
        char root[PATH_MAX];
        int rootfd;
};

struct inas_handle {
        int in_use;
        smb2_file_id id;
        /* Owning connection. Handles live and die with their TCP session:
         * destruction_event frees every handle whose owner matches the
         * disconnecting context, otherwise a browse-heavy client (Finder
         * opens .DS_Store / AppleDouble / dir handles per folder) leaks
         * slots until CREATE fails with ENOMEM forever. */
        struct smb2_context *owner;
        int fd;
        int dirfd;
        DIR *dir;
        char leaf[256];
        int is_dir;
        int delete_on_close;
        int unlinked; /* name already removed (SET_INFO disposition) */
        int notify_pending;
        uint64_t notify_mid;
        struct timespec notify_armed_at;
        uint32_t enum_index;
        int enum_done;
        uint32_t access;
        int is_pipe;
        int wrote;
        uint32_t create_action;
        uint8_t *rpc_out;
        size_t rpc_out_len;
        size_t rpc_out_off;
};

struct inas_state {
        pthread_mutex_t lock;
        pthread_t thread;
        int thread_started;
        volatile int running;
        int listen_fd;
        uint16_t port;
        char user[128];
        struct inas_share shares[INAS_MAX_SHARES];
        int share_count;
        char password[128];
        char hostname[128];
        struct inas_handle handles[INAS_MAX_HANDLES];
        uint64_t id_counter;
        atomic_int clients;
        atomic_uint_fast64_t bytes;
        atomic_uint_fast64_t bytes_read;
        atomic_uint_fast64_t bytes_written;
        atomic_uint_fast64_t peak_clients;
        atomic_int active_transfers;
        /* Deferred file-I/O machinery: READ/WRITE handlers hand the
         * blocking pread/pwrite to a worker pool and return >0 ("deferred")
         * to the dispatcher. Completed ops are queued here and drained by
         * extra_service() on the server thread, so reply PDUs are always
         * queued from the same thread that runs the select loop. */
        int wake[2];
        pthread_mutex_t io_lock;
        struct inas_io_completion *io_done_head;
        struct inas_io_completion *io_done_tail;
        struct inas_io_completion *io_pending_head;
        struct inas_io_completion *io_pending_tail;
        struct inas_io_target io_targets[INAS_IO_TARGETS];
        dispatch_queue_t io_worker_queue;
        dispatch_semaphore_t io_worker_gate;
        struct smb2_context *sessions[INAS_MAX_SESSIONS];
        int notify_dirty;
        struct timespec notify_dirty_at;
        struct smb2_server server;
        inas_auth_slot auth[INAS_AUTH_PEERS];
        inas_auth_global auth_global;
};

static struct inas_state g;

static struct inas_state *fs_state(struct smb2_server *srvr)
{
        if (srvr && srvr->opaque) {
                return (struct inas_state *)srvr->opaque;
        }
        return &g;
}

/* ---- deferred file I/O ------------------------------------------------ */

/* Server-thread only. Find or create the io target tracking smb2 so
 * completions can be dropped if the client disconnects mid-transfer. */
static struct inas_io_target *io_target_for(struct inas_state *fs, struct smb2_context *smb2)
{
        struct inas_io_target *free_slot = NULL;
        for (int i = 0; i < INAS_IO_TARGETS; i++) {
                struct inas_io_target *t = &fs->io_targets[i];
                if (!t->in_use) {
                        if (!free_slot) {
                                free_slot = t;
                        }
                        continue;
                }
                if (t->smb2 == smb2) {
                        t->refs++;
                        return t;
                }
        }
        if (!free_slot) {
                return NULL;
        }
        free_slot->in_use = 1;
        free_slot->smb2 = smb2;
        free_slot->dead = 0;
        free_slot->refs = 1;
        return free_slot;
}

/* Server-thread only (destruction_event / drain). */
static void io_target_release(struct inas_state *fs, struct inas_io_target *t)
{
        if (!t) {
                return;
        }
        if (t->refs > 0) {
                t->refs--;
        }
        if (t->dead && t->refs == 0) {
                memset(t, 0, sizeof(*t));
        }
}

static void io_worker(void *ctx);
static void io_kick(struct inas_state *fs);

static void io_pending_enqueue(struct inas_state *fs, struct inas_io_completion *op)
{
        op->next = NULL;
        pthread_mutex_lock(&fs->io_lock);
        if (fs->io_pending_tail) {
                fs->io_pending_tail->next = op;
        } else {
                fs->io_pending_head = op;
        }
        fs->io_pending_tail = op;
        pthread_mutex_unlock(&fs->io_lock);
}

static struct inas_io_completion *io_pending_dequeue(struct inas_state *fs)
{
        pthread_mutex_lock(&fs->io_lock);
        struct inas_io_completion *op = fs->io_pending_head;
        if (op) {
                fs->io_pending_head = op->next;
                if (!fs->io_pending_head) {
                        fs->io_pending_tail = NULL;
                }
                op->next = NULL;
        }
        pthread_mutex_unlock(&fs->io_lock);
        return op;
}

/* Start one op on a worker. Caller already owns a gate slot. */
static void io_op_start(struct inas_state *fs, struct inas_io_completion *op)
{
        atomic_fetch_add(&fs->active_transfers, 1);
        dispatch_async_f(fs->io_worker_queue, op, io_worker);
}

/* Server thread. Never blocks: if the worker gate is full the op sits
 * on io_pending until io_kick() runs from extra_service. */
static void io_op_dispatch(struct inas_state *fs, struct inas_io_completion *op)
{
        if (dispatch_semaphore_wait(fs->io_worker_gate, DISPATCH_TIME_NOW) == 0) {
                io_op_start(fs, op);
                return;
        }
        io_pending_enqueue(fs, op);
        io_kick(fs);
}

static void io_kick(struct inas_state *fs)
{
        for (;;) {
                if (dispatch_semaphore_wait(fs->io_worker_gate, DISPATCH_TIME_NOW) != 0) {
                        return;
                }
                struct inas_io_completion *op = io_pending_dequeue(fs);
                if (!op) {
                        dispatch_semaphore_signal(fs->io_worker_gate);
                        return;
                }
                io_op_start(fs, op);
        }
}

/* Worker thread. Never touches smb2 — the server thread owns its
 * lifecycle; results go through the completion queue. */
static void io_worker(void *ctx)
{
        struct inas_state *fs = &g;
        struct inas_io_completion *op = ctx;

        if (op->is_read) {
                op->buf = malloc(op->length ? op->length : 1);
                if (!op->buf) {
                        op->status = -ENOMEM;
                } else {
                        op->status = (int)pread(op->fd, op->buf, op->length, (off_t)op->offset);
                }
        } else {
                op->status = (int)pwrite(op->fd, op->buf, op->length, (off_t)op->offset);
        }
        if (op->status < 0) {
                op->status = -errno;
        }
        close(op->fd);
        op->fd = -1;
        atomic_fetch_sub(&fs->active_transfers, 1);

        pthread_mutex_lock(&fs->io_lock);
        op->next = NULL;
        if (fs->io_done_tail) {
                fs->io_done_tail->next = op;
        } else {
                fs->io_done_head = op;
        }
        fs->io_done_tail = op;
        pthread_mutex_unlock(&fs->io_lock);

        uint8_t wake = 1;
        (void)write(fs->wake[1], &wake, sizeof(wake));
        dispatch_semaphore_signal(fs->io_worker_gate);
}

/* Server-thread only: queue the reply for one completed op. */
static int inas_status_from_errno(int err)
{
        switch (err) {
        case 0:
                return SMB2_STATUS_SUCCESS;
        case ENOENT:
                return SMB2_STATUS_OBJECT_NAME_NOT_FOUND;
        case ENOTDIR:
                return SMB2_STATUS_NOT_A_DIRECTORY;
        case EISDIR:
                return SMB2_STATUS_FILE_IS_A_DIRECTORY;
        case EACCES:
        case EPERM:
                return SMB2_STATUS_ACCESS_DENIED;
        case EINVAL:
                return SMB2_STATUS_INVALID_PARAMETER;
        case EBADF:
                return SMB2_STATUS_FILE_CLOSED;
        case ENOMEM:
                return SMB2_STATUS_INSUFFICIENT_RESOURCES;
        case ENOTEMPTY:
                return SMB2_STATUS_DIRECTORY_NOT_EMPTY;
        case EEXIST:
                return SMB2_STATUS_OBJECT_NAME_COLLISION;
        default:
                return SMB2_STATUS_NOT_SUPPORTED;
        }
}

static void io_op_finish(struct inas_state *fs, struct inas_io_completion *op)
{
        struct smb2_context *smb2 = op->target->smb2;
        struct smb2_pdu *pdu = NULL;
        char line[96];
        if (!op->target->dead) {
                if (op->is_read) {
                        struct smb2_read_reply rep;
                        memset(&rep, 0, sizeof(rep));
                        if (op->status >= 0) {
                                rep.data = op->buf;
                                rep.data_length = (uint32_t)op->status;
                                rep.data_remaining = 0;
                                atomic_fetch_add(&fs->bytes, (uint64_t)op->status);
                                atomic_fetch_add(&fs->bytes_read, (uint64_t)op->status);
                                pdu = smb2_cmd_read_reply_async(smb2, &rep, NULL, NULL);
                                /* The reply PDU owns op->buf now (it is added
                                 * to the pdu as an iovec with free()). */
                                if (pdu != NULL) {
                                        op->buf = NULL;
                                }
                        } else {
                                struct smb2_error_reply err;
                                memset(&err, 0, sizeof(err));
                                pdu = smb2_cmd_error_reply_async(
                                    smb2, &err, SMB2_READ, inas_status_from_errno(-op->status),
                                    NULL, NULL);
                        }
                } else {
                        struct smb2_write_reply rep;
                        memset(&rep, 0, sizeof(rep));
                        if (op->status >= 0) {
                                rep.count = (uint32_t)op->status;
                                rep.remaining = 0;
                                atomic_fetch_add(&fs->bytes, (uint64_t)op->status);
                                atomic_fetch_add(&fs->bytes_written, (uint64_t)op->status);
                                pdu = smb2_cmd_write_reply_async(smb2, &rep, NULL, NULL);
                        } else {
                                struct smb2_error_reply err;
                                memset(&err, 0, sizeof(err));
                                pdu = smb2_cmd_error_reply_async(
                                    smb2, &err, SMB2_WRITE, inas_status_from_errno(-op->status),
                                    NULL, NULL);
                        }
                }
                if (pdu != NULL) {
                        smb2_set_pdu_message_id(smb2, pdu, op->message_id);
                        smb2_queue_pdu(smb2, pdu);
#ifdef INAS_DEFER_DEBUG
                        {
                                FILE *df = NULL;
                                char path[512];
                                if (g.share_count > 0 &&
                                    snprintf(path, sizeof(path), "%s/defer.log", g.shares[0].root) >
                                        0) {
                                        df = fopen(path, "a");
                                }
                                if (df) {
                                        fprintf(df, "%s msg=%llu len=%u grant=%u charge=%u\n",
                                                op->is_read ? "READ" : "WRITE",
                                                (unsigned long long)op->message_id, op->length,
                                                pdu->header.credit_request_response,
                                                pdu->header.credit_charge);
                                        fclose(df);
                                }
                        }
#endif
                } else {
                        snprintf(line, sizeof(line), "deferred io reply alloc failed msg=%llu",
                                 (unsigned long long)op->message_id);
                        fprintf(stderr, "inas-smb: %s\n", line);
                }
        }
        io_target_release(fs, op->target);
        free(op->buf);
        free(op);
}

/* Server-thread only (extra_service): drain finished ops. */
static void io_drain(struct inas_state *fs)
{
        for (;;) {
                pthread_mutex_lock(&fs->io_lock);
                struct inas_io_completion *op = fs->io_done_head;
                if (op) {
                        fs->io_done_head = op->next;
                        if (!fs->io_done_head) {
                                fs->io_done_tail = NULL;
                        }
                }
                pthread_mutex_unlock(&fs->io_lock);
                if (!op) {
                        break;
                }
                io_op_finish(fs, op);
        }
        io_kick(fs);
}

static void io_teardown(struct inas_state *fs)
{
        pthread_mutex_lock(&fs->io_lock);
        struct inas_io_completion *op = fs->io_done_head;
        fs->io_done_head = fs->io_done_tail = NULL;
        struct inas_io_completion *pending = fs->io_pending_head;
        fs->io_pending_head = fs->io_pending_tail = NULL;
        pthread_mutex_unlock(&fs->io_lock);
        while (op) {
                struct inas_io_completion *next = op->next;
                io_target_release(fs, op->target);
                free(op->buf);
                free(op);
                op = next;
        }
        while (pending) {
                struct inas_io_completion *next = pending->next;
                if (pending->fd >= 0) {
                        close(pending->fd);
                }
                io_target_release(fs, pending->target);
                free(pending->buf);
                free(pending);
                pending = next;
        }
        for (int i = 0; i < INAS_IO_TARGETS; i++) {
                memset(&fs->io_targets[i], 0, sizeof(fs->io_targets[i]));
        }
}

/* ---------------------------------------------------------------------- */

static void fill_file_id(smb2_file_id id, uint64_t n)
{
        memset(id, 0, SMB2_FD_SIZE);
        memcpy(id, &n, sizeof(n));
}

static int file_id_equal(const smb2_file_id a, const smb2_file_id b)
{
        return memcmp(a, b, SMB2_FD_SIZE) == 0;
}

static struct inas_handle *handle_lookup(struct inas_state *fs, const smb2_file_id id)
{
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                if (fs->handles[i].in_use && file_id_equal(fs->handles[i].id, id)) {
                        return &fs->handles[i];
                }
        }
        return NULL;
}

static void notify_send(struct smb2_context *smb2, uint64_t message_id, uint32_t status)
{
        struct smb2_error_reply err;
        struct smb2_pdu *pdu;

        if (!smb2) {
                return;
        }
        memset(&err, 0, sizeof(err));
        pdu = smb2_cmd_error_reply_async(smb2, &err, SMB2_CHANGE_NOTIFY, (int)status, NULL, NULL);
        if (!pdu) {
                return;
        }
        smb2_set_pdu_message_id(smb2, pdu, message_id);
        smb2_queue_pdu(smb2, pdu);
}

/* Complete every outstanding CHANGE_NOTIFY. Finder watches displayed
 * folders; STATUS_NOTIFY_ENUM_DIR tells it to re-list. Flushed once per
 * extra_service tick so a batch CREATE does not re-list after every file. */
static int timespec_leq(const struct timespec *a, const struct timespec *b)
{
        if (a->tv_sec != b->tv_sec) {
                return a->tv_sec < b->tv_sec;
        }
        return a->tv_nsec <= b->tv_nsec;
}

static void notify_complete_all(struct inas_state *fs, uint32_t status)
{
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                struct inas_handle *h = &fs->handles[i];
                if (!h->in_use || !h->notify_pending) {
                        continue;
                }
                /* A watch armed after the mutation must not consume it. */
                if (!timespec_leq(&h->notify_armed_at, &fs->notify_dirty_at)) {
                        continue;
                }
                notify_send(h->owner, h->notify_mid, status);
                h->notify_pending = 0;
                h->notify_mid = 0;
        }
}

static void notify_mark(struct inas_state *fs)
{
        fs->notify_dirty = 1;
        clock_gettime(CLOCK_MONOTONIC, &fs->notify_dirty_at);
}

static int io_is_idle(struct inas_state *fs)
{
        if (atomic_load(&fs->active_transfers) != 0) {
                return 0;
        }
        pthread_mutex_lock(&fs->io_lock);
        int idle = fs->io_pending_head == NULL && fs->io_done_head == NULL;
        pthread_mutex_unlock(&fs->io_lock);
        return idle;
}

static void notify_flush(struct inas_state *fs)
{
        struct timespec now;

        if (!fs->notify_dirty || !io_is_idle(fs)) {
                return;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - fs->notify_dirty_at.tv_sec) * 1000 +
                (now.tv_nsec - fs->notify_dirty_at.tv_nsec) / 1000000 <
            100) {
                return;
        }
        fs->notify_dirty = 0;
        notify_complete_all(fs, SMB2_STATUS_NOTIFY_ENUM_DIR);
}

/* True if `fd` is a directory containing only "." / "..". 1 empty, 0 not,
 * <0 -errno. Uses a private DIR* so QUERY_DIRECTORY cursor is untouched. */
static int dir_is_empty_fd(int fd)
{
        int dfd;
        DIR *d;
        struct dirent *de;

        if (fd < 0) {
                return -EBADF;
        }
        dfd = dup(fd);
        if (dfd < 0) {
                return -errno;
        }
        d = fdopendir(dfd);
        if (!d) {
                int err = errno;
                close(dfd);
                return -err;
        }
        while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] == '.' &&
                    (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
                        continue;
                }
                closedir(d);
                return 0;
        }
        closedir(d);
        return 1;
}

static struct inas_handle *handle_alloc(struct inas_state *fs, struct smb2_context *owner)
{
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                if (!fs->handles[i].in_use) {
                        memset(&fs->handles[i], 0, sizeof(fs->handles[i]));
                        fs->handles[i].in_use = 1;
                        fs->handles[i].owner = owner;
                        fs->handles[i].fd = -1;
                        fs->handles[i].dirfd = -1;
                        fs->id_counter++;
                        fill_file_id(fs->handles[i].id, fs->id_counter);
                        return &fs->handles[i];
                }
        }
        return NULL;
}

static int handle_free(struct inas_state *fs, struct inas_handle *h, int send_notify)
{
        int rc = 0;

        if (!h || !h->in_use) {
                return 0;
        }
        if (h->notify_pending) {
                if (send_notify) {
                        notify_send(h->owner, h->notify_mid, SMB2_STATUS_NOTIFY_CLEANUP);
                }
                h->notify_pending = 0;
                h->notify_mid = 0;
        }
        /* closedir() releases only the dup()ed fd that fdopendir() owns;
         * h->fd and h->dirfd are separate descriptors closed below. */
        if (h->dir) {
                closedir(h->dir);
                h->dir = NULL;
        }
        if (h->fd >= 0) {
                close(h->fd);
                h->fd = -1;
        }
        if (h->delete_on_close && !h->unlinked && h->dirfd >= 0 && h->leaf[0]) {
                if (unlinkat(h->dirfd, h->leaf, h->is_dir ? AT_REMOVEDIR : 0) != 0) {
                        if (errno != ENOENT) {
                                rc = -errno;
                        }
                } else if (send_notify) {
                        notify_mark(fs);
                }
        }
        if (h->dirfd >= 0) {
                close(h->dirfd);
        }
        free(h->rpc_out);
        memset(h, 0, sizeof(*h));
        h->fd = -1;
        h->dirfd = -1;
        return rc;
}

/* Release every handle opened by `owner` (connection teardown or LOGOFF).
 * Returns the number of handles freed. Pending notifies are dropped:
 * the connection is going away, so there is nowhere to send CLEANUP. */
static int handle_free_owned(struct inas_state *fs, struct smb2_context *owner)
{
        int freed = 0;
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                if (fs->handles[i].in_use && fs->handles[i].owner == owner) {
                        handle_free(fs, &fs->handles[i], 0);
                        freed++;
                }
        }
        return freed;
}

static uint64_t timespec_to_smb(const struct timespec *ts)
{
        struct smb2_timeval tv;
        tv.tv_sec = ts->tv_sec;
        tv.tv_usec = (long)(ts->tv_nsec / 1000);
        return smb2_timeval_to_win(&tv);
}

static void stat_to_timeval(const struct timespec *ts, struct smb2_timeval *out)
{
        out->tv_sec = ts->tv_sec;
        out->tv_usec = (long)(ts->tv_nsec / 1000);
}

static uint32_t stat_to_attrs(const struct stat *st)
{
        if (S_ISDIR(st->st_mode)) {
                return SMB2_FILE_ATTRIBUTE_DIRECTORY;
        }
        return SMB2_FILE_ATTRIBUTE_NORMAL;
}

static const char *share_root_for_tree(struct inas_state *fs, struct smb2_context *smb2)
{
        uint32_t tid = smb2_tree_id(smb2);
        if (tid < 1 || tid > (uint32_t)fs->share_count) {
                return NULL;
        }
        return fs->shares[tid - 1].root;
}

static const char *share_name_for_tree(struct inas_state *fs, struct smb2_context *smb2)
{
        uint32_t tid = smb2_tree_id(smb2);
        if (tid < 1 || tid > (uint32_t)fs->share_count) {
                return INAS_SHARE_DEFAULT;
        }
        return fs->shares[tid - 1].name;
}

/* SECURITY: the tree id -> share mapping is trusted as-is. Safe today
 * because every share is served under the same authenticated session; if
 * per-share ACLs ever appear, tree ids must be tracked per smb2_context
 * instead of being treated as dense indices. */
static int share_rootfd_for_tree(struct inas_state *fs, struct smb2_context *smb2)
{
        uint32_t tid = smb2_tree_id(smb2);
        if (tid < 1 || tid > (uint32_t)fs->share_count) {
                return -1;
        }
        return fs->shares[tid - 1].rootfd;
}

static int access_to_open_flags(uint32_t desired)
{
        int read_bits =
            (int)(desired & (SMB2_FILE_READ_DATA | SMB2_FILE_READ_ATTRIBUTES | SMB2_GENERIC_READ |
                             SMB2_GENERIC_ALL | SMB2_FILE_LIST_DIRECTORY));
        int write_bits =
            (int)(desired & (SMB2_FILE_WRITE_DATA | SMB2_FILE_APPEND_DATA |
                             SMB2_FILE_WRITE_ATTRIBUTES | SMB2_GENERIC_WRITE | SMB2_GENERIC_ALL |
                             SMB2_FILE_ADD_FILE | SMB2_FILE_ADD_SUBDIRECTORY));
        if (write_bits && read_bits) {
                return O_RDWR;
        }
        if (write_bits) {
                return O_WRONLY;
        }
        return O_RDONLY;
}

static uint32_t fs_bytes_per_sector(const struct statvfs *vfs)
{
        uint32_t b = vfs ? (uint32_t)vfs->f_frsize : 0;
        return b >= 512 ? b : 512;
}

/* macOS treats inodes 0–15 as reserved Catalog Node IDs and fails the
 * mount with "invalid" if the share root reports one of those. */
static uint64_t inas_file_id(const struct stat *st)
{
        uint64_t ino = st ? (uint64_t)st->st_ino : 16;
        return ino < 16 ? ino + 16 : ino;
}

/* TREE_CONNECT path is a UTF-16 UNC (`\\server\share`). Take the last
 * non-empty component so host@port, DFS, and trailing slashes still
 * resolve to the share name. */
static int share_from_tree_path(const uint16_t *path, uint16_t path_length, char *out,
                                size_t out_len)
{
        char copy[256];
        const char *end;
        const char *start;
        size_t n;

        if (!path || path_length < 2 || !out || out_len == 0) {
                return -1;
        }
        const char *utf8 = smb2_utf16_to_utf8(path, path_length / 2);
        if (!utf8) {
                return -1;
        }
        if (snprintf(copy, sizeof(copy), "%s", utf8) >= (int)sizeof(copy)) {
                free((void *)utf8);
                return -1;
        }
        free((void *)utf8);

        n = strlen(copy);
        while (n > 0 && (copy[n - 1] == '\\' || copy[n - 1] == '/' || copy[n - 1] == '\0')) {
                copy[--n] = '\0';
        }
        if (n == 0) {
                return -1;
        }
        end = copy + n;
        start = end;
        while (start > copy && start[-1] != '\\' && start[-1] != '/') {
                start--;
        }
        n = (size_t)(end - start);
        if (n == 0 || n >= out_len) {
                return -1;
        }
        memcpy(out, start, n);
        out[n] = '\0';
        return 0;
}

static uint32_t peer_ipv4(struct smb2_context *smb2)
{
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        memset(&addr, 0, sizeof(addr));
        if (getpeername((int)smb2->fd, (struct sockaddr *)&addr, &len) != 0) {
                return 0;
        }
        if (addr.sin_family != AF_INET) {
                return 0;
        }
        return addr.sin_addr.s_addr;
}

/* Single-user appliance: only DOMAIN\user is stripped; user@REALM is
 * not rewritten. All handlers share g.lock; finer locking is deferred
 * until a load profile shows it matters. */
static int authorize_user(struct smb2_server *srvr, struct smb2_context *smb2, const char *user,
                          const char *domain, const char *workstation)
{
        struct inas_state *fs = fs_state(srvr);
        (void)domain;
        (void)workstation;
        pthread_mutex_lock(&fs->lock);
        time_t now = time(NULL);
        uint32_t ip = peer_ipv4(smb2);
        if (inas_auth_global_locked(&fs->auth_global, now)) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        inas_auth_slot *slot = inas_auth_lookup(fs->auth, INAS_AUTH_PEERS, ip, now);
        if (inas_auth_is_locked(slot, now)) {
                /* Locked peers still count toward the global window so a
                 * single chatty address can trip the LAN-wide backoff. */
                inas_auth_global_record_failure(&fs->auth_global, now);
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        const char *bare = user ? strrchr(user, '\\') : NULL;
        bare = (bare && bare[1]) ? bare + 1 : user;
        int ok = bare && strcasecmp(bare, fs->user) == 0 && fs->password[0] != '\0';
#ifdef __APPLE__
        os_log_debug(OS_LOG_DEFAULT, "inas-auth: provided=%{public}s expected=%{public}s ok=%d",
                     bare ? bare : "(null)", fs->user, ok);
#else
        fprintf(stderr, "inas-auth: provided='%s' expected='%s' ok=%d\n", bare ? bare : "(null)",
                fs->user, ok);
#endif
        if (ok) {
                smb2_set_user(smb2, fs->user);
                smb2_set_password(smb2, fs->password);
        } else {
                /* Dummy password so NTLM still runs (no username-enum shortcut). */
                smb2_set_password(smb2, "\x01inas-reject");
        }
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int session_slot(struct inas_state *fs, struct smb2_context *smb2)
{
        for (int i = 0; i < INAS_MAX_SESSIONS; i++) {
                if (fs->sessions[i] == smb2) {
                        return i;
                }
        }
        return -1;
}

static int session_established(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        pthread_mutex_lock(&fs->lock);
        time_t now = time(NULL);
        inas_auth_on_success(inas_auth_lookup(fs->auth, INAS_AUTH_PEERS, peer_ipv4(smb2), now));
        inas_auth_global_record_success(&fs->auth_global);
        if (session_slot(fs, smb2) < 0) {
                for (int i = 0; i < INAS_MAX_SESSIONS; i++) {
                        if (fs->sessions[i] == NULL) {
                                fs->sessions[i] = smb2;
                                int n = atomic_fetch_add(&fs->clients, 1) + 1;
                                uint64_t peak = atomic_load(&fs->peak_clients);
                                while ((uint64_t)n > peak &&
                                       !atomic_compare_exchange_weak(&fs->peak_clients, &peak,
                                                                     (uint64_t)n)) {
                                }
                                break;
                        }
                }
        }
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int auth_failed(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        pthread_mutex_lock(&fs->lock);
        time_t now = time(NULL);
        inas_auth_on_failure(inas_auth_lookup(fs->auth, INAS_AUTH_PEERS, peer_ipv4(smb2), now),
                             now);
        inas_auth_global_record_failure(&fs->auth_global, now);
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int destruction_event(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        pthread_mutex_lock(&fs->lock);
        int slot = session_slot(fs, smb2);
        if (slot >= 0) {
                fs->sessions[slot] = NULL;
                int n = atomic_fetch_sub(&fs->clients, 1);
                if (n <= 1) {
                        atomic_store(&fs->clients, 0);
                }
        }
        handle_free_owned(fs, smb2);
        /* In-flight deferred ops for this context are dropped at drain time
         * (the worker never dereferences smb2, and the drain runs on this
         * same thread that will free the context). */
        for (int i = 0; i < INAS_IO_TARGETS; i++) {
                struct inas_io_target *t = &fs->io_targets[i];
                if (t->in_use && !t->dead && t->smb2 == smb2) {
                        t->dead = 1;
                        if (t->refs == 0) {
                                memset(t, 0, sizeof(*t));
                        }
                }
        }
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int logoff_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        pthread_mutex_lock(&fs->lock);
        handle_free_owned(fs, smb2);
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int tree_connect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                            struct smb2_tree_connect_request *req,
                            struct smb2_tree_connect_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        char share[128];
        if (share_from_tree_path(req->path, req->path_length, share, sizeof(share)) != 0) {
                return -EINVAL;
        }
        if (strcasecmp(share, "IPC$") == 0) {
                /* Samba/Linux browse the server via IPC$ after login.
                 * Accept the pipe share so TREE_CONNECT is not reported as
                 * STATUS_NOT_IMPLEMENTED ("function not implemented"). */
                rep->share_type = SMB2_SHARE_TYPE_PIPE;
                rep->share_flags = SMB2_SHAREFLAG_NO_CACHING | SMB2_SHAREFLAG_ENCRYPT_DATA;
                rep->capabilities = 0;
                rep->maximal_access = 0x0012019f;
                rep->tree_id = INAS_TREE_IPC;
                return 0;
        }
        pthread_mutex_lock(&fs->lock);
        int index = -1;
        for (int i = 0; i < fs->share_count; i++) {
                if (strcasecmp(share, fs->shares[i].name) == 0) {
                        index = i;
                        break;
                }
        }
        pthread_mutex_unlock(&fs->lock);
        if (index < 0) {
                return -ENOENT;
        }
        rep->share_type = SMB2_SHARE_TYPE_DISK;
        rep->share_flags = SMB2_SHAREFLAG_NO_CACHING | SMB2_SHAREFLAG_ENCRYPT_DATA;
        rep->capabilities = 0;
        rep->maximal_access = 0x001f01ff;
        rep->tree_id = (uint32_t)(index + 1);
        return 0;
}

static int tree_disconnect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                               const uint32_t tree_id)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        (void)tree_id;
        return 0;
}

static int open_path(struct inas_handle *h, int rootfd, const char *smb_name,
                     struct smb2_create_request *req, struct stat *st)
{
        inas_path resolved;
        int is_dir_req = (req->create_options & SMB2_FILE_DIRECTORY_FILE) != 0;
        int is_file_req = (req->create_options & SMB2_FILE_NON_DIRECTORY_FILE) != 0;
        uint32_t disp = req->create_disposition;
        int oflags = access_to_open_flags(req->desired_access) | O_NOFOLLOW | O_CLOEXEC;
        int exists;

        if (inas_path_resolve_at(rootfd, smb_name, &resolved) != 0) {
                return -ENOENT;
        }
        h->dirfd = resolved.dirfd;
        snprintf(h->leaf, sizeof(h->leaf), "%s", resolved.name);

        if (h->leaf[0] == '\0') {
                if (fstat(h->dirfd, st) != 0) {
                        return -errno;
                }
                h->is_dir = 1;
                h->fd = dup(h->dirfd);
                if (h->fd < 0) {
                        return -errno;
                }
                h->dir = fdopendir(dup(h->fd));
                if (!h->dir) {
                        return -errno;
                }
                h->delete_on_close = 0;
                h->access = req->desired_access;
                h->create_action = 1; /* FILE_OPENED */
                return 0;
        }

        exists = (fstatat(h->dirfd, h->leaf, st, AT_SYMLINK_NOFOLLOW) == 0);
        if (exists && S_ISLNK(st->st_mode)) {
                return -ELOOP;
        }
        if (exists && is_dir_req && !S_ISDIR(st->st_mode)) {
                return -ENOTDIR;
        }
        if (exists && is_file_req && S_ISDIR(st->st_mode)) {
                /* Client sent FILE_NON_DIRECTORY_FILE without FILE_DIRECTORY_FILE
                 * on a target that already exists as a directory (common for
                 * libsmb2 / cifs.ko / gvfs which don't know the target type up
                 * front). Samba is permissive here — open as directory rather
                 * than rejecting with STATUS_FILE_IS_A_DIRECTORY. */
                is_file_req = 0;
                is_dir_req = 1;
        }

        if (!exists) {
                if (disp == SMB2_FILE_OPEN || disp == SMB2_FILE_OVERWRITE) {
                        return -ENOENT;
                }
                if (is_dir_req) {
                        if (mkdirat(h->dirfd, h->leaf, 0755) != 0) {
                                return -errno;
                        }
                } else {
                        int fd = openat(h->dirfd, h->leaf, oflags | O_CREAT | O_EXCL, 0644);
                        if (fd < 0) {
                                return -errno;
                        }
                        h->fd = fd;
                }
                h->create_action = 2; /* FILE_CREATED */
        } else {
                if (disp == SMB2_FILE_CREATE) {
                        return -EEXIST;
                }
                h->create_action = 1; /* FILE_OPENED */
                if (S_ISDIR(st->st_mode)) {
                        if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF ||
                            disp == SMB2_FILE_SUPERSEDE) {
                                return -EISDIR;
                        }
                } else {
                        if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF ||
                            disp == SMB2_FILE_SUPERSEDE) {
                                oflags |= O_TRUNC;
                                h->create_action = 3; /* FILE_OVERWRITTEN */
                        }
                        if (disp == SMB2_FILE_SUPERSEDE) {
                                unlinkat(h->dirfd, h->leaf, 0);
                                oflags |= O_CREAT | O_TRUNC;
                        }
                        int fd = openat(h->dirfd, h->leaf, oflags, 0644);
                        if (fd < 0) {
                                fd = openat(h->dirfd, h->leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                                if (fd < 0) {
                                        return -errno;
                                }
                        }
                        h->fd = fd;
                }
        }

        if (fstatat(h->dirfd, h->leaf, st, AT_SYMLINK_NOFOLLOW) != 0) {
                return -errno;
        }
        h->is_dir = S_ISDIR(st->st_mode);
        if (h->is_dir) {
                if (h->fd < 0) {
                        h->fd = openat(h->dirfd, h->leaf,
                                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                        if (h->fd < 0) {
                                return -errno;
                        }
                }
                h->dir = fdopendir(dup(h->fd));
                if (!h->dir) {
                        return -errno;
                }
        }
        h->delete_on_close = (req->create_options & SMB2_FILE_DELETE_ON_CLOSE) != 0;
        h->access = req->desired_access;
        return 0;
}

static int pipe_name_is_srvsvc(const char *name)
{
        while (name && (*name == '\\' || *name == '/')) {
                name++;
        }
        if (name && (!strncasecmp(name, "PIPE\\", 5) || !strncasecmp(name, "PIPE/", 5))) {
                name += 5;
        }
        return name && strcasecmp(name, "srvsvc") == 0;
}

static int pipe_run_rpc(struct inas_state *fs, struct inas_handle *h, const uint8_t *in,
                        size_t in_len)
{
        const char *names[INAS_MAX_SHARES + 1];
        uint8_t *out = NULL;
        size_t out_len = 0;
        int n = 0;
        int i;

        for (i = 0; i < fs->share_count; i++) {
                names[n++] = fs->shares[i].name;
        }
        names[n++] = "IPC$";
        if (inas_srvsvc_process(in, in_len, names, n, &out, &out_len) != 0) {
                free(h->rpc_out);
                h->rpc_out = NULL;
                h->rpc_out_len = 0;
                h->rpc_out_off = 0;
                return -EINVAL;
        }
        free(h->rpc_out);
        h->rpc_out = out;
        h->rpc_out_len = out_len;
        h->rpc_out_off = 0;
        return 0;
}

static int create_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                      struct smb2_create_request *req, struct smb2_create_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        const char *name = req->name ? req->name : "";
        uint32_t tid = smb2_tree_id(smb2);

        if (tid == INAS_TREE_IPC) {
                if (!pipe_name_is_srvsvc(name)) {
                        return -ENOENT;
                }
                pthread_mutex_lock(&fs->lock);
                struct inas_handle *h = handle_alloc(fs, smb2);
                if (!h) {
                        pthread_mutex_unlock(&fs->lock);
                        return -ENOMEM;
                }
                h->is_pipe = 1;
                memcpy(rep->file_id, h->id, SMB2_FD_SIZE);
                rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
                rep->create_action = 1; /* FILE_OPENED */
                rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
                pthread_mutex_unlock(&fs->lock);
                return 0;
        }

        int rootfd = share_rootfd_for_tree(fs, smb2);
        if (rootfd < 0) {
                return -EBADF;
        }

        /* Finder often CREATE's the share name as a child of the tree.
         * If there is no real child with that name, treat it as the root. */
        const char *open_name = name;
        const char *leaf = name;
        const char *share = share_name_for_tree(fs, smb2);
        while (*leaf == '\\' || *leaf == '/') {
                leaf++;
        }
        if (share && leaf[0] && strchr(leaf, '/') == NULL && strchr(leaf, '\\') == NULL &&
            strcasecmp(leaf, share) == 0) {
                struct stat child;
                if (fstatat(rootfd, leaf, &child, AT_SYMLINK_NOFOLLOW) != 0) {
                        open_name = "";
                }
        }

        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_alloc(fs, smb2);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -ENOMEM;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        int err = open_path(h, rootfd, open_name, req, &st);
        if (err != 0) {
                handle_free(fs, h, 0);
                pthread_mutex_unlock(&fs->lock);
                return err;
        }
        memcpy(rep->file_id, h->id, SMB2_FD_SIZE);
        rep->file_attributes = stat_to_attrs(&st);
        if (S_ISDIR(st.st_mode)) {
                rep->end_of_file = 0;
                rep->allocation_size = 0;
        } else {
                rep->end_of_file = (uint64_t)st.st_size;
                rep->allocation_size = (uint64_t)st.st_blocks * 512ull;
        }
        rep->creation_time = timespec_to_smb(&st.st_birthtimespec);
        rep->last_access_time = timespec_to_smb(&st.st_atimespec);
        rep->last_write_time = timespec_to_smb(&st.st_mtimespec);
        rep->change_time = timespec_to_smb(&st.st_ctimespec);
        rep->create_action = h->create_action ? h->create_action : 1;
        rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        if (h->create_action == 2) {
                notify_mark(fs);
        }
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int close_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                     struct smb2_close_request *req, struct smb2_close_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        if (h->fd >= 0) {
                fstat(h->fd, &st);
        } else if (h->leaf[0] && h->dirfd >= 0) {
                fstatat(h->dirfd, h->leaf, &st, AT_SYMLINK_NOFOLLOW);
        } else if (h->dirfd >= 0) {
                fstat(h->dirfd, &st);
        }
        memset(rep, 0, sizeof(*rep));
        rep->file_attributes = stat_to_attrs(&st);
        rep->end_of_file = (uint64_t)st.st_size;
        if (h->wrote) {
                notify_mark(fs);
        }
        int rc = handle_free(fs, h, 1);
        pthread_mutex_unlock(&fs->lock);
        return rc;
}

static int flush_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                     struct smb2_flush_request *req)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        /* Samba strict sync = no: do not fsync on SMB2 FLUSH. fsync of a
         * large file blocks the server thread and Finder copy hangs at 100%. */
        (void)h;
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int read_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                    struct smb2_read_request *req, struct smb2_read_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        if (h->is_pipe) {
                size_t avail =
                    h->rpc_out_len > h->rpc_out_off ? h->rpc_out_len - h->rpc_out_off : 0;
                uint32_t n = req->length < avail ? req->length : (uint32_t)avail;
                uint8_t *buf = malloc(n ? n : 1);
                if (!buf) {
                        pthread_mutex_unlock(&fs->lock);
                        return -ENOMEM;
                }
                if (n) {
                        memcpy(buf, h->rpc_out + h->rpc_out_off, n);
                }
                h->rpc_out_off += n;
                pthread_mutex_unlock(&fs->lock);
                if (n == 0) {
                        free(buf);
                        rep->data = NULL;
                        rep->data_length = 0;
                        return 0;
                }
                rep->data = buf;
                rep->data_length = n;
                return 0;
        }
        if (h->fd < 0) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        uint32_t len = req->length;
        uint32_t max_read = fs->server.max_read_size ? fs->server.max_read_size : 0x100000;
        if (len > max_read) {
                pthread_mutex_unlock(&fs->lock);
                return -EINVAL;
        }
        if (len == 0) {
                pthread_mutex_unlock(&fs->lock);
                rep->data = NULL;
                rep->data_length = 0;
                rep->data_remaining = 0;
                return 0;
        }
        if (fs->io_worker_queue != NULL) {
                /* Hand the blocking pread to the worker pool. The reply is
                 * queued from extra_service() on the server thread once the
                 * completion drains. */
                struct inas_io_completion *op = calloc(1, sizeof(*op));
                if (op) {
                        op->target = io_target_for(fs, smb2);
                        op->message_id = smb2_get_last_request_message_id(smb2);
                        op->is_read = 1;
                        op->offset = req->offset;
                        op->length = len;
                        if (op->target) {
                                op->fd = dup(h->fd);
                        }
                        if (!op->target || op->fd < 0) {
                                io_target_release(fs, op->target);
                                free(op);
                        } else {
                                pthread_mutex_unlock(&fs->lock);
                                io_op_dispatch(fs, op);
                                return 1; /* deferred; reply queued later */
                        }
                }
        }
        uint8_t *buf = malloc(len);
        if (!buf) {
                pthread_mutex_unlock(&fs->lock);
                return -ENOMEM;
        }
        atomic_fetch_add(&fs->active_transfers, 1);
        ssize_t n = pread(h->fd, buf, len, (off_t)req->offset);
        pthread_mutex_unlock(&fs->lock);
        atomic_fetch_sub(&fs->active_transfers, 1);
        if (n < 0) {
                free(buf);
                return -errno;
        }
        if (n == 0) {
                free(buf);
                rep->data = NULL;
                rep->data_length = 0;
                rep->data_remaining = 0;
                return 0;
        }
        rep->data = buf;
        rep->data_length = (uint32_t)n;
        rep->data_remaining = 0;
        atomic_fetch_add(&fs->bytes, (uint64_t)n);
        atomic_fetch_add(&fs->bytes_read, (uint64_t)n);
        return 0;
}

static int write_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                     struct smb2_write_request *req, struct smb2_write_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        if (h->is_pipe) {
                int rc = pipe_run_rpc(fs, h, req->buf, req->length);
                pthread_mutex_unlock(&fs->lock);
                if (rc != 0) {
                        return rc;
                }
                rep->count = req->length;
                rep->remaining = 0;
                return 0;
        }
        if (h->fd < 0) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        uint32_t max_write = fs->server.max_write_size ? fs->server.max_write_size : 0x100000;
        if (req->length > max_write) {
                pthread_mutex_unlock(&fs->lock);
                return -EINVAL;
        }
        if (req->length > 0 && fs->io_worker_queue != NULL) {
                /* Hand the blocking pwrite to the worker pool (see read_cmd). */
                struct inas_io_completion *op = calloc(1, sizeof(*op));
                if (op) {
                        op->buf = malloc(req->length);
                        op->target = io_target_for(fs, smb2);
                        op->message_id = smb2_get_last_request_message_id(smb2);
                        op->offset = req->offset;
                        op->length = req->length;
                        if (op->target) {
                                op->fd = dup(h->fd);
                        }
                        if (!op->buf || !op->target || op->fd < 0) {
                                io_target_release(fs, op->target);
                                free(op->buf);
                                free(op);
                        } else {
                                memcpy(op->buf, req->buf, req->length);
                                h->wrote = 1;
                                pthread_mutex_unlock(&fs->lock);
                                io_op_dispatch(fs, op);
                                return 1; /* deferred; reply queued later */
                        }
                }
        }
        h->wrote = 1;
        atomic_fetch_add(&fs->active_transfers, 1);
        ssize_t n = pwrite(h->fd, req->buf, req->length, (off_t)req->offset);
        pthread_mutex_unlock(&fs->lock);
        atomic_fetch_sub(&fs->active_transfers, 1);
        if (n < 0) {
                return -errno;
        }
        rep->count = (uint32_t)n;
        rep->remaining = 0;
        atomic_fetch_add(&fs->bytes, (uint64_t)n);
        atomic_fetch_add(&fs->bytes_written, (uint64_t)n);
        return 0;
}

static int match_pattern(const char *name, const char *pattern)
{
        return inas_glob_match(name, pattern);
}

static uint32_t qdir_entry_raw(uint8_t info_class, uint32_t fname16)
{
        switch (info_class) {
        case SMB2_FILE_DIRECTORY_INFORMATION:
                return 64 + fname16;
        case SMB2_FILE_FULL_DIRECTORY_INFORMATION:
                return 68 + fname16;
        case SMB2_FILE_BOTH_DIRECTORY_INFORMATION:
                return 94 + fname16;
        case SMB2_FILE_NAMES_INFORMATION:
                return 12 + fname16;
        case SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION:
                return SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE + fname16;
        case SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION:
                return SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE + fname16;
        case SMB2_FILE_ID_EXTD_DIRECTORY_INFORMATION:
                return SMB2_FILEID_EXTD_DIRECTORY_INFORMATION_SIZE + fname16;
        default:
                return SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE + fname16;
        }
}

static int query_directory_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                               struct smb2_query_directory_request *req,
                               struct smb2_query_directory_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        if (!h->is_dir) {
                pthread_mutex_unlock(&fs->lock);
                return -ENOTDIR;
        }
        switch (req->file_information_class) {
        case SMB2_FILE_DIRECTORY_INFORMATION:
        case SMB2_FILE_FULL_DIRECTORY_INFORMATION:
        case SMB2_FILE_BOTH_DIRECTORY_INFORMATION:
        case SMB2_FILE_NAMES_INFORMATION:
        case SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION:
        case SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION:
        case SMB2_FILE_ID_EXTD_DIRECTORY_INFORMATION:
                break;
        default:
                pthread_mutex_unlock(&fs->lock);
                return -ENOSYS;
        }
        if (req->flags & (SMB2_RESTART_SCANS | SMB2_REOPEN)) {
                h->enum_index = 0;
                h->enum_done = 0;
                if (h->dir) {
                        rewinddir(h->dir);
                }
        }
        if (h->enum_done) {
                pthread_mutex_unlock(&fs->lock);
                rep->output_buffer = NULL;
                rep->output_buffer_length = 0;
                return 0;
        }
        if (!h->dir) {
                int dfd = h->fd >= 0 ? dup(h->fd) : dup(h->dirfd);
                if (dfd < 0) {
                        pthread_mutex_unlock(&fs->lock);
                        return -1;
                }
                h->dir = fdopendir(dfd);
                if (!h->dir) {
                        close(dfd);
                        pthread_mutex_unlock(&fs->lock);
                        return -1;
                }
        }

        const char *pattern = req->name ? req->name : "*";
        struct dirent *de;
        struct smb2_fileidbothdirectoryinformation *entries = NULL;
        size_t count = 0;
        size_t cap = 0;
        uint32_t room = req->output_buffer_length;
        uint32_t padded_sum = 0;

        for (;;) {
                long loc = telldir(h->dir);
                uint32_t fname16;
                uint32_t raw;
                uint32_t total_if_last;

                de = readdir(h->dir);
                if (de == NULL) {
                        break;
                }
                if (!match_pattern(de->d_name, pattern)) {
                        continue;
                }
                fname16 = (uint32_t)strlen(de->d_name) * 2u;
                raw = qdir_entry_raw(req->file_information_class, fname16);
                total_if_last = padded_sum + raw;
                if (room && count > 0 && total_if_last > room) {
                        if (loc != -1) {
                                seekdir(h->dir, loc);
                        }
                        break;
                }
                if (count + 1 > cap) {
                        cap = cap ? cap * 2 : 16;
                        void *nbuf = realloc(entries, cap * sizeof(*entries));
                        if (!nbuf) {
                                free(entries);
                                pthread_mutex_unlock(&fs->lock);
                                return -1;
                        }
                        entries = nbuf;
                }
                struct stat st;
                memset(&st, 0, sizeof(st));
                int atfd = h->fd >= 0 ? h->fd : h->dirfd;
                fstatat(atfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW);
                struct smb2_fileidbothdirectoryinformation *e = &entries[count];
                memset(e, 0, sizeof(*e));
                e->file_index = h->enum_index + (uint32_t)count;
                stat_to_timeval(&st.st_birthtimespec, &e->creation_time);
                stat_to_timeval(&st.st_atimespec, &e->last_access_time);
                stat_to_timeval(&st.st_mtimespec, &e->last_write_time);
                stat_to_timeval(&st.st_ctimespec, &e->change_time);
                if (de->d_type == DT_DIR || S_ISDIR(st.st_mode)) {
                        e->file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
                        e->end_of_file = 0;
                        e->allocation_size = 0;
                } else {
                        e->file_attributes = stat_to_attrs(&st);
                        e->end_of_file = (uint64_t)st.st_size;
                        e->allocation_size = (uint64_t)st.st_blocks * 512ull;
                }
                e->file_id = inas_file_id(&st);
                e->name = strdup(de->d_name);
                if (!e->name) {
                        for (size_t i = 0; i < count; i++) {
                                free((void *)entries[i].name);
                        }
                        free(entries);
                        pthread_mutex_unlock(&fs->lock);
                        return -1;
                }
                count++;
                padded_sum += PAD_TO_64BIT(raw);
                if (req->flags & SMB2_RETURN_SINGLE_ENTRY) {
                        break;
                }
        }
        h->enum_index += (uint32_t)count;
        if (count == 0) {
                h->enum_done = 1;
                pthread_mutex_unlock(&fs->lock);
                rep->output_buffer = NULL;
                rep->output_buffer_length = 0;
                return 0;
        }

        size_t recsz = PAD_TO_64BIT(sizeof(struct smb2_fileidbothdirectoryinformation));
        size_t packed = recsz * count;
        size_t names_bytes = 0;
        for (size_t i = 0; i < count; i++) {
                names_bytes += strlen(entries[i].name) + 1;
        }
        uint8_t *buf = calloc(1, packed + names_bytes);
        if (!buf) {
                for (size_t i = 0; i < count; i++) {
                        free((void *)entries[i].name);
                }
                free(entries);
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        char *nptr = (char *)(buf + packed);
        for (size_t i = 0; i < count; i++) {
                struct smb2_fileidbothdirectoryinformation *e =
                    (struct smb2_fileidbothdirectoryinformation *)(buf + i * recsz);
                memcpy(e, &entries[i], sizeof(entries[i]));
                size_t nl = strlen(entries[i].name) + 1;
                memcpy(nptr, entries[i].name, nl);
                e->name = nptr;
                nptr += nl;
                free((void *)entries[i].name);
        }
        free(entries);
        pthread_mutex_unlock(&fs->lock);
        rep->output_buffer = buf;
        rep->output_buffer_length = (uint32_t)packed;
        return 0;
}

static int fill_basic(const struct stat *st, struct smb2_file_basic_info *info)
{
        memset(info, 0, sizeof(*info));
        stat_to_timeval(&st->st_birthtimespec, &info->creation_time);
        stat_to_timeval(&st->st_atimespec, &info->last_access_time);
        stat_to_timeval(&st->st_mtimespec, &info->last_write_time);
        stat_to_timeval(&st->st_ctimespec, &info->change_time);
        info->file_attributes = stat_to_attrs(st);
        return (int)sizeof(*info);
}

static int fill_standard(const struct stat *st, struct smb2_file_standard_info *info,
                         int delete_pending)
{
        memset(info, 0, sizeof(*info));
        info->directory = S_ISDIR(st->st_mode) ? 1 : 0;
        if (info->directory) {
                info->allocation_size = 0;
                info->end_of_file = 0;
        } else {
                info->allocation_size = (uint64_t)st->st_blocks * 512ull;
                info->end_of_file = (uint64_t)st->st_size;
        }
        info->delete_pending = delete_pending ? 1 : 0;
        info->number_of_links = delete_pending ? 0 : (uint32_t)st->st_nlink;
        return (int)sizeof(*info);
}

static int query_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                          struct smb2_query_info_request *req, struct smb2_query_info_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        char namebuf[256];
        namebuf[0] = '\0';
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        struct stat st;
        int delete_pending = 0;
        memset(&st, 0, sizeof(st));
        const char *root = share_root_for_tree(fs, smb2);
        int rootfd = share_rootfd_for_tree(fs, smb2);
        if (h) {
                delete_pending = h->delete_on_close;
                if (h->fd >= 0) {
                        fstat(h->fd, &st);
                } else if (h->leaf[0] && h->dirfd >= 0) {
                        fstatat(h->dirfd, h->leaf, &st, AT_SYMLINK_NOFOLLOW);
                } else if (h->dirfd >= 0) {
                        fstat(h->dirfd, &st);
                }
                if (h->leaf[0]) {
                        snprintf(namebuf, sizeof(namebuf), "\\%s", h->leaf);
                } else {
                        snprintf(namebuf, sizeof(namebuf), "\\");
                }
        } else if (rootfd >= 0) {
                fstat(rootfd, &st);
                snprintf(namebuf, sizeof(namebuf), "\\");
        } else if (root) {
                stat(root, &st);
                snprintf(namebuf, sizeof(namebuf), "\\");
        } else {
                snprintf(namebuf, sizeof(namebuf), "\\");
        }
        pthread_mutex_unlock(&fs->lock);

        void *info = NULL;
        int len = 0;

        if (req->info_type == SMB2_0_INFO_FILE) {
                switch (req->file_info_class) {
                case SMB2_FILE_BASIC_INFORMATION: {
                        struct smb2_file_basic_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        len = fill_basic(&st, p);
                        info = p;
                        break;
                }
                case SMB2_FILE_STANDARD_INFORMATION: {
                        struct smb2_file_standard_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        len = fill_standard(&st, p, delete_pending);
                        info = p;
                        break;
                }
                case SMB2_FILE_INTERNAL_INFORMATION: {
                        uint64_t *p = calloc(1, sizeof(uint64_t));
                        if (!p)
                                return -1;
                        *p = inas_file_id(&st);
                        info = p;
                        len = 8;
                        break;
                }
                case SMB2_FILE_ID_INFORMATION: {
                        uint8_t *p = calloc(1, 24);
                        uint64_t serial = 0x314e4153ull;
                        uint64_t fid = inas_file_id(&st);
                        if (!p)
                                return -1;
                        memcpy(p, &serial, 8);
                        memcpy(p + 8, &fid, 8);
                        info = p;
                        len = 24;
                        break;
                }
                case SMB2_FILE_ACCESS_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p)
                                return -1;
                        *p = 0x001f01ff;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_ALL_INFORMATION: {
                        size_t nlen = strlen(namebuf) + 1;
                        struct smb2_file_all_info *p = calloc(1, sizeof(*p) + nlen);
                        if (!p)
                                return -1;
                        fill_basic(&st, &p->basic);
                        fill_standard(&st, &p->standard, delete_pending);
                        p->index_number = inas_file_id(&st);
                        p->access_flags = 0x001f01ff;
                        char *stored = (char *)(p + 1);
                        memcpy(stored, namebuf, nlen);
                        p->name = (const uint8_t *)stored;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_NETWORK_OPEN_INFORMATION: {
                        struct smb2_file_network_open_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        stat_to_timeval(&st.st_birthtimespec, &p->creation_time);
                        stat_to_timeval(&st.st_atimespec, &p->last_access_time);
                        stat_to_timeval(&st.st_mtimespec, &p->last_write_time);
                        stat_to_timeval(&st.st_ctimespec, &p->change_time);
                        p->file_attributes = stat_to_attrs(&st);
                        if (S_ISDIR(st.st_mode)) {
                                p->allocation_size = 0;
                                p->end_of_file = 0;
                        } else {
                                p->allocation_size = (uint64_t)st.st_blocks * 512ull;
                                p->end_of_file = (uint64_t)st.st_size;
                        }
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_EA_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p)
                                return -1;
                        *p = 0;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_POSITION_INFORMATION: {
                        struct smb2_file_position_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_MODE_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p)
                                return -1;
                        *p = 0;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_ALIGNMENT_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p)
                                return -1;
                        *p = 0;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_NAME_INFORMATION:
                case SMB2_FILE_NORMALIZED_NAME_INFORMATION: {
                        size_t nlen = strlen(namebuf) + 1;
                        struct smb2_file_name_info *p = calloc(1, sizeof(*p) + nlen);
                        if (!p)
                                return -1;
                        char *stored = (char *)(p + 1);
                        memcpy(stored, namebuf, nlen);
                        p->name = (const uint8_t *)stored;
                        p->file_name_length = (uint32_t)(strlen(namebuf) * 2);
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_STREAM_INFORMATION: {
                        static const char stream[] = "::$DATA";
                        size_t slen = sizeof(stream);
                        struct smb2_file_stream_info *p = calloc(1, sizeof(*p) + slen);
                        if (!p)
                                return -1;
                        char *stored = (char *)(p + 1);
                        memcpy(stored, stream, slen);
                        p->stream_name = stored;
                        p->stream_name_length = (uint32_t)(sizeof(stream) - 1);
                        p->stream_size = (uint64_t)st.st_size;
                        p->stream_allocation_size = (uint64_t)st.st_blocks * 512ull;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                default:
                        break;
                }
        } else if (req->info_type == SMB2_0_INFO_FILESYSTEM) {
                struct statvfs vfs;
                memset(&vfs, 0, sizeof(vfs));
                int fsfd = share_rootfd_for_tree(fs, smb2);
                if (fsfd >= 0) {
                        fstatvfs(fsfd, &vfs);
                } else {
                        const char *fsroot = share_root_for_tree(fs, smb2);
                        if (fsroot) {
                                statvfs(fsroot, &vfs);
                        }
                }
                switch (req->file_info_class) {
                case SMB2_FILE_FS_VOLUME_INFORMATION: {
                        struct smb2_file_fs_volume_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        p->volume_serial_number = 0x314e4153;
                        p->volume_label = (const uint8_t *)"iNAS";
                        p->volume_label_length = 8;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_SIZE_INFORMATION: {
                        struct smb2_file_fs_size_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        p->total_allocation_units = vfs.f_blocks;
                        p->available_allocation_units = vfs.f_bavail;
                        p->sectors_per_allocation_unit = 1;
                        p->bytes_per_sector = fs_bytes_per_sector(&vfs);
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_DEVICE_INFORMATION: {
                        struct smb2_file_fs_device_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        p->device_type = FILE_DEVICE_DISK;
                        p->characteristics = 0;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_ATTRIBUTE_INFORMATION: {
                        struct smb2_file_fs_attribute_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        /* CASE_PRESERVED_NAMES | UNICODE_ON_DISK */
                        p->filesystem_attributes = 0x00000006;
                        p->maximum_component_name_length = 255;
                        p->filesystem_name = (const uint8_t *)"iNAS";
                        p->filesystem_name_length = 8;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_FULL_SIZE_INFORMATION: {
                        struct smb2_file_fs_full_size_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        p->total_allocation_units = vfs.f_blocks;
                        p->caller_available_allocation_units = vfs.f_bavail;
                        p->actual_available_allocation_units = vfs.f_bfree;
                        p->sectors_per_allocation_unit = 1;
                        p->bytes_per_sector = fs_bytes_per_sector(&vfs);
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_SECTOR_SIZE_INFORMATION: {
                        struct smb2_file_fs_sector_size_info *p = calloc(1, sizeof(*p));
                        uint32_t bps;
                        if (!p)
                                return -1;
                        bps = fs_bytes_per_sector(&vfs);
                        p->logical_bytes_per_sector = bps;
                        p->physical_bytes_per_sector_for_atomicity = bps;
                        p->physical_bytes_per_sector_for_performance = bps;
                        p->file_system_effective_physical_bytes_per_sector_for_atomicity = bps;
                        p->flags =
                            SSINFO_FLAGS_ALIGNED_DEVICE | SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_OBJECT_ID_INFORMATION: {
                        struct smb2_file_fs_object_id_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        memcpy(p->object_id, "iNAS-volume-guid", SMB2_GUID_SIZE);
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_CONTROL_INFORMATION: {
                        struct smb2_file_fs_control_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                default:
                        break;
                }
        }

        if (!info) {
                /* Unknown class: STATUS_NOT_SUPPORTED (ENOSYS). An empty
                 * SUCCESS reply makes Finder treat the root as missing. */
                return -ENOSYS;
        }
        rep->output_buffer = info;
        rep->output_buffer_length = (uint32_t)len;
        return len > 0 ? 0 : -1;
}

static int set_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                        struct smb2_set_info_request *req)
{
        struct inas_state *fs = fs_state(srvr);
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        int rc = 0;
        if (req->info_type == SMB2_0_INFO_FILE) {
                switch (req->file_info_class) {
                case SMB2_FILE_DISPOSITION_INFORMATION: {
                        struct smb2_file_disposition_info *info = req->input_data;
                        int is_dir, dirfd, fd;
                        char leaf[256];

                        if (!info) {
                                break;
                        }
                        if (!info->delete_pending) {
                                /* Cannot undelete a name already unlinked. */
                                if (!h->unlinked) {
                                        h->delete_on_close = 0;
                                }
                                break;
                        }
                        if (!h->leaf[0] || h->dirfd < 0) {
                                rc = -EPERM;
                                break;
                        }
                        is_dir = h->is_dir;
                        dirfd = h->dirfd;
                        fd = h->fd;
                        snprintf(leaf, sizeof(leaf), "%s", h->leaf);
                        pthread_mutex_unlock(&fs->lock);

                        if (is_dir) {
                                int empty = dir_is_empty_fd(fd);
                                if (empty == 0) {
                                        return -ENOTEMPTY;
                                }
                                if (empty < 0) {
                                        return empty;
                                }
                        }
                        if (unlinkat(dirfd, leaf, is_dir ? AT_REMOVEDIR : 0) != 0 &&
                            errno != ENOENT) {
                                return -errno;
                        }

                        pthread_mutex_lock(&fs->lock);
                        h = handle_lookup(fs, req->file_id);
                        if (h) {
                                h->delete_on_close = 1;
                                h->unlinked = 1;
                                notify_mark(fs);
                        }
                        break;
                }
                case SMB2_FILE_END_OF_FILE_INFORMATION: {
                        struct smb2_file_end_of_file_info *info = req->input_data;
                        if (info && h->fd >= 0) {
                                if (ftruncate(h->fd, (off_t)info->end_of_file) != 0) {
                                        rc = -errno;
                                }
                        }
                        break;
                }
                case SMB2_FILE_RENAME_INFORMATION: {
                        struct smb2_file_rename_info *info = req->input_data;
                        inas_path dest;
                        int rootfd = share_rootfd_for_tree(fs, smb2);
                        if (!info || !info->file_name || rootfd < 0 || h->dirfd < 0 ||
                            !h->leaf[0]) {
                                rc = -EINVAL;
                                break;
                        }
                        if (inas_path_resolve_at(rootfd, (const char *)info->file_name, &dest) !=
                            0) {
                                rc = -ENOENT;
                                break;
                        }
                        if (!dest.name[0]) {
                                inas_path_release(&dest);
                                rc = -EINVAL;
                                break;
                        }
                        if (!info->replace_if_exist) {
                                struct stat exists;
                                if (fstatat(dest.dirfd, dest.name, &exists, AT_SYMLINK_NOFOLLOW) ==
                                    0) {
                                        inas_path_release(&dest);
                                        rc = -EEXIST;
                                        break;
                                }
                        }
                        if (renameat(h->dirfd, h->leaf, dest.dirfd, dest.name) != 0) {
                                rc = -errno;
                                inas_path_release(&dest);
                                break;
                        }
                        close(h->dirfd);
                        h->dirfd = dest.dirfd;
                        dest.dirfd = -1;
                        snprintf(h->leaf, sizeof(h->leaf), "%s", dest.name);
                        inas_path_release(&dest);
                        notify_mark(fs);
                        break;
                }
                case SMB2_FILE_BASIC_INFORMATION:
                case SMB2_FILE_ALLOCATION_INFORMATION:
                case SMB2_FILE_POSITION_INFORMATION:
                case SMB2_FILE_MODE_INFORMATION:
                        break;
                default:
                        rc = -ENOSYS;
                        break;
                }
        } else {
                rc = -ENOSYS;
        }
        pthread_mutex_unlock(&fs->lock);
        return rc;
}

static int ioctl_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                     struct smb2_ioctl_request *req, struct smb2_ioctl_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        memset(rep, 0, sizeof(*rep));
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);
        switch (req->ctl_code) {
        case SMB2_FSCTL_PIPE_TRANSCEIVE: {
                struct inas_handle *h;
                char namebuf[INAS_MAX_SHARES][64];
                const char *names[INAS_MAX_SHARES + 1];
                uint8_t *out = NULL;
                size_t out_len = 0;
                int n = 0;
                int i;

                pthread_mutex_lock(&fs->lock);
                h = handle_lookup(fs, req->file_id);
                if (!h || !h->is_pipe) {
                        pthread_mutex_unlock(&fs->lock);
                        return -EBADF;
                }
                for (i = 0; i < fs->share_count && n < INAS_MAX_SHARES; i++) {
                        snprintf(namebuf[n], sizeof(namebuf[n]), "%s", fs->shares[i].name);
                        names[n] = namebuf[n];
                        n++;
                }
                pthread_mutex_unlock(&fs->lock);
                names[n++] = "IPC$";
                if (inas_srvsvc_process(req->input, req->input_count, names, n, &out, &out_len) !=
                    0) {
                        return -EINVAL;
                }
                pthread_mutex_lock(&fs->lock);
                h = handle_lookup(fs, req->file_id);
                if (!h || !h->is_pipe) {
                        pthread_mutex_unlock(&fs->lock);
                        free(out);
                        return -EBADF;
                }
                free(h->rpc_out);
                h->rpc_out = out;
                h->rpc_out_len = out_len;
                h->rpc_out_off = 0;
                rep->output = h->rpc_out;
                rep->output_count = (uint32_t)h->rpc_out_len;
                pthread_mutex_unlock(&fs->lock);
                return 0;
        }
        case SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO:
        case SMB2_FSCTL_LMR_REQUEST_RESILIENCY:
        case SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS:
                return 0;
        default:
                return -ENOSYS;
        }
}

static int change_notify_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                             struct smb2_change_notify_request *req,
                             struct smb2_change_notify_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        struct inas_handle *h;
        uint64_t mid;

        memset(rep, 0, sizeof(*rep));
        pthread_mutex_lock(&fs->lock);
        h = handle_lookup(fs, req->file_id);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -EBADF;
        }
        /* One outstanding notify per handle. A second arm replaces the
         * first with ENUM_DIR so Finder re-lists rather than hanging. */
        if (h->notify_pending) {
                notify_send(h->owner, h->notify_mid, SMB2_STATUS_NOTIFY_ENUM_DIR);
                h->notify_pending = 0;
                h->notify_mid = 0;
        }
        mid = smb2_get_last_request_message_id(smb2);
        h->notify_pending = 1;
        h->notify_mid = mid;
        clock_gettime(CLOCK_MONOTONIC, &h->notify_armed_at);
        pthread_mutex_unlock(&fs->lock);
        /* No PDU now — same deferred pattern as READ/WRITE. Finder's
         * poll fallback was the multi-second spinner; we complete this
         * on the next create/unlink/rename (or CLOSE/CANCEL). */
        return 1;
}

static int lock_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                    struct smb2_lock_request *req)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        (void)req;
        return 0;
}

static int echo_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        return 0;
}

static int cancel_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        uint64_t mid = smb2_get_last_request_message_id(smb2);

        pthread_mutex_lock(&fs->lock);
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                struct inas_handle *h = &fs->handles[i];
                if (h->in_use && h->notify_pending && h->owner == smb2 && h->notify_mid == mid) {
                        notify_send(h->owner, h->notify_mid, SMB2_STATUS_CANCELLED);
                        h->notify_pending = 0;
                        h->notify_mid = 0;
                        break;
                }
        }
        pthread_mutex_unlock(&fs->lock);
        /* SMB2 CANCEL itself has no response; the cancelled command does. */
        return 0;
}

static struct smb2_server_request_handlers g_handlers = {destruction_event,
                                                         authorize_user,
                                                         session_established,
                                                         logoff_cmd,
                                                         tree_connect_cmd,
                                                         tree_disconnect_cmd,
                                                         create_cmd,
                                                         close_cmd,
                                                         flush_cmd,
                                                         read_cmd,
                                                         write_cmd,
                                                         NULL,
                                                         NULL,
                                                         lock_cmd,
                                                         ioctl_cmd,
                                                         cancel_cmd,
                                                         echo_cmd,
                                                         query_directory_cmd,
                                                         change_notify_cmd,
                                                         query_info_cmd,
                                                         set_info_cmd,
                                                         auth_failed};

static void on_new_client(struct smb2_context *smb2, void *cb_data)
{
        (void)cb_data;
        /* ANY3 is vendor-patched to dialects 3.0.2 and 3.1.1 only. */
        smb2_set_version(smb2, SMB2_VERSION_ANY3);
        smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP);
        smb2_set_seal(smb2, 1);
        smb2_set_sign(smb2, 1);
        smb2_set_security_mode(smb2,
                               SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED);
}

static void *server_thread(void *arg)
{
        (void)arg;
        int err = smb2_serve_port(&g.server, 8, on_new_client, NULL);
        (void)err;
        g.running = 0;
        return NULL;
}

static void extra_fdset(struct smb2_server *server, fd_set *rfds, fd_set *wfds, int *maxfd)
{
        struct inas_state *fs = fs_state(server);
        (void)wfds;
        if (!fs->running && server->fd >= 0) {
                shutdown(server->fd, SHUT_RDWR);
        }
        if (fs->wake[0] >= 0) {
                FD_SET(fs->wake[0], rfds);
                if (fs->wake[0] > *maxfd) {
                        *maxfd = fs->wake[0];
                }
        }
}

static void extra_service(struct smb2_server *server, fd_set *rfds, fd_set *wfds)
{
        struct inas_state *fs = fs_state(server);
        (void)rfds;
        (void)wfds;
        if (!fs->running && server->fd >= 0) {
                close(server->fd);
                server->fd = -1;
        }
        /* Always drain completions. Handlers may finish workers after
         * select() sampled rfds, and a full non-blocking wake pipe must
         * not strand replies. */
        if (fs->wake[0] >= 0) {
                uint8_t scratch[64];
                ssize_t n;
                do {
                        n = read(fs->wake[0], scratch, sizeof(scratch));
                } while (n > 0 || (n < 0 && errno == EINTR));
                io_drain(fs);
        }
        notify_flush(fs);
}

static void close_share_fds(void)
{
        for (int i = 0; i < g.share_count; i++) {
                if (g.shares[i].rootfd >= 0) {
                        close(g.shares[i].rootfd);
                        g.shares[i].rootfd = -1;
                }
        }
}

static int valid_share_name(const char *name)
{
        size_t len = strlen(name);

        if (len < 1 || len > 63) {
                return 0;
        }
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)name[i];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      c == '_' || c == '-')) {
                        return 0;
                }
        }
        return 1;
}

static int inas_smb_start_config_ok(const inas_smb_config *config)
{
        if (!config || !config->username || !config->password || !config->shares ||
            config->share_count < 1 || config->share_count > INAS_MAX_SHARES) {
                return 0;
        }
        for (int i = 0; i < config->share_count; i++) {
                const char *nm = config->shares[i].name;
                if (!nm || !valid_share_name(nm) || !config->shares[i].root_path) {
                        return 0;
                }
        }
        return 1;
}

static void inas_ignore_sigpipe_once(void)
{
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGPIPE, &sa, NULL);
}

int inas_smb_start(const inas_smb_config *config)
{
        if (!inas_smb_start_config_ok(config)) {
                return -EINVAL;
        }
        /* The server replies on a pthread; writing to a peer-closed socket
         * delivers SIGPIPE to that thread and — by default — kills the whole
         * process. Ignore SIGPIPE so a flaky client cannot bring down the
         * server (and the iOS app with it). */
        static pthread_once_t sigpipe_once = PTHREAD_ONCE_INIT;
        pthread_once(&sigpipe_once, inas_ignore_sigpipe_once);
        pthread_mutex_lock(&g.lock);
        if (g.running) {
                pthread_mutex_unlock(&g.lock);
                return -EALREADY;
        }

        memset(&g.server, 0, sizeof(g.server));
        g.server.fd = -1;
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                handle_free(&g, &g.handles[i], 0);
        }
        io_teardown(&g);
        if (g.wake[0] < 0) {
                if (pipe(g.wake) != 0) {
                        g.wake[0] = g.wake[1] = -1;
                } else {
                        for (int i = 0; i < 2; i++) {
                                int flags = fcntl(g.wake[i], F_GETFL, 0);
                                fcntl(g.wake[i], F_SETFL, flags | O_NONBLOCK);
                                flags = fcntl(g.wake[i], F_GETFD, 0);
                                fcntl(g.wake[i], F_SETFD, flags | FD_CLOEXEC);
                        }
                }
        }
#ifdef __APPLE__
        if (g.io_worker_queue == NULL) {
                g.io_worker_queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
                g.io_worker_gate = dispatch_semaphore_create(INAS_IO_MAX_INFLIGHT);
        }
#endif
        g.id_counter = 1;
        atomic_store(&g.clients, 0);
        atomic_store(&g.bytes, 0);
        atomic_store(&g.bytes_read, 0);
        atomic_store(&g.bytes_written, 0);
        atomic_store(&g.peak_clients, 0);
        atomic_store(&g.active_transfers, 0);
        memset(g.sessions, 0, sizeof(g.sessions));
        g.notify_dirty = 0;
        memset(g.auth, 0, sizeof(g.auth));
        memset(&g.auth_global, 0, sizeof(g.auth_global));
        for (int i = 0; i < INAS_MAX_SHARES; i++) {
                g.shares[i].rootfd = -1;
        }
        g.share_count = 0;
        for (int i = 0; i < config->share_count; i++) {
                const char *nm = config->shares[i].name;
                const char *rt = config->shares[i].root_path;
                if (!nm || !nm[0] || !rt) {
                        close_share_fds();
                        pthread_mutex_unlock(&g.lock);
                        return -EINVAL;
                }
                if (mkdir(rt, 0755) != 0 && errno != EEXIST) {
                        /* realpath/open below report the real failure */
                }
                if (!realpath(rt, g.shares[g.share_count].root)) {
                        close_share_fds();
                        pthread_mutex_unlock(&g.lock);
                        return -errno;
                }
                if (snprintf(g.shares[g.share_count].name, sizeof(g.shares[0].name), "%s", nm) >=
                    (int)sizeof(g.shares[0].name)) {
                        close_share_fds();
                        pthread_mutex_unlock(&g.lock);
                        return -ENAMETOOLONG;
                }
                g.shares[g.share_count].rootfd =
                    open(g.shares[g.share_count].root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (g.shares[g.share_count].rootfd < 0) {
                        int err = errno;
                        close_share_fds();
                        pthread_mutex_unlock(&g.lock);
                        return -err;
                }
                g.share_count++;
        }
        memset(g.user, 0, sizeof(g.user));
        (void)memset_s(g.password, sizeof(g.password), 0, sizeof(g.password));
        if (!config->username[0] || !config->password[0]) {
                close_share_fds();
                pthread_mutex_unlock(&g.lock);
                return -EINVAL;
        }
        if (snprintf(g.user, sizeof(g.user), "%s", config->username) >= (int)sizeof(g.user) ||
            snprintf(g.password, sizeof(g.password), "%s", config->password) >=
                (int)sizeof(g.password)) {
                (void)memset_s(g.password, sizeof(g.password), 0, sizeof(g.password));
                close_share_fds();
                pthread_mutex_unlock(&g.lock);
                return -ENAMETOOLONG;
        }
        if (config->hostname && config->hostname[0]) {
                snprintf(g.hostname, sizeof(g.hostname), "%s", config->hostname);
        } else {
                gethostname(g.hostname, sizeof(g.hostname));
        }

        g.server.handlers = &g_handlers;
        g.server.opaque = &g;
        g.server.signing_enabled = 1;
        g.server.allow_anonymous = 0;
        g.server.port = config->port;
        if (config->bind_ip && config->bind_ip[0]) {
                snprintf(g.server.bind_ipv4, sizeof(g.server.bind_ipv4), "%s", config->bind_ip);
        } else {
                g.server.bind_ipv4[0] = '\0';
        }
        g.server.max_transact_size = 0x100000;
        g.server.max_read_size = 0x100000;
        g.server.max_write_size = 0x100000;
        memcpy(g.server.guid, "iNAS-smb2-guid!", 16);
        snprintf(g.server.hostname, sizeof(g.server.hostname), "%s", g.hostname);
        snprintf(g.server.domain, sizeof(g.server.domain), "%s", "WORKGROUP");
        g.server.extra_fdset = extra_fdset;
        g.server.extra_service = extra_service;
        g.server.allowed_dialects[0] = INAS_SMB_DIALECT_MIN;
        g.server.allowed_dialects[1] = INAS_SMB_DIALECT_PREF;
        g.server.allowed_dialect_count = 2;

        uint16_t fallback_port = config->port;
        const uint16_t *ports = config->try_ports;
        int nports = config->try_port_count;
        if (!ports || nports < 1) {
                ports = &fallback_port;
                nports = 1;
        }

        int last_err = -EADDRINUSE;
        int bound = 0;
        for (int pi = 0; pi < nports; pi++) {
                g.server.port = ports[pi];
                g.port = ports[pi];
                g.server.fd = -1;
                g.running = 1;
                g.thread_started = 0;
                int rc = pthread_create(&g.thread, NULL, server_thread, NULL);
                if (rc != 0) {
                        g.running = 0;
                        last_err = -rc;
                        continue;
                }
                g.thread_started = 1;
                pthread_mutex_unlock(&g.lock);
                for (int i = 0; i < 50 && g.server.fd <= 0 && g.running; i++) {
                        usleep(20000);
                }
                pthread_mutex_lock(&g.lock);
                if (g.server.fd > 0) {
                        bound = 1;
                        break;
                }
                g.running = 0;
                pthread_mutex_unlock(&g.lock);
                pthread_join(g.thread, NULL);
                pthread_mutex_lock(&g.lock);
                g.thread_started = 0;
                last_err = -EADDRINUSE;
        }
        pthread_mutex_unlock(&g.lock);
        if (!bound) {
                close_share_fds();
                return last_err;
        }
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        if (getsockname(g.server.fd, (struct sockaddr *)&addr, &alen) == 0) {
                g.port = ntohs(addr.sin_port);
        }
        return 0;
}

void inas_smb_stop(void)
{
        pthread_mutex_lock(&g.lock);
        g.running = 0;
        int fd = g.server.fd;
        int started = g.thread_started;
        pthread_mutex_unlock(&g.lock);
        /* Wake select(); the server thread closes the fd and exits the loop. */
        if (fd >= 0) {
                shutdown(fd, SHUT_RDWR);
        }
        if (started) {
                pthread_join(g.thread, NULL);
                g.thread_started = 0;
        }
        pthread_mutex_lock(&g.lock);
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                handle_free(&g, &g.handles[i], 0);
        }
        close_share_fds();
        g.share_count = 0;
        io_teardown(&g);
        (void)memset_s(g.password, sizeof(g.password), 0, sizeof(g.password));
        pthread_mutex_unlock(&g.lock);
}

int inas_smb_is_running(void)
{
        return g.running;
}

int inas_smb_bound_port(void)
{
        return g.port;
}

int inas_smb_client_count(void)
{
        return atomic_load(&g.clients);
}

uint64_t inas_smb_bytes_transferred(void)
{
        return atomic_load(&g.bytes);
}

int inas_smb_active_transfers(void)
{
        return atomic_load(&g.active_transfers);
}

uint64_t inas_smb_bytes_read(void)
{
        return atomic_load(&g.bytes_read);
}

uint64_t inas_smb_bytes_written(void)
{
        return atomic_load(&g.bytes_written);
}

int inas_smb_peak_clients(void)
{
        return (int)atomic_load(&g.peak_clients);
}

int inas_smb_auth_stats(int *peer_count, int *locked_count)
{
        int peers = 0;
        int locked = 0;
        time_t now = time(NULL);
        pthread_mutex_lock(&g.lock);
        for (int i = 0; i < INAS_AUTH_PEERS; i++) {
                if (g.auth[i].ip == 0) {
                        continue;
                }
                peers++;
                if (inas_auth_is_locked(&g.auth[i], now)) {
                        locked++;
                }
        }
        pthread_mutex_unlock(&g.lock);
        if (peer_count) {
                *peer_count = peers;
        }
        if (locked_count) {
                *locked_count = locked;
        }
        return 0;
}

int inas_smb_auth_global_locked(void)
{
        time_t now = time(NULL);
        int locked;
        pthread_mutex_lock(&g.lock);
        locked = inas_auth_global_locked(&g.auth_global, now);
        pthread_mutex_unlock(&g.lock);
        return locked;
}

__attribute__((constructor)) static void inas_init(void)
{
        pthread_mutex_init(&g.lock, NULL);
        pthread_mutex_init(&g.io_lock, NULL);
        (void)mlock(g.password, sizeof(g.password));
        g.server.fd = -1;
        g.wake[0] = -1;
        g.wake[1] = -1;
        for (int i = 0; i < INAS_MAX_SHARES; i++) {
                g.shares[i].rootfd = -1;
        }
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                g.handles[i].fd = -1;
                g.handles[i].dirfd = -1;
        }
}
