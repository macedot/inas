/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#include "FilesystemShare.h"
#include "PathSandbox.h"
#include "GlobMatch.h"
#include "AuthThrottle.h"
#include "DialectPolicy.h"

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
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define INAS_MAX_HANDLES 256
#define INAS_SHARE_DEFAULT "inas"
#define PAD_TO_64BIT(len) (((len) + 0x07u) & 0xfffffff8u)

struct inas_share {
        char name[64];
        char root[PATH_MAX];
        int rootfd;
};

struct inas_handle {
        int in_use;
        smb2_file_id id;
        int fd;
        int dirfd;
        DIR *dir;
        char leaf[256];
        int is_dir;
        int delete_on_close;
        uint32_t enum_index;
        int enum_done;
        uint32_t access;
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
        struct smb2_server server;
        inas_auth_slot auth[INAS_AUTH_PEERS];
};

static struct inas_state g;

static struct inas_state *fs_state(struct smb2_server *srvr)
{
        if (srvr && srvr->opaque) {
                return (struct inas_state *)srvr->opaque;
        }
        return &g;
}

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

static struct inas_handle *handle_alloc(struct inas_state *fs)
{
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                if (!fs->handles[i].in_use) {
                        memset(&fs->handles[i], 0, sizeof(fs->handles[i]));
                        fs->handles[i].in_use = 1;
                        fs->handles[i].fd = -1;
                        fs->handles[i].dirfd = -1;
                        fs->id_counter++;
                        fill_file_id(fs->handles[i].id, fs->id_counter);
                        return &fs->handles[i];
                }
        }
        return NULL;
}

static void handle_free(struct inas_handle *h)
{
        if (!h || !h->in_use) {
                return;
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
        if (h->delete_on_close && h->dirfd >= 0 && h->leaf[0]) {
                unlinkat(h->dirfd, h->leaf, h->is_dir ? AT_REMOVEDIR : 0);
        }
        if (h->dirfd >= 0) {
                close(h->dirfd);
        }
        memset(h, 0, sizeof(*h));
        h->fd = -1;
        h->dirfd = -1;
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

static int share_from_tree_path(const uint16_t *path, uint16_t path_length, char *out,
                                size_t out_len)
{
        if (!path || path_length < 2 || !out || out_len == 0) {
                return -1;
        }
        const char *utf8 = smb2_utf16_to_utf8(path, path_length / 2);
        if (!utf8) {
                return -1;
        }
        const char *slash = strrchr(utf8, '\\');
        const char *name = slash ? slash + 1 : utf8;
        if (name[0] == '\0') {
                free((void *)utf8);
                return -1;
        }
        snprintf(out, out_len, "%s", name);
        free((void *)utf8);
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

static int authorize_user(struct smb2_server *srvr, struct smb2_context *smb2, const char *user,
                          const char *domain, const char *workstation)
{
        struct inas_state *fs = fs_state(srvr);
        (void)domain;
        (void)workstation;
        pthread_mutex_lock(&fs->lock);
        uint32_t ip = peer_ipv4(smb2);
        inas_auth_slot *slot = inas_auth_lookup(fs->auth, INAS_AUTH_PEERS, ip, time(NULL));
        if (inas_auth_is_locked(slot, time(NULL))) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        const char *bare = user ? strrchr(user, '\\') : NULL;
        bare = (bare && bare[1]) ? bare + 1 : user;
        int ok = bare && strcasecmp(bare, fs->user) == 0 && fs->password[0] != '\0';
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

static int session_established(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        atomic_fetch_add(&fs->clients, 1);
        pthread_mutex_lock(&fs->lock);
        inas_auth_on_success(
            inas_auth_lookup(fs->auth, INAS_AUTH_PEERS, peer_ipv4(smb2), time(NULL)));
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int auth_failed(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        pthread_mutex_lock(&fs->lock);
        inas_auth_on_failure(
            inas_auth_lookup(fs->auth, INAS_AUTH_PEERS, peer_ipv4(smb2), time(NULL)), time(NULL));
        pthread_mutex_unlock(&fs->lock);
        return 0;
}

static int destruction_event(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        int n = atomic_fetch_sub(&fs->clients, 1);
        if (n <= 1) {
                atomic_store(&fs->clients, 0);
        }
        return 0;
}

static int logoff_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
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
                return -1;
        }
        if (strcasecmp(share, "IPC$") == 0) {
                return -1;
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
                return -1;
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
                return -EISDIR;
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
        } else {
                if (disp == SMB2_FILE_CREATE) {
                        return -EEXIST;
                }
                if (S_ISDIR(st->st_mode)) {
                        if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF ||
                            disp == SMB2_FILE_SUPERSEDE) {
                                return -EISDIR;
                        }
                } else {
                        if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF ||
                            disp == SMB2_FILE_SUPERSEDE) {
                                oflags |= O_TRUNC;
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

static int create_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                      struct smb2_create_request *req, struct smb2_create_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        const char *name = req->name ? req->name : "";
        int rootfd = share_rootfd_for_tree(fs, smb2);
        if (rootfd < 0) {
                return -1;
        }

        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_alloc(fs);
        if (!h) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        int err = open_path(h, rootfd, name, req, &st);
        if (err != 0) {
                handle_free(h);
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        memcpy(rep->file_id, h->id, SMB2_FD_SIZE);
        rep->file_attributes = stat_to_attrs(&st);
        rep->end_of_file = (uint64_t)st.st_size;
        rep->allocation_size = (uint64_t)st.st_blocks * 512ull;
        rep->creation_time = timespec_to_smb(&st.st_birthtimespec);
        rep->last_access_time = timespec_to_smb(&st.st_atimespec);
        rep->last_write_time = timespec_to_smb(&st.st_mtimespec);
        rep->change_time = timespec_to_smb(&st.st_ctimespec);
        rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
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
                return -1;
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
        handle_free(h);
        pthread_mutex_unlock(&fs->lock);
        return 0;
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
                return -1;
        }
        if (h->fd >= 0) {
                fsync(h->fd);
        }
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
        if (!h || h->fd < 0) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        uint32_t len = req->length;
        uint32_t max_read = fs->server.max_read_size ? fs->server.max_read_size : 0x100000;
        if (len > max_read) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        uint8_t *buf = malloc(len ? len : 1);
        if (!buf) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        ssize_t n = pread(h->fd, buf, len, (off_t)req->offset);
        pthread_mutex_unlock(&fs->lock);
        if (n < 0) {
                free(buf);
                return -1;
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
        return 0;
}

static int write_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                     struct smb2_write_request *req, struct smb2_write_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h || h->fd < 0) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        uint32_t max_write = fs->server.max_write_size ? fs->server.max_write_size : 0x100000;
        if (req->length > max_write) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
        }
        ssize_t n = pwrite(h->fd, req->buf, req->length, (off_t)req->offset);
        pthread_mutex_unlock(&fs->lock);
        if (n < 0) {
                return -1;
        }
        rep->count = (uint32_t)n;
        rep->remaining = 0;
        atomic_fetch_add(&fs->bytes, (uint64_t)n);
        return 0;
}

static int match_pattern(const char *name, const char *pattern)
{
        return inas_glob_match(name, pattern);
}

static int query_directory_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                               struct smb2_query_directory_request *req,
                               struct smb2_query_directory_reply *rep)
{
        struct inas_state *fs = fs_state(srvr);
        (void)smb2;
        pthread_mutex_lock(&fs->lock);
        struct inas_handle *h = handle_lookup(fs, req->file_id);
        if (!h || !h->is_dir) {
                pthread_mutex_unlock(&fs->lock);
                return -1;
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

        while ((de = readdir(h->dir)) != NULL) {
                if (!match_pattern(de->d_name, pattern)) {
                        continue;
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
                e->end_of_file = (uint64_t)st.st_size;
                e->allocation_size = (uint64_t)st.st_blocks * 512ull;
                e->file_attributes = stat_to_attrs(&st);
                e->file_id = (uint64_t)st.st_ino;
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

static int fill_standard(const struct stat *st, struct smb2_file_standard_info *info)
{
        memset(info, 0, sizeof(*info));
        info->allocation_size = (uint64_t)st->st_blocks * 512ull;
        info->end_of_file = (uint64_t)st->st_size;
        info->number_of_links = (uint32_t)st->st_nlink;
        info->directory = S_ISDIR(st->st_mode) ? 1 : 0;
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
        memset(&st, 0, sizeof(st));
        const char *root = share_root_for_tree(fs, smb2);
        int rootfd = share_rootfd_for_tree(fs, smb2);
        if (h) {
                if (h->fd >= 0) {
                        fstat(h->fd, &st);
                } else if (h->leaf[0] && h->dirfd >= 0) {
                        fstatat(h->dirfd, h->leaf, &st, AT_SYMLINK_NOFOLLOW);
                } else if (h->dirfd >= 0) {
                        fstat(h->dirfd, &st);
                }
                snprintf(namebuf, sizeof(namebuf), "%s",
                         h->leaf[0] ? h->leaf : share_name_for_tree(fs, smb2));
        } else if (rootfd >= 0) {
                fstat(rootfd, &st);
                snprintf(namebuf, sizeof(namebuf), "%s", share_name_for_tree(fs, smb2));
        } else if (root) {
                stat(root, &st);
                snprintf(namebuf, sizeof(namebuf), "%s", share_name_for_tree(fs, smb2));
        } else {
                snprintf(namebuf, sizeof(namebuf), "%s", INAS_SHARE_DEFAULT);
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
                        len = fill_standard(&st, p);
                        info = p;
                        break;
                }
                case SMB2_FILE_INTERNAL_INFORMATION: {
                        uint64_t *p = calloc(1, sizeof(uint64_t));
                        if (!p)
                                return -1;
                        *p = (uint64_t)st.st_ino;
                        info = p;
                        len = 8;
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
                        fill_standard(&st, &p->standard);
                        p->index_number = (uint64_t)st.st_ino;
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
                        p->allocation_size = (uint64_t)st.st_blocks * 512ull;
                        p->end_of_file = (uint64_t)st.st_size;
                        p->file_attributes = stat_to_attrs(&st);
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
                case SMB2_FILE_NAME_INFORMATION: {
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
                default:
                        return -1;
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
                        p->bytes_per_sector = (uint32_t)vfs.f_frsize;
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
                        p->filesystem_attributes = 0x00000002; /* CASE_PRESERVED */
                        p->maximum_component_name_length = 255;
                        p->filesystem_name = (const uint8_t *)"iNAS";
                        p->filesystem_name_length = 8;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_FULL_SIZE_INFORMATION: {
                        struct smb2_file_fs_size_info *p = calloc(1, sizeof(*p));
                        if (!p)
                                return -1;
                        p->total_allocation_units = vfs.f_blocks;
                        p->available_allocation_units = vfs.f_bavail;
                        p->sectors_per_allocation_unit = 1;
                        p->bytes_per_sector = (uint32_t)vfs.f_frsize;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                default:
                        return -1;
                }
        } else {
                return -1;
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
                return -1;
        }
        int rc = 0;
        if (req->info_type == SMB2_0_INFO_FILE) {
                switch (req->file_info_class) {
                case SMB2_FILE_DISPOSITION_INFORMATION: {
                        struct smb2_file_disposition_info *info = req->input_data;
                        if (info) {
                                h->delete_on_close = info->delete_pending ? 1 : 0;
                        }
                        break;
                }
                case SMB2_FILE_END_OF_FILE_INFORMATION: {
                        struct smb2_file_end_of_file_info *info = req->input_data;
                        if (info && h->fd >= 0) {
                                if (ftruncate(h->fd, (off_t)info->end_of_file) != 0) {
                                        rc = -1;
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
                                rc = -1;
                                break;
                        }
                        if (inas_path_resolve_at(rootfd, (const char *)info->file_name, &dest) !=
                            0) {
                                rc = -1;
                                break;
                        }
                        if (!dest.name[0]) {
                                inas_path_release(&dest);
                                rc = -1;
                                break;
                        }
                        if (!info->replace_if_exist) {
                                struct stat exists;
                                if (fstatat(dest.dirfd, dest.name, &exists, AT_SYMLINK_NOFOLLOW) ==
                                    0) {
                                        inas_path_release(&dest);
                                        rc = -1;
                                        break;
                                }
                        }
                        if (renameat(h->dirfd, h->leaf, dest.dirfd, dest.name) != 0) {
                                inas_path_release(&dest);
                                rc = -1;
                                break;
                        }
                        close(h->dirfd);
                        h->dirfd = dest.dirfd;
                        dest.dirfd = -1;
                        snprintf(h->leaf, sizeof(h->leaf), "%s", dest.name);
                        inas_path_release(&dest);
                        break;
                }
                case SMB2_FILE_BASIC_INFORMATION:
                case SMB2_FILE_ALLOCATION_INFORMATION:
                case SMB2_FILE_POSITION_INFORMATION:
                case SMB2_FILE_MODE_INFORMATION:
                        break;
                default:
                        rc = -1;
                        break;
                }
        } else {
                rc = -1;
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
        /* Do not ACK security FSCTLs we do not implement (e.g. validate-negotiate). */
        return -1;
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
        (void)smb2;
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
                                                         NULL,
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
        (void)rfds;
        (void)maxfd;
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

int inas_smb_start(const inas_smb_config *config)
{
        if (!inas_smb_start_config_ok(config)) {
                return -EINVAL;
        }
        pthread_mutex_lock(&g.lock);
        if (g.running) {
                pthread_mutex_unlock(&g.lock);
                return -EALREADY;
        }

        memset(&g.server, 0, sizeof(g.server));
        g.server.fd = -1;
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                handle_free(&g.handles[i]);
        }
        g.id_counter = 1;
        atomic_store(&g.clients, 0);
        atomic_store(&g.bytes, 0);
        memset(g.auth, 0, sizeof(g.auth));
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
        memset(g.password, 0, sizeof(g.password));
        if (!config->username[0] || !config->password[0]) {
                close_share_fds();
                pthread_mutex_unlock(&g.lock);
                return -EINVAL;
        }
        if (snprintf(g.user, sizeof(g.user), "%s", config->username) >= (int)sizeof(g.user) ||
            snprintf(g.password, sizeof(g.password), "%s", config->password) >=
                (int)sizeof(g.password)) {
                memset(g.password, 0, sizeof(g.password));
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
                handle_free(&g.handles[i]);
        }
        close_share_fds();
        g.share_count = 0;
        memset(g.password, 0, sizeof(g.password));
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

__attribute__((constructor)) static void inas_init(void)
{
        pthread_mutex_init(&g.lock, NULL);
        g.server.fd = -1;
        for (int i = 0; i < INAS_MAX_SHARES; i++) {
                g.shares[i].rootfd = -1;
        }
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                g.handles[i].fd = -1;
                g.handles[i].dirfd = -1;
        }
}
